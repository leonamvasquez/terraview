// Package validator validates AI-generated findings against the topology graph,
// discarding hallucinated or invalid findings before the merge stage.
//
// Validation rules:
//   - Resource existence in the graph
//   - Resource type matching
//   - Valid severity (CRITICAL|HIGH|MEDIUM|LOW|INFO)
//   - Duplicate detection (same resource + same category/description)
//   - Required fields populated (ResourceID, Description)
package validator

import (
	"fmt"
	"strings"

	"github.com/leonamvasquez/terraview/internal/rules"
	"github.com/leonamvasquez/terraview/internal/topology"
)

// DiscardReason describes the reason a finding was discarded.
type DiscardReason string

const (
	// ReasonResourceNotFound indicates the resource does not exist in the topology graph.
	ReasonResourceNotFound DiscardReason = "resource_not_found"
	// ReasonResourceTypeMismatch indicates a type mismatch between finding and graph.
	ReasonResourceTypeMismatch DiscardReason = "resource_type_mismatch"
	// ReasonInvalidSeverity indicates severity outside the allowed set.
	ReasonInvalidSeverity DiscardReason = "invalid_severity"
	// ReasonDuplicate indicates a duplicate finding (same resource + category/description).
	ReasonDuplicate DiscardReason = "duplicate"
	// ReasonEmptyFields indicates missing required fields.
	ReasonEmptyFields DiscardReason = "empty_required_fields"
)

// DiscardedFinding groups a discarded finding with its reason.
type DiscardedFinding struct {
	Finding rules.Finding `json:"finding"`
	Reason  DiscardReason `json:"reason"`
	Detail  string        `json:"detail"`
}

// ValidationReport contains the AI findings validation statistics.
type ValidationReport struct {
	TotalReceived int                `json:"total_received"`
	TotalValid    int                `json:"total_valid"`
	TotalDiscard  int                `json:"total_discarded"`
	Discarded     []DiscardedFinding `json:"discarded,omitempty"`
}

// validSeverities contains the accepted severities.
var validSeverities = map[string]bool{
	rules.SeverityCritical: true,
	rules.SeverityHigh:     true,
	rules.SeverityMedium:   true,
	rules.SeverityLow:      true,
	rules.SeverityInfo:     true,
}

// ValidateAIFindings filters AI-generated findings, discarding those that do not
// match real resources in the topology graph or that are invalid.
//
// Returns the valid findings, the discarded ones, and a validation report.
func ValidateAIFindings(findings []rules.Finding, graph *topology.Graph) (valid []rules.Finding, discarded []DiscardedFinding, report *ValidationReport) {
	report = &ValidationReport{
		TotalReceived: len(findings),
	}

	if len(findings) == 0 {
		return nil, nil, report
	}

	// Build graph node index: address → Node
	nodeIndex := buildNodeIndex(graph)

	// Track duplicates: key = resource|category|descNorm
	seen := make(map[string]bool)

	for _, f := range findings {
		// Rule 5: required fields
		if reason, detail := checkEmptyFields(f); reason != "" {
			discarded = append(discarded, DiscardedFinding{
				Finding: f,
				Reason:  reason,
				Detail:  detail,
			})
			continue
		}

		// Rule 3: valid severity
		if reason, detail := checkSeverity(f); reason != "" {
			discarded = append(discarded, DiscardedFinding{
				Finding: f,
				Reason:  reason,
				Detail:  detail,
			})
			continue
		}

		// Rule 1 + 2: resource existence and type
		if reason, detail := checkResource(f, nodeIndex); reason != "" {
			discarded = append(discarded, DiscardedFinding{
				Finding: f,
				Reason:  reason,
				Detail:  detail,
			})
			continue
		}

		// Rule 4: duplicate detection
		if reason, detail := checkDuplicate(f, seen); reason != "" {
			discarded = append(discarded, DiscardedFinding{
				Finding: f,
				Reason:  reason,
				Detail:  detail,
			})
			continue
		}

		valid = append(valid, f)
	}

	report.TotalValid = len(valid)
	report.TotalDiscard = len(discarded)
	report.Discarded = discarded

	return valid, discarded, report
}

func buildNodeIndex(graph *topology.Graph) map[string]topology.Node {
	index := make(map[string]topology.Node, len(graph.Nodes))
	for _, n := range graph.Nodes {
		index[n.Address] = n
	}
	return index
}

func checkEmptyFields(f rules.Finding) (DiscardReason, string) {
	resource := strings.TrimSpace(f.Resource)
	message := strings.TrimSpace(f.Message)

	if resource == "" && message == "" {
		return ReasonEmptyFields, "resource and message are empty"
	}
	if resource == "" {
		return ReasonEmptyFields, "resource is empty"
	}
	if message == "" {
		return ReasonEmptyFields, "message is empty"
	}
	return "", ""
}

func checkSeverity(f rules.Finding) (DiscardReason, string) {
	sev := strings.ToUpper(strings.TrimSpace(f.Severity))
	if !validSeverities[sev] {
		return ReasonInvalidSeverity, fmt.Sprintf("severity '%s' is not valid (expected: CRITICAL|HIGH|MEDIUM|LOW|INFO)", f.Severity)
	}
	return "", ""
}

func checkResource(f rules.Finding, nodeIndex map[string]topology.Node) (DiscardReason, string) {
	resource := strings.TrimSpace(f.Resource)

	node, exists := nodeIndex[resource]
	if !exists {
		return ReasonResourceNotFound, fmt.Sprintf("resource '%s' does not exist in the Terraform plan", resource)
	}

	// Extract type from finding address (e.g., "aws_s3_bucket" from "aws_s3_bucket.my_bucket")
	findingType := extractResourceType(resource)
	if findingType != "" && node.Type != "" && findingType != node.Type {
		return ReasonResourceTypeMismatch, fmt.Sprintf(
			"finding type '%s' diverges from graph type '%s' for resource '%s'",
			findingType, node.Type, resource,
		)
	}

	return "", ""
}

func checkDuplicate(f rules.Finding, seen map[string]bool) (DiscardReason, string) {
	key := deduplicationKey(f)
	if seen[key] {
		return ReasonDuplicate, fmt.Sprintf("duplicate finding for resource '%s' with category '%s'", f.Resource, f.Category)
	}
	seen[key] = true
	return "", ""
}

// deduplicationKey generates a unique key for duplicate detection.
// Uses resource + category + first 80 characters of the normalized message.
func deduplicationKey(f rules.Finding) string {
	msg := strings.ToLower(strings.TrimSpace(f.Message))
	if len(msg) > 80 {
		msg = msg[:80]
	}
	return fmt.Sprintf("%s|%s|%s",
		strings.ToLower(strings.TrimSpace(f.Resource)),
		strings.ToLower(strings.TrimSpace(f.Category)),
		msg,
	)
}

// extractResourceType extracts the resource type from a Terraform address.
// E.g., "aws_s3_bucket.my_bucket" → "aws_s3_bucket"
//
//	"module.vpc.aws_subnet.private" → "aws_subnet"
func extractResourceType(address string) string {
	// Handle module addresses: module.vpc.aws_subnet.private[0]
	parts := strings.Split(address, ".")
	if len(parts) < 2 {
		return ""
	}

	// Walk backwards to find type.name
	// The type is the second-to-last segment that doesn't start with "module"
	for i := len(parts) - 2; i >= 0; i-- {
		if parts[i] == "module" || (i > 0 && parts[i-1] == "module") {
			continue
		}
		// Remove index if present: "aws_subnet" from "aws_subnet[0]"
		candidate := parts[i]
		if idx := strings.Index(candidate, "["); idx != -1 {
			candidate = candidate[:idx]
		}
		// Terraform resource type always contains underscore and is not "module"
		if strings.Contains(candidate, "_") && candidate != "module" {
			return candidate
		}
	}

	return ""
}

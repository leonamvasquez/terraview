// Package suppression loads and applies .terraview-ignore files.
//
// A .terraview-ignore file allows teams to permanently suppress specific
// findings that are accepted risks or known false positives, so they do
// not reappear on every CI run.
//
// File format (YAML, placed at the project root or specified via --ignore-file):
//
//	version: 1
//	suppressions:
//	  - rule_id: CKV_AWS_130
//	    reason: "public subnets required for ALB"
//
//	  - rule_id: CKV_AWS_260
//	    resource: aws_vpc_security_group_ingress.alb_http
//	    reason: "port 80 needed for HTTP→HTTPS redirect"
//
//	  - resource: aws_subnet.public[0]
//	    reason: "legacy resource, migration planned Q2"
//
//	  - source: llm
//	    reason: "AI analysis disabled for this project"
//
// Matching logic: AND — all non-empty fields in an entry must match.
// A single-field entry (only rule_id) suppresses that rule globally.
package suppression

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"

	"github.com/leonamvasquez/terraview/internal/rules"
)

const DefaultIgnoreFile = ".terraview-ignore"

// Entry represents a single suppression rule in the ignore file.
type Entry struct {
	// RuleID suppresses a specific rule ID. If empty, matches any rule.
	RuleID string `yaml:"rule_id"`
	// Resource suppresses findings on a specific resource address. If empty, matches any resource.
	Resource string `yaml:"resource"`
	// Source suppresses findings from a specific scanner source (checkov, tfsec, llm, etc.).
	// If empty, matches any source.
	Source string `yaml:"source"`
	// Reason is a human-readable explanation. Recommended but not required.
	Reason string `yaml:"reason"`
}

// matches reports whether this entry suppresses the given finding.
// All non-empty fields must match (AND logic).
func (e Entry) matches(f rules.Finding) bool {
	if e.RuleID != "" && e.RuleID != f.RuleID {
		return false
	}
	if e.Resource != "" && e.Resource != f.Resource {
		return false
	}
	if e.Source != "" && e.Source != f.Source {
		return false
	}
	// At least one field must be set to avoid a wildcard entry suppressing everything.
	return e.RuleID != "" || e.Resource != "" || e.Source != ""
}

// File is the parsed representation of a .terraview-ignore file.
type File struct {
	Version      int     `yaml:"version"`
	Suppressions []Entry `yaml:"suppressions"`
}

// Load reads and parses a .terraview-ignore file from the given path.
// Returns an empty File (no suppressions) if the file does not exist.
// Returns an error only for files that exist but cannot be parsed.
func Load(path string) (*File, error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return &File{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("suppression: read %s: %w", path, err)
	}

	var f File
	if err := yaml.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("suppression: parse %s: %w", path, err)
	}
	return &f, nil
}

// Apply filters out any findings matched by the suppression entries.
// It returns the filtered slice and a summary of what was suppressed.
func Apply(findings []rules.Finding, f *File) (filtered []rules.Finding, suppressed []SuppressedFinding) {
	if f == nil || len(f.Suppressions) == 0 {
		return findings, nil
	}

	for _, finding := range findings {
		if entry, ok := matchedBy(finding, f.Suppressions); ok {
			suppressed = append(suppressed, SuppressedFinding{
				Finding: finding,
				Reason:  entry.Reason,
			})
		} else {
			filtered = append(filtered, finding)
		}
	}
	return filtered, suppressed
}

// SuppressedFinding pairs a finding with the reason it was suppressed.
type SuppressedFinding struct {
	Finding rules.Finding
	Reason  string
}

// matchedBy returns the first entry that matches the finding, and true.
// Returns the zero Entry and false if no entry matches.
func matchedBy(f rules.Finding, entries []Entry) (Entry, bool) {
	for _, e := range entries {
		if e.matches(f) {
			return e, true
		}
	}
	return Entry{}, false
}

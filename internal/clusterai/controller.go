// Package clusterai implements cluster-level adaptive AI invocation.
// Instead of running AI per-resource, it groups findings into clusters
// by resource identity and runs a SINGLE batched AI call with all clusters.
// This reduces token usage by 80%+ while preserving analysis quality.
package clusterai

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/leonamvasquez/terraview/internal/ai"
	"github.com/leonamvasquez/terraview/internal/cluster"
	"github.com/leonamvasquez/terraview/internal/parser"
	"github.com/leonamvasquez/terraview/internal/rules"
)

// ────────────────────────── AI Modes ──────────────────────────

// Mode determines the depth of AI analysis for a cluster.
type Mode string

const (
	ModeSkip           Mode = "skip"
	ModeEnrichmentOnly Mode = "enrichment_only"
	ModeFullAnalysis   Mode = "full_analysis"
)

// ────────────────────────── Payloads ──────────────────────────

// EnrichmentPayload is the compressed payload for enrichment_only mode.
type EnrichmentPayload struct {
	ClusterType          string         `json:"cluster_type"`
	Provider             string         `json:"provider"`
	RiskCategories       []string       `json:"risk_categories"`
	SeverityDistribution map[string]int `json:"severity_distribution"`
}

// FullAnalysisPayload is the compressed payload for full_analysis mode.
type FullAnalysisPayload struct {
	ClusterType string   `json:"cluster_type"`
	Provider    string   `json:"provider"`
	RiskVector  RiskVec  `json:"risk_vector"`
	Flags       []string `json:"flags"`
}

// RiskVec is the risk vector embedded in the full_analysis payload.
type RiskVec struct {
	Network       int `json:"network"`
	Encryption    int `json:"encryption"`
	Identity      int `json:"identity"`
	Governance    int `json:"governance"`
	Observability int `json:"observability"`
}

// ────────────────────────── AI Responses ──────────────────────

// EnrichmentResponse is the expected output from enrichment_only mode.
type EnrichmentResponse struct {
	RemediationImprovements string  `json:"remediation_improvements"`
	ArchitecturalNotes      string  `json:"architectural_notes"`
	Confidence              float64 `json:"confidence"`
}

// FullAnalysisResponse is the expected output from full_analysis mode.
type FullAnalysisResponse struct {
	RiskCategories    []string `json:"risk_categories"`
	Severity          string   `json:"severity"`
	ArchitecturalRisk string   `json:"architectural_risk"`
	Remediation       string   `json:"remediation"`
	Confidence        float64  `json:"confidence"`
}

// ClusterResult holds the AI result for a single cluster.
type ClusterResult struct {
	ClusterID  string
	Mode       Mode
	Enrichment *EnrichmentResponse
	FullResult *FullAnalysisResponse
	SkipReason string
	CacheHit   bool
	Error      error
}

// ControllerStats holds aggregate statistics from a controller run.
type ControllerStats struct {
	TotalClusters int
	Skipped       int
	Enriched      int
	FullAnalysis  int
	CacheHits     int
	Errors        int
}

// ────────────────────────── Cache ──────────────────────────

// CachedClusterResult is what gets stored in the cache.
type CachedClusterResult struct {
	Mode       Mode                  `json:"mode"`
	Enrichment *EnrichmentResponse   `json:"enrichment,omitempty"`
	FullResult *FullAnalysisResponse `json:"full_result,omitempty"`
}

// ClusterCache is a thread-safe cache for cluster-level AI results.
type ClusterCache struct {
	mu      sync.RWMutex
	entries map[string]CachedClusterResult
	hits    int
	misses  int
	summary string // AI-generated summary for --explain
}

// NewClusterCache creates a new empty cluster cache.
func NewClusterCache() *ClusterCache {
	return &ClusterCache{
		entries: make(map[string]CachedClusterResult),
	}
}

// Get retrieves a cached result. Thread-safe.
func (cc *ClusterCache) Get(key string) (CachedClusterResult, bool) {
	cc.mu.Lock()
	defer cc.mu.Unlock()

	r, ok := cc.entries[key]
	if ok {
		cc.hits++
	} else {
		cc.misses++
	}
	return r, ok
}

// Put stores a result in the cache. Thread-safe.
func (cc *ClusterCache) Put(key string, result CachedClusterResult) {
	cc.mu.Lock()
	defer cc.mu.Unlock()
	cc.entries[key] = result
}

// SetSummary stores the AI-generated summary for --explain reuse.
func (cc *ClusterCache) SetSummary(s string) {
	cc.mu.Lock()
	defer cc.mu.Unlock()
	cc.summary = s
}

// Summary returns the cached AI summary.
func (cc *ClusterCache) Summary() string {
	cc.mu.RLock()
	defer cc.mu.RUnlock()
	return cc.summary
}

// Stats returns cache hit/miss/size statistics.
func (cc *ClusterCache) Stats() (hits, misses, size int) {
	cc.mu.RLock()
	defer cc.mu.RUnlock()
	return cc.hits, cc.misses, len(cc.entries)
}

// AllResults returns all cached results (for --explain reuse).
func (cc *ClusterCache) AllResults() map[string]CachedClusterResult {
	cc.mu.RLock()
	defer cc.mu.RUnlock()
	out := make(map[string]CachedClusterResult, len(cc.entries))
	for k, v := range cc.entries {
		out[k] = v
	}
	return out
}

// ────────────────────────── Cluster Hashing ──────────────────

// ClusterHash computes a deterministic SHA256 hash for a cluster.
// Includes: provider, cluster_type, sorted risk_categories, severity_distribution.
func ClusterHash(rc *cluster.RiskCluster) string {
	h := sha256.New()

	provider := detectClusterProvider(rc)
	resType := detectClusterType(rc)

	fmt.Fprintf(h, "provider=%s\n", provider)
	fmt.Fprintf(h, "type=%s\n", resType)

	// Sorted risk categories
	cats := collectCategories(rc.Findings)
	sort.Strings(cats)
	fmt.Fprintf(h, "categories=%s\n", strings.Join(cats, ","))

	// Severity distribution (deterministic order)
	dist := severityDistribution(rc.Findings)
	for _, sev := range []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"} {
		fmt.Fprintf(h, "%s=%d\n", sev, dist[sev])
	}

	// Sorted sources
	sources := make([]string, len(rc.Sources))
	copy(sources, rc.Sources)
	sort.Strings(sources)
	fmt.Fprintf(h, "sources=%s\n", strings.Join(sources, ","))

	return hex.EncodeToString(h.Sum(nil))
}

// ────────────────────────── Adaptive Invocation ──────────────

// DetermineMode selects the AI invocation mode for a cluster.
func DetermineMode(rc *cluster.RiskCluster) Mode {
	dist := severityDistribution(rc.Findings)

	// Rule: If cluster has only LOW/INFO severity → skip AI
	if dist["CRITICAL"]+dist["HIGH"]+dist["MEDIUM"] == 0 {
		return ModeSkip
	}

	hasScannerSource := false
	hasAISource := false
	for _, s := range rc.Sources {
		if strings.HasPrefix(s, "scanner:") || strings.HasPrefix(s, "checkov") ||
			strings.HasPrefix(s, "tfsec") || strings.HasPrefix(s, "trivy") ||
			(!strings.HasPrefix(s, "ai/") && !strings.HasPrefix(s, "ai:")) {
			hasScannerSource = true
		}
		if strings.HasPrefix(s, "ai/") || strings.HasPrefix(s, "ai:") {
			hasAISource = true
		}
	}

	// Rule: If cluster has >=5 HIGH findings from scanner only → enrichment_only
	if hasScannerSource && dist["HIGH"] >= 5 {
		return ModeEnrichmentOnly
	}

	// Rule: If cluster contains mixed sources (scanner + ai) → enrichment_only
	if hasScannerSource && hasAISource {
		return ModeEnrichmentOnly
	}

	// Rule: If cluster has no scanner findings but risk flags detected → full_analysis
	if !hasScannerSource {
		return ModeFullAnalysis
	}

	// Default: if scanner found stuff but not enough HIGH → enrichment
	if hasScannerSource && (dist["HIGH"] > 0 || dist["CRITICAL"] > 0 || dist["MEDIUM"] > 0) {
		return ModeEnrichmentOnly
	}

	return ModeSkip
}

// ────────────────────────── Controller ──────────────────────

// Controller orchestrates cluster-level AI invocation.
type Controller struct {
	provider ai.Provider
	cache    *ClusterCache
	workers  int
	lang     string // "pt-BR" for Portuguese output
}

// NewController creates a new cluster AI controller.
func NewController(provider ai.Provider, cache *ClusterCache, workers int) *Controller {
	if workers <= 0 {
		workers = 4
	}
	if cache == nil {
		cache = NewClusterCache()
	}
	return &Controller{
		provider: provider,
		cache:    cache,
		workers:  workers,
	}
}

// SetLang configures the output language for AI prompts.
func (c *Controller) SetLang(lang string) {
	c.lang = lang
}

// Cache returns the controller's cache for reuse (e.g., by --explain).
func (c *Controller) Cache() *ClusterCache {
	return c.cache
}

// pendingCluster tracks a cluster that needs AI analysis.
type pendingCluster struct {
	index int
	mode  Mode
	hash  string
}

// Run processes all clusters through adaptive AI invocation.
// Uses a SINGLE batched AI call for all non-skip clusters,
// reducing token usage to match or beat the v0.3.4 single-call approach.
func (c *Controller) Run(ctx context.Context, clusters []cluster.RiskCluster) ([]ClusterResult, ControllerStats) {
	results := make([]ClusterResult, len(clusters))
	stats := ControllerStats{TotalClusters: len(clusters)}

	// Phase 1: Classify clusters and check cache
	var pending []pendingCluster
	for i := range clusters {
		rc := &clusters[i]
		mode := DetermineMode(rc)
		hash := ClusterHash(rc)

		if mode == ModeSkip {
			results[i] = ClusterResult{
				ClusterID:  rc.ID,
				Mode:       ModeSkip,
				SkipReason: "low-severity-only",
			}
			stats.Skipped++
			continue
		}

		if cached, ok := c.cache.Get(hash); ok {
			results[i] = ClusterResult{
				ClusterID:  rc.ID,
				Mode:       cached.Mode,
				Enrichment: cached.Enrichment,
				FullResult: cached.FullResult,
				CacheHit:   true,
			}
			stats.CacheHits++
			continue
		}

		pending = append(pending, pendingCluster{index: i, mode: mode, hash: hash})
	}

	if len(pending) == 0 {
		return results, stats
	}

	// Phase 2: Build a SINGLE batched prompt for all pending clusters
	req := ai.Request{
		Resources: c.buildBatchResources(clusters, pending),
		Summary:   c.buildBatchPrompt(clusters, pending),
		Prompts: ai.Prompts{
			System: c.buildBatchSystemPrompt(),
		},
	}

	// Phase 3: Single AI call
	completion, err := c.provider.Analyze(ctx, req)
	if err != nil {
		for _, p := range pending {
			results[p.index] = ClusterResult{
				ClusterID: clusters[p.index].ID,
				Mode:      p.mode,
				Error:     err,
			}
			stats.Errors++
		}
		return results, stats
	}

	// Phase 4: Store the AI summary for --explain
	c.cache.SetSummary(completion.Summary)

	// Phase 5: Initialize result slots for pending clusters
	for _, p := range pending {
		results[p.index] = ClusterResult{
			ClusterID: clusters[p.index].ID,
			Mode:      p.mode,
		}
	}

	// Phase 6: Map AI findings back to clusters
	clusterMap := make(map[string]int) // resource address → pending index
	for _, p := range pending {
		rc := &clusters[p.index]
		for _, res := range rc.Resources {
			clusterMap[res] = p.index
		}
		clusterMap[rc.ID] = p.index
	}

	for _, f := range completion.Findings {
		idx, ok := clusterMap[f.Resource]
		if !ok {
			// Try partial match
			for res, pidx := range clusterMap {
				if strings.Contains(f.Resource, res) || strings.Contains(res, f.Resource) {
					idx = pidx
					ok = true
					break
				}
			}
		}
		if !ok {
			continue
		}

		r := &results[idx]
		switch r.Mode {
		case ModeEnrichmentOnly:
			if r.Enrichment == nil {
				r.Enrichment = &EnrichmentResponse{Confidence: 0.85}
			}
			if f.Remediation != "" {
				if r.Enrichment.RemediationImprovements != "" {
					r.Enrichment.RemediationImprovements += "; "
				}
				r.Enrichment.RemediationImprovements += f.Remediation
			}
			if f.Message != "" {
				if r.Enrichment.ArchitecturalNotes != "" {
					r.Enrichment.ArchitecturalNotes += "; "
				}
				r.Enrichment.ArchitecturalNotes += f.Message
			}

		case ModeFullAnalysis:
			if r.FullResult == nil {
				r.FullResult = &FullAnalysisResponse{
					Severity:   normalizeSeverity(f.Severity),
					Confidence: 0.85,
				}
			}
			if f.Category != "" {
				r.FullResult.RiskCategories = append(r.FullResult.RiskCategories, f.Category)
			}
			if f.Message != "" {
				if r.FullResult.ArchitecturalRisk != "" {
					r.FullResult.ArchitecturalRisk += "; "
				}
				r.FullResult.ArchitecturalRisk += f.Message
			}
			if f.Remediation != "" {
				if r.FullResult.Remediation != "" {
					r.FullResult.Remediation += "; "
				}
				r.FullResult.Remediation += f.Remediation
			}
		}
	}

	// Phase 7: Cache results and count stats
	for _, p := range pending {
		r := results[p.index]
		if r.Error != nil {
			stats.Errors++
			continue
		}

		cached := CachedClusterResult{Mode: r.Mode}
		switch r.Mode {
		case ModeEnrichmentOnly:
			cached.Enrichment = r.Enrichment
			stats.Enriched++
		case ModeFullAnalysis:
			cached.FullResult = r.FullResult
			stats.FullAnalysis++
		}
		c.cache.Put(p.hash, cached)
	}

	return results, stats
}

// ────────────────────────── Batch Prompt Builders ──────────────

// buildBatchSystemPrompt creates a concise system prompt for cluster analysis.
// Does NOT include a custom JSON schema — lets the provider's buildSystemPrompt()
// append the standard {findings, summary} schema that parseResponse() expects.
func (c *Controller) buildBatchSystemPrompt() string {
	prompt := `You are a cloud infrastructure security auditor. Analyze the pre-scored Terraform resource clusters below.

Each cluster groups scanner findings by resource. Your job:
1. For "enrichment" clusters: improve remediation advice with architectural context
2. For "analysis" clusters: perform full risk evaluation

Return ONE finding per cluster. Use the cluster's resource address as the "resource" field.
Be concise and actionable. Focus on the highest-impact remediation.`

	if c.lang == "pt-BR" {
		prompt += "\n\nIMPORTANT: You MUST respond entirely in Brazilian Portuguese (pt-BR)."
	}

	return prompt
}

// buildBatchPrompt creates the compressed batch summary for all pending clusters.
func (c *Controller) buildBatchPrompt(clusters []cluster.RiskCluster, pending []pendingCluster) map[string]interface{} {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("%d clusters requiring analysis:\n\n", len(pending)))

	for _, p := range pending {
		rc := &clusters[p.index]
		dist := severityDistribution(rc.Findings)
		cats := collectCategories(rc.Findings)

		sb.WriteString(fmt.Sprintf("### %s [%s]\n", rc.ID, p.mode))
		sb.WriteString(fmt.Sprintf("Type: %s | Provider: %s | Findings: %d\n",
			detectClusterType(rc), detectClusterProvider(rc), len(rc.Findings)))
		sb.WriteString(fmt.Sprintf("Severity: CRIT=%d HIGH=%d MED=%d LOW=%d\n",
			dist["CRITICAL"], dist["HIGH"], dist["MEDIUM"], dist["LOW"]))
		sb.WriteString(fmt.Sprintf("Categories: %s\n", strings.Join(cats, ", ")))

		// Include top finding rule IDs for context
		var ruleIDs []string
		seen := make(map[string]bool)
		for _, f := range rc.Findings {
			if !seen[f.RuleID] && len(ruleIDs) < 5 {
				ruleIDs = append(ruleIDs, f.RuleID)
				seen[f.RuleID] = true
			}
		}
		sb.WriteString(fmt.Sprintf("Top rules: %s\n", strings.Join(ruleIDs, ", ")))

		// Include risk vector for full analysis clusters
		if p.mode == ModeFullAnalysis {
			rv := buildClusterRiskVector(rc)
			sb.WriteString(fmt.Sprintf("Risk vector: net=%d enc=%d iam=%d gov=%d obs=%d\n",
				rv.Network, rv.Encryption, rv.Identity, rv.Governance, rv.Observability))
		}

		sb.WriteString("\n")
	}

	return map[string]interface{}{
		"cluster_analysis": true,
		"total_clusters":   len(pending),
		"analysis":         sb.String(),
	}
}

// buildBatchResources creates the resource list for the batched request.
func (c *Controller) buildBatchResources(clusters []cluster.RiskCluster, pending []pendingCluster) []parser.NormalizedResource {
	resources := make([]parser.NormalizedResource, 0, len(pending))
	for _, p := range pending {
		rc := &clusters[p.index]
		resources = append(resources, parser.NormalizedResource{
			Address:  rc.ID,
			Type:     detectClusterType(rc),
			Provider: detectClusterProvider(rc),
		})
	}
	return resources
}

// ────────────────────────── Result Conversion ────────────────

// ToFindings converts cluster-level AI results into standard rules.Finding entries.
func ToFindings(results []ClusterResult, clusters []cluster.RiskCluster, providerName string) []rules.Finding {
	var findings []rules.Finding
	pName := providerName
	if len(pName) > 3 {
		pName = pName[:3]
	}

	for i, r := range results {
		if r.Mode == ModeSkip || r.Error != nil {
			continue
		}

		resource := r.ClusterID
		if i < len(clusters) && len(clusters[i].Resources) > 0 {
			resource = clusters[i].Resources[0]
		}

		switch r.Mode {
		case ModeEnrichmentOnly:
			if r.Enrichment != nil && (r.Enrichment.RemediationImprovements != "" || r.Enrichment.ArchitecturalNotes != "") {
				msg := r.Enrichment.ArchitecturalNotes
				if msg == "" {
					msg = r.Enrichment.RemediationImprovements
				}
				findings = append(findings, rules.Finding{
					RuleID:      fmt.Sprintf("AI-CLU-%s-ENR", strings.ToUpper(pName)),
					Severity:    "INFO",
					Category:    "best-practice",
					Resource:    resource,
					Message:     msg,
					Remediation: r.Enrichment.RemediationImprovements,
					Source:      "ai/" + providerName,
				})
			}

		case ModeFullAnalysis:
			if r.FullResult != nil && (r.FullResult.ArchitecturalRisk != "" || r.FullResult.Remediation != "") {
				category := "best-practice"
				if len(r.FullResult.RiskCategories) > 0 {
					category = normalizeCategory(r.FullResult.RiskCategories[0])
				}
				catCode := category
				if len(catCode) > 3 {
					catCode = catCode[:3]
				}
				findings = append(findings, rules.Finding{
					RuleID:      fmt.Sprintf("AI-CLU-%s-%s", strings.ToUpper(pName), strings.ToUpper(catCode)),
					Severity:    normalizeSeverity(r.FullResult.Severity),
					Category:    category,
					Resource:    resource,
					Message:     r.FullResult.ArchitecturalRisk,
					Remediation: r.FullResult.Remediation,
					Source:      "ai/" + providerName,
				})
			}
		}
	}

	return findings
}

// GenerateExplainSummary builds an explanation summary from cached cluster results.
// Uses the AI-generated summary (from the single batched call) when available,
// falling back to structured data from individual cluster results.
func GenerateExplainSummary(cache *ClusterCache) string {
	// Primary: use the AI-generated summary from the batched call
	aiSummary := cache.Summary()
	if aiSummary != "" {
		return aiSummary
	}

	// Fallback: build from cached results
	all := cache.AllResults()
	if len(all) == 0 {
		return ""
	}

	var sb strings.Builder
	sb.WriteString("Cluster-level AI analysis summary:\n")

	enriched := 0
	fullAnalyzed := 0

	for _, r := range all {
		switch r.Mode {
		case ModeEnrichmentOnly:
			enriched++
			if r.Enrichment != nil && r.Enrichment.ArchitecturalNotes != "" {
				sb.WriteString(fmt.Sprintf("- [Enrichment] %s\n", r.Enrichment.ArchitecturalNotes))
			}
		case ModeFullAnalysis:
			fullAnalyzed++
			if r.FullResult != nil {
				sb.WriteString(fmt.Sprintf("- [%s] %s → %s\n",
					r.FullResult.Severity,
					r.FullResult.ArchitecturalRisk,
					r.FullResult.Remediation))
			}
		}
	}

	sb.WriteString(fmt.Sprintf("\nTotal: %d enriched, %d fully analyzed\n", enriched, fullAnalyzed))
	return sb.String()
}

// ────────────────────────── Helpers ──────────────────────────

func detectClusterProvider(rc *cluster.RiskCluster) string {
	for _, res := range rc.Resources {
		lower := strings.ToLower(res)
		if strings.HasPrefix(lower, "aws_") {
			return "aws"
		}
		if strings.HasPrefix(lower, "azurerm_") || strings.HasPrefix(lower, "azure_") {
			return "azure"
		}
		if strings.HasPrefix(lower, "google_") || strings.HasPrefix(lower, "gcp_") {
			return "gcp"
		}
	}
	// Try from cluster ID
	lower := strings.ToLower(rc.ID)
	if strings.Contains(lower, "aws_") {
		return "aws"
	}
	if strings.Contains(lower, "azurerm_") {
		return "azure"
	}
	if strings.Contains(lower, "google_") {
		return "gcp"
	}
	return "unknown"
}

func detectClusterType(rc *cluster.RiskCluster) string {
	// Extract resource type from cluster ID (e.g., "aws_security_group.open" → "aws_security_group")
	parts := strings.SplitN(rc.ID, ".", 2)
	if len(parts) >= 1 {
		return parts[0]
	}
	return rc.ID
}

func collectCategories(findings []rules.Finding) []string {
	set := make(map[string]bool)
	for _, f := range findings {
		if f.Category != "" {
			set[strings.ToLower(f.Category)] = true
		}
	}
	cats := make([]string, 0, len(set))
	for k := range set {
		cats = append(cats, k)
	}
	sort.Strings(cats)
	return cats
}

func severityDistribution(findings []rules.Finding) map[string]int {
	dist := map[string]int{
		"CRITICAL": 0,
		"HIGH":     0,
		"MEDIUM":   0,
		"LOW":      0,
		"INFO":     0,
	}
	for _, f := range findings {
		sev := strings.ToUpper(f.Severity)
		if _, ok := dist[sev]; ok {
			dist[sev]++
		}
	}
	return dist
}

func collectFlags(rc *cluster.RiskCluster) []string {
	set := make(map[string]bool)
	for _, f := range rc.Findings {
		// Derive flags from finding characteristics
		if strings.Contains(strings.ToLower(f.Message), "wildcard") || strings.Contains(strings.ToLower(f.Message), "0.0.0.0/0") {
			set["wildcard-cidr"] = true
		}
		if strings.Contains(strings.ToLower(f.Message), "public") {
			set["public-access"] = true
		}
		if strings.Contains(strings.ToLower(f.Message), "encrypt") {
			set["unencrypted"] = true
		}
		if strings.Contains(strings.ToLower(f.Message), "tag") {
			set["no-tags"] = true
		}
		if strings.Contains(strings.ToLower(f.Message), "log") || strings.Contains(strings.ToLower(f.Message), "monitor") {
			set["no-logging"] = true
		}
		if strings.Contains(strings.ToLower(f.Category), "security") {
			set["security-risk"] = true
		}
	}

	flags := make([]string, 0, len(set))
	for k := range set {
		flags = append(flags, k)
	}
	sort.Strings(flags)
	return flags
}

func buildClusterRiskVector(rc *cluster.RiskCluster) RiskVec {
	rv := RiskVec{}

	for _, f := range rc.Findings {
		msg := strings.ToLower(f.Message)
		cat := strings.ToLower(f.Category)
		sev := strings.ToUpper(f.Severity)
		weight := sevWeight(sev)

		// Network
		if strings.Contains(msg, "network") || strings.Contains(msg, "cidr") ||
			strings.Contains(msg, "ingress") || strings.Contains(msg, "egress") ||
			strings.Contains(msg, "firewall") || strings.Contains(msg, "security group") ||
			strings.Contains(msg, "public") || strings.Contains(cat, "networking") {
			rv.Network = clamp(rv.Network+weight, 0, 3)
		}

		// Encryption
		if strings.Contains(msg, "encrypt") || strings.Contains(msg, "kms") ||
			strings.Contains(msg, "ssl") || strings.Contains(msg, "tls") ||
			strings.Contains(msg, "certificate") {
			rv.Encryption = clamp(rv.Encryption+weight, 0, 3)
		}

		// Identity
		if strings.Contains(msg, "iam") || strings.Contains(msg, "role") ||
			strings.Contains(msg, "policy") || strings.Contains(msg, "permission") ||
			strings.Contains(msg, "principal") || strings.Contains(msg, "wildcard") {
			rv.Identity = clamp(rv.Identity+weight, 0, 3)
		}

		// Governance
		if strings.Contains(msg, "tag") || strings.Contains(msg, "label") ||
			strings.Contains(msg, "backup") || strings.Contains(msg, "retention") ||
			strings.Contains(msg, "versioning") || strings.Contains(cat, "compliance") {
			rv.Governance = clamp(rv.Governance+weight, 0, 3)
		}

		// Observability
		if strings.Contains(msg, "log") || strings.Contains(msg, "monitor") ||
			strings.Contains(msg, "metric") || strings.Contains(msg, "alarm") ||
			strings.Contains(msg, "trail") || strings.Contains(msg, "flow") {
			rv.Observability = clamp(rv.Observability+weight, 0, 3)
		}
	}

	return rv
}

func sevWeight(sev string) int {
	switch sev {
	case "CRITICAL":
		return 3
	case "HIGH":
		return 2
	case "MEDIUM":
		return 1
	default:
		return 1
	}
}

func clamp(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

func normalizeSeverity(s string) string {
	s = strings.ToUpper(strings.TrimSpace(s))
	switch s {
	case "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO":
		return s
	default:
		return "INFO"
	}
}

func normalizeCategory(cat string) string {
	cat = strings.ToLower(strings.TrimSpace(cat))
	switch cat {
	case "security", "compliance", "best-practice", "maintainability", "reliability":
		return cat
	default:
		return "best-practice"
	}
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

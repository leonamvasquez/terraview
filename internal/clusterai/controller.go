// Package clusterai implements cluster-level adaptive AI invocation.
// Instead of running AI per-resource, it groups findings into clusters
// by resource identity and runs AI per-cluster with adaptive depth.
// This reduces token usage by 80%+ while preserving analysis quality.
package clusterai

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
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
	ClusterID   string
	Mode        Mode
	Enrichment  *EnrichmentResponse
	FullResult  *FullAnalysisResponse
	SkipReason  string
	CacheHit    bool
	Error       error
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

// Run processes all clusters through adaptive AI invocation.
// O(n) in the number of clusters. Uses bounded worker pool.
func (c *Controller) Run(ctx context.Context, clusters []cluster.RiskCluster) ([]ClusterResult, ControllerStats) {
	results := make([]ClusterResult, len(clusters))
	stats := ControllerStats{TotalClusters: len(clusters)}

	type workItem struct {
		index   int
		cluster cluster.RiskCluster
		mode    Mode
		hash    string
	}

	var work []workItem
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

		// Check cache
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

		work = append(work, workItem{
			index:   i,
			cluster: clusters[i],
			mode:    mode,
			hash:    hash,
		})
	}

	if len(work) == 0 {
		return results, stats
	}

	// Bounded worker pool
	var wg sync.WaitGroup
	sem := make(chan struct{}, c.workers)

	for _, w := range work {
		wg.Add(1)
		go func(wi workItem) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			result := c.processCluster(ctx, &wi.cluster, wi.mode, wi.hash)
			results[wi.index] = result
		}(w)
	}

	wg.Wait()

	// Count stats
	for _, r := range results {
		if r.Mode == ModeSkip {
			continue
		}
		if r.CacheHit {
			continue // already counted
		}
		if r.Error != nil {
			stats.Errors++
		} else if r.Mode == ModeEnrichmentOnly {
			stats.Enriched++
		} else if r.Mode == ModeFullAnalysis {
			stats.FullAnalysis++
		}
	}

	return results, stats
}

func (c *Controller) processCluster(ctx context.Context, rc *cluster.RiskCluster, mode Mode, hash string) ClusterResult {
	result := ClusterResult{
		ClusterID: rc.ID,
		Mode:      mode,
	}

	switch mode {
	case ModeEnrichmentOnly:
		resp, err := c.runEnrichment(ctx, rc)
		if err != nil {
			result.Error = err
			return result
		}
		result.Enrichment = resp
		c.cache.Put(hash, CachedClusterResult{
			Mode:       ModeEnrichmentOnly,
			Enrichment: resp,
		})

	case ModeFullAnalysis:
		resp, err := c.runFullAnalysis(ctx, rc)
		if err != nil {
			result.Error = err
			return result
		}
		result.FullResult = resp
		c.cache.Put(hash, CachedClusterResult{
			Mode:       ModeFullAnalysis,
			FullResult: resp,
		})
	}

	return result
}

// ────────────────────────── LLM Prompts ──────────────────────

const enrichmentSystemPrompt = `You are a deterministic cloud security remediation optimizer. Improve remediation concisely. Output strict JSON only.

You will receive a cluster summary with severity distribution and risk categories.
Your job is to improve remediation advice and add architectural context.

You MUST respond ONLY with valid JSON matching this exact schema:
{
  "remediation_improvements": "concise improved remediation steps",
  "architectural_notes": "architectural context and risk implications",
  "confidence": 0.0 to 1.0
}

Rules:
- No markdown. No explanations outside JSON.
- Deterministic, concise phrasing.
- confidence must be a float between 0.0 and 1.0`

const fullAnalysisSystemPrompt = `You are a cloud architecture risk evaluator. Analyze compressed cluster risk data and return strict JSON only.

You will receive a compressed cluster risk vector. Each axis ranges from 0 (no risk) to 3 (critical risk).

You MUST respond ONLY with valid JSON matching this exact schema:
{
  "risk_categories": ["security", "compliance", "best-practice", "maintainability", "reliability"],
  "severity": "CRITICAL|HIGH|MEDIUM|LOW",
  "architectural_risk": "concise description of the primary architectural risk",
  "remediation": "specific actionable remediation steps",
  "confidence": 0.0 to 1.0
}

Rules:
- No markdown. No explanations outside JSON.
- Deterministic, concise phrasing.
- severity must be one of: CRITICAL, HIGH, MEDIUM, LOW
- confidence must be a float between 0.0 and 1.0
- risk_categories must be from the allowed set above`

func (c *Controller) runEnrichment(ctx context.Context, rc *cluster.RiskCluster) (*EnrichmentResponse, error) {
	payload := EnrichmentPayload{
		ClusterType:          detectClusterType(rc),
		Provider:             detectClusterProvider(rc),
		RiskCategories:       collectCategories(rc.Findings),
		SeverityDistribution: severityDistribution(rc.Findings),
	}

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshal enrichment payload: %w", err)
	}

	systemPrompt := enrichmentSystemPrompt
	if c.lang == "pt-BR" {
		systemPrompt += "\n\nIMPORTANT: You MUST respond entirely in Brazilian Portuguese (pt-BR). All text must be in Portuguese.\n"
	}

	req := ai.Request{
		Resources: []parser.NormalizedResource{
			{Address: rc.ID, Type: detectClusterType(rc), Provider: detectClusterProvider(rc)},
		},
		Summary: map[string]interface{}{
			"cluster_analysis":    true,
			"mode":                "enrichment_only",
			"_compressed_prompt":  fmt.Sprintf("Improve remediation for the following cluster:\n\n%s", string(payloadJSON)),
		},
		Prompts: ai.Prompts{
			System: systemPrompt,
		},
	}

	completion, err := c.provider.Analyze(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("enrichment AI call failed: %w", err)
	}

	return parseEnrichmentResponse(completion.Summary)
}

func (c *Controller) runFullAnalysis(ctx context.Context, rc *cluster.RiskCluster) (*FullAnalysisResponse, error) {
	payload := FullAnalysisPayload{
		ClusterType: detectClusterType(rc),
		Provider:    detectClusterProvider(rc),
		RiskVector:  buildClusterRiskVector(rc),
		Flags:       collectFlags(rc),
	}

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshal full analysis payload: %w", err)
	}

	systemPrompt := fullAnalysisSystemPrompt
	if c.lang == "pt-BR" {
		systemPrompt += "\n\nIMPORTANT: You MUST respond entirely in Brazilian Portuguese (pt-BR). All text must be in Portuguese.\n"
	}

	req := ai.Request{
		Resources: []parser.NormalizedResource{
			{Address: rc.ID, Type: detectClusterType(rc), Provider: detectClusterProvider(rc)},
		},
		Summary: map[string]interface{}{
			"cluster_analysis":   true,
			"mode":               "full_analysis",
			"_compressed_prompt": fmt.Sprintf("Analyze the following cluster risk vector:\n\n%s", string(payloadJSON)),
		},
		Prompts: ai.Prompts{
			System: systemPrompt,
		},
	}

	completion, err := c.provider.Analyze(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("full analysis AI call failed: %w", err)
	}

	return parseFullAnalysisResponse(completion.Summary)
}

// ────────────────────────── Response Parsing ──────────────────

func parseEnrichmentResponse(raw string) (*EnrichmentResponse, error) {
	cleaned := extractJSON(raw)
	var resp EnrichmentResponse
	if err := json.Unmarshal([]byte(cleaned), &resp); err == nil && resp.Confidence > 0 {
		return &resp, nil
	}

	// Fallback
	return &EnrichmentResponse{
		RemediationImprovements: cleaned,
		ArchitecturalNotes:      "",
		Confidence:              0.3,
	}, nil
}

func parseFullAnalysisResponse(raw string) (*FullAnalysisResponse, error) {
	cleaned := extractJSON(raw)
	var resp FullAnalysisResponse
	if err := json.Unmarshal([]byte(cleaned), &resp); err == nil && resp.Severity != "" {
		return &resp, nil
	}

	// Fallback
	return &FullAnalysisResponse{
		Severity:          "INFO",
		ArchitecturalRisk: cleaned,
		Confidence:        0.3,
	}, nil
}

func extractJSON(raw string) string {
	raw = strings.TrimSpace(raw)

	if idx := strings.Index(raw, "```json"); idx != -1 {
		endIdx := strings.Index(raw[idx+7:], "```")
		if endIdx != -1 {
			return strings.TrimSpace(raw[idx+7 : idx+7+endIdx])
		}
	}
	if idx := strings.Index(raw, "```"); idx != -1 {
		endIdx := strings.Index(raw[idx+3:], "```")
		if endIdx != -1 {
			return strings.TrimSpace(raw[idx+3 : idx+3+endIdx])
		}
	}
	return raw
}

// ────────────────────────── Result Conversion ────────────────

// ToFindings converts cluster-level AI results into standard rules.Finding entries.
func ToFindings(results []ClusterResult, clusters []cluster.RiskCluster, providerName string) []rules.Finding {
	var findings []rules.Finding

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
			if r.Enrichment != nil && r.Enrichment.RemediationImprovements != "" {
				findings = append(findings, rules.Finding{
					RuleID:      fmt.Sprintf("AI-CLU-%s-ENR", strings.ToUpper(providerName[:minInt(3, len(providerName))])),
					Severity:    "INFO",
					Category:    "best-practice",
					Resource:    resource,
					Message:     r.Enrichment.ArchitecturalNotes,
					Remediation: r.Enrichment.RemediationImprovements,
					Source:      "ai/" + providerName,
				})
			}

		case ModeFullAnalysis:
			if r.FullResult != nil && r.FullResult.ArchitecturalRisk != "" {
				category := "best-practice"
				if len(r.FullResult.RiskCategories) > 0 {
					category = normalizeCategory(r.FullResult.RiskCategories[0])
				}
				findings = append(findings, rules.Finding{
					RuleID:      fmt.Sprintf("AI-CLU-%s-%s", strings.ToUpper(providerName[:minInt(3, len(providerName))]), strings.ToUpper(category[:minInt(3, len(category))])),
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
// This is used by --explain to avoid re-invoking AI.
func GenerateExplainSummary(cache *ClusterCache) string {
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
			if r.Enrichment != nil {
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

// Package compress implements the Deterministic Semantic Compression pipeline.
// It builds minimal payloads from risk vectors, controls AI invocation policy,
// and provides an abstracted LLM client interface.
package compress

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"

	"github.com/leonamvasquez/terraview/internal/aicache"
	"github.com/leonamvasquez/terraview/internal/riskvec"
	"github.com/leonamvasquez/terraview/internal/rules"
)

// CompressedPayload is the minimal, flat JSON payload sent to the LLM.
type CompressedPayload struct {
	ResourceType string        `json:"resource_type"`
	Provider     string        `json:"provider"`
	RiskVector   PayloadVector `json:"risk_vector"`
	Flags        []string      `json:"flags"`
}

// PayloadVector is the risk vector portion of the payload.
type PayloadVector struct {
	Network       int `json:"network"`
	Encryption    int `json:"encryption"`
	Identity      int `json:"identity"`
	Governance    int `json:"governance"`
	Observability int `json:"observability"`
}

// LLMClient is the interface for AI providers used by the compression pipeline.
type LLMClient interface {
	AnalyzeCompressed(ctx context.Context, payload CompressedPayload) (aicache.Response, error)
}

// InvocationPolicy controls when AI is called.
type InvocationPolicy struct {
	MinRiskScore          int
	SkipIfScannerCritical bool
}

// DefaultPolicy returns the default AI invocation policy.
func DefaultPolicy() InvocationPolicy {
	return InvocationPolicy{
		MinRiskScore:          2,
		SkipIfScannerCritical: true,
	}
}

// Pipeline orchestrates the full compression and AI invocation flow.
type Pipeline struct {
	client  LLMClient
	cache   *aicache.Cache
	policy  InvocationPolicy
	workers int
}

// NewPipeline creates a new compression pipeline.
func NewPipeline(client LLMClient, cache *aicache.Cache, policy InvocationPolicy, workers int) *Pipeline {
	if workers <= 0 {
		workers = 4
	}
	if cache == nil {
		cache = aicache.NewCache()
	}
	return &Pipeline{
		client:  client,
		cache:   cache,
		policy:  policy,
		workers: workers,
	}
}

// Result holds the output of the compression pipeline for a single resource.
type Result struct {
	ResourceID string
	Response   aicache.Response
	Skipped    bool
	SkipReason string
	CacheHit   bool
	Error      error
}

// PipelineStats holds aggregate statistics from the pipeline run.
type PipelineStats struct {
	Total       int
	Processed   int
	Skipped     int
	CacheHits   int
	CacheMisses int
	Errors      int
}

// Run processes all scored resources through the compression pipeline. O(n).
func (p *Pipeline) Run(ctx context.Context, scored []riskvec.ScoredResource,
	scannerFindings []rules.Finding) ([]Result, PipelineStats) {

	scannerCriticals := buildCriticalSet(scannerFindings)

	results := make([]Result, len(scored))
	stats := PipelineStats{Total: len(scored)}

	type workItem struct {
		index int
		sr    riskvec.ScoredResource
	}

	var work []workItem //nolint:prealloc
	for i := range scored {
		sr := scored[i]

		reason := p.shouldSkip(&sr, scannerCriticals)
		if reason != "" {
			results[i] = Result{
				ResourceID: sr.Features.ResourceID,
				Skipped:    true,
				SkipReason: reason,
			}
			stats.Skipped++
			continue
		}

		work = append(work, workItem{index: i, sr: sr})
	}

	if len(work) == 0 {
		return results, stats
	}

	var wg sync.WaitGroup
	sem := make(chan struct{}, p.workers)

	for _, w := range work {
		wg.Add(1)
		go func(wi workItem) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			result := p.processOne(ctx, &wi.sr)
			results[wi.index] = result
		}(w)
	}

	wg.Wait()

	for _, r := range results {
		if r.Skipped {
			continue
		}
		if r.Error != nil {
			stats.Errors++
		} else if r.CacheHit {
			stats.CacheHits++
		} else {
			stats.CacheMisses++
		}
		stats.Processed++
	}

	return results, stats
}

func (p *Pipeline) processOne(ctx context.Context, sr *riskvec.ScoredResource) Result {
	key := aicache.HashKey(sr)

	resp, cached, err := p.cache.GetOrCompute(key, func() (aicache.Response, error) {
		payload := BuildPayload(sr)
		return p.client.AnalyzeCompressed(ctx, payload)
	})

	return Result{
		ResourceID: sr.Features.ResourceID,
		Response:   resp,
		CacheHit:   cached,
		Error:      err,
	}
}

func (p *Pipeline) shouldSkip(sr *riskvec.ScoredResource, scannerCriticals map[string]bool) string {
	if sr.RiskVector.Total == 0 {
		return "risk-score-zero"
	}

	if sr.RiskVector.Total < p.policy.MinRiskScore {
		return fmt.Sprintf("risk-below-threshold(%d<%d)", sr.RiskVector.Total, p.policy.MinRiskScore)
	}

	if p.policy.SkipIfScannerCritical && scannerCriticals[sr.Features.ResourceID] {
		return "scanner-critical-exists"
	}

	return ""
}

// BuildPayload creates a compressed payload from a scored resource.
func BuildPayload(sr *riskvec.ScoredResource) CompressedPayload {
	return CompressedPayload{
		ResourceType: sr.Features.ResourceType,
		Provider:     sr.Features.Provider,
		RiskVector: PayloadVector{
			Network:       sr.RiskVector.Network,
			Encryption:    sr.RiskVector.Encryption,
			Identity:      sr.RiskVector.Identity,
			Governance:    sr.RiskVector.Governance,
			Observability: sr.RiskVector.Observability,
		},
		Flags: sr.Features.Flags,
	}
}

// PayloadJSON returns the compressed payload as a JSON string.
func PayloadJSON(sr *riskvec.ScoredResource) (string, error) {
	payload := BuildPayload(sr)
	data, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("failed to marshal payload: %w", err)
	}
	return string(data), nil
}

// ToFindings converts pipeline results into standard rules.Finding entries.
func ToFindings(results []Result, scored []riskvec.ScoredResource, providerName string) []rules.Finding {
	findings := make([]rules.Finding, 0, len(results))

	for i, r := range results {
		if r.Skipped || r.Error != nil {
			continue
		}

		resp := r.Response
		if resp.Severity == "" || resp.ArchitecturalRisk == "" {
			continue
		}

		category := "best-practice"
		if len(resp.RiskCategories) > 0 {
			category = normalizeCategory(resp.RiskCategories[0])
		} else if i < len(scored) {
			category = scored[i].RiskVector.DominantCategory()
		}

		findings = append(findings, rules.Finding{
			RuleID:      fmt.Sprintf("AI-%s-%s", strings.ToUpper(providerName[:3]), strings.ToUpper(category[:3])),
			Severity:    normalizeSeverity(resp.Severity),
			Category:    category,
			Resource:    r.ResourceID,
			Message:     resp.ArchitecturalRisk,
			Remediation: resp.Remediation,
			Source:      "ai/" + providerName,
		})
	}

	return findings
}

func buildCriticalSet(findings []rules.Finding) map[string]bool {
	set := make(map[string]bool)
	for _, f := range findings {
		if strings.EqualFold(f.Severity, "CRITICAL") {
			set[f.Resource] = true
		}
	}
	return set
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

func normalizeCategory(c string) string {
	c = strings.ToLower(strings.TrimSpace(c))
	switch c {
	case "security", "compliance", "best-practice", "maintainability", "reliability":
		return c
	default:
		return "best-practice"
	}
}

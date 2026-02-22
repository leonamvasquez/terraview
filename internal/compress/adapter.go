package compress

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/leonamvasquez/terraview/internal/ai"
	"github.com/leonamvasquez/terraview/internal/aicache"
	"github.com/leonamvasquez/terraview/internal/parser"
)

const compressedSystemPrompt = `You are a deterministic cloud architecture risk evaluator. Output strict JSON only.

You will receive a compressed resource risk vector. Each risk axis ranges from 0 (no risk) to 3 (critical risk).
Flags indicate specific detected risk attributes.

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
- Deterministic phrasing. Concise remediation.
- severity must be one of: CRITICAL, HIGH, MEDIUM, LOW
- confidence must be a float between 0 and 1
- risk_categories must be from the allowed set above`

const compressedUserTemplate = "Analyze the following compressed resource risk vector and determine architectural risk and remediation.\n\nINPUT:\n%s\n\nReturn JSON strictly matching schema."

// ProviderAdapter adapts an existing ai.Provider to the LLMClient interface.
type ProviderAdapter struct {
	provider ai.Provider
}

// NewProviderAdapter wraps an existing ai.Provider for use with the compression pipeline.
func NewProviderAdapter(provider ai.Provider) *ProviderAdapter {
	return &ProviderAdapter{provider: provider}
}

// AnalyzeCompressed sends a compressed payload to the LLM via the existing provider.
func (pa *ProviderAdapter) AnalyzeCompressed(ctx context.Context, payload CompressedPayload) (aicache.Response, error) {
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return aicache.Response{}, fmt.Errorf("failed to marshal payload: %w", err)
	}

	userPrompt := fmt.Sprintf(compressedUserTemplate, string(payloadJSON))

	req := ai.Request{
		Resources: []parser.NormalizedResource{
			{
				Address:  payload.ResourceType,
				Type:     payload.ResourceType,
				Provider: payload.Provider,
			},
		},
		Summary: map[string]interface{}{
			"compressed_analysis": true,
			"risk_vector":         payload.RiskVector,
			"flags":               payload.Flags,
			"_compressed_prompt":  userPrompt,
		},
		Prompts: ai.Prompts{
			System: compressedSystemPrompt,
		},
	}

	completion, err := pa.provider.Analyze(ctx, req)
	if err != nil {
		return aicache.Response{}, fmt.Errorf("AI analysis failed: %w", err)
	}

	return parseCompressedResponse(completion.Summary)
}

func parseCompressedResponse(summary string) (aicache.Response, error) {
	var resp aicache.Response

	summary = strings.TrimSpace(summary)

	if idx := strings.Index(summary, "```json"); idx != -1 {
		endIdx := strings.Index(summary[idx+7:], "```")
		if endIdx != -1 {
			summary = summary[idx+7 : idx+7+endIdx]
		}
	} else if idx := strings.Index(summary, "```"); idx != -1 {
		endIdx := strings.Index(summary[idx+3:], "```")
		if endIdx != -1 {
			summary = summary[idx+3 : idx+3+endIdx]
		}
	}

	summary = strings.TrimSpace(summary)

	if json.Valid([]byte(summary)) {
		if err := json.Unmarshal([]byte(summary), &resp); err == nil && resp.Severity != "" {
			return resp, nil
		}
	}

	return aicache.Response{
		Severity:          "INFO",
		ArchitecturalRisk: summary,
		Confidence:        0.3,
	}, nil
}

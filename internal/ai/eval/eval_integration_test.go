//go:build eval
// +build eval

package eval

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/leonamvasquez/terraview/internal/ai"
)

// TestEvalIntegration_AwsSaas runs the aws-saas eval case against a real AI
// provider. Skipped unless TERRAVIEW_EVAL_PROVIDER is set.
//
// Usage:
//
//	TERRAVIEW_EVAL_PROVIDER=gemini go test -tags=eval ./internal/ai/eval/... -v -run TestEvalIntegration_AwsSaas
func TestEvalIntegration_AwsSaas(t *testing.T) {
	providerName := os.Getenv("TERRAVIEW_EVAL_PROVIDER")
	if providerName == "" {
		t.Skip("TERRAVIEW_EVAL_PROVIDER not set; skipping integration eval")
	}

	provider, err := ai.Create(providerName, ai.ProviderConfig{})
	if err != nil {
		t.Fatalf("create provider %q: %v", providerName, err)
	}

	evalsDir := filepath.Join("..", "..", "..", "testdata", "evals")
	runner := NewRunner(evalsDir, provider)

	cases, err := runner.LoadCases()
	if err != nil {
		t.Fatalf("LoadCases: %v", err)
	}

	var awsSaas *EvalCase
	for i := range cases {
		if cases[i].Name == "aws-saas" {
			awsSaas = &cases[i]
			break
		}
	}
	if awsSaas == nil {
		t.Fatal("aws-saas case not found in testdata/evals")
	}

	res := runner.Run(context.Background(), *awsSaas)
	if !res.Pass {
		t.Errorf("aws-saas eval failed with %d issues:", len(res.Failures))
		for _, f := range res.Failures {
			t.Errorf("  - %s", f)
		}
	}

	t.Logf("findings: %d", len(res.Findings))
	t.Logf("summary snippet: %.200s", res.Summary)
}

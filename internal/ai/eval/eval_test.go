package eval

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/leonamvasquez/terraview/internal/ai"
	"github.com/leonamvasquez/terraview/internal/rules"
)

// stubProvider implements ai.Provider for testing without real HTTP calls.
type stubProvider struct {
	findings []rules.Finding
	summary  string
}

func (s *stubProvider) Name() string { return "stub" }

func (s *stubProvider) Validate(_ context.Context) error { return nil }

func (s *stubProvider) Analyze(_ context.Context, _ ai.Request) (ai.Completion, error) {
	return ai.Completion{
		Findings: s.findings,
		Summary:  s.summary,
		Model:    "stub-model",
		Provider: "stub",
	}, nil
}

func (s *stubProvider) Complete(_ context.Context, _, _ string) (string, error) {
	return s.summary, nil
}

// writeGolden writes a GoldenCriteria as golden.json inside dir.
func writeGolden(t *testing.T, dir string, gc GoldenCriteria) {
	t.Helper()
	data, err := json.Marshal(gc)
	if err != nil {
		t.Fatalf("marshal golden: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "golden.json"), data, 0o644); err != nil {
		t.Fatalf("write golden.json: %v", err)
	}
}

// minimalPlanJSON is a syntactically valid but content-minimal terraform plan.
const minimalPlanJSON = `{
  "format_version": "0.1",
  "terraform_version": "1.5.0",
  "planned_values": {
    "root_module": {
      "resources": []
    }
  },
  "resource_changes": [
    {
      "address": "aws_s3_bucket.example",
      "mode": "managed",
      "type": "aws_s3_bucket",
      "name": "example",
      "provider_name": "registry.terraform.io/hashicorp/aws",
      "change": {
        "actions": ["create"],
        "before": null,
        "after": {"bucket": "example"}
      }
    }
  ],
  "configuration": {
    "provider_config": {},
    "root_module": {}
  }
}`

// writePlan writes minimalPlanJSON as plan.json inside dir.
func writePlan(t *testing.T, dir string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, "plan.json"), []byte(minimalPlanJSON), 0o644); err != nil {
		t.Fatalf("write plan.json: %v", err)
	}
}

// makeCase builds a fully populated eval directory inside a temp dir and returns
// the evalsDir and the case name.
func makeCase(t *testing.T, name string, gc GoldenCriteria) (evalsDir string) {
	t.Helper()
	root := t.TempDir()
	caseDir := filepath.Join(root, name)
	if err := os.MkdirAll(caseDir, 0o755); err != nil {
		t.Fatalf("mkdir case: %v", err)
	}
	writePlan(t, caseDir)
	writeGolden(t, caseDir, gc)
	return root
}

// ---- TestLoadCases_AwsSaas ---------------------------------------------------

func TestLoadCases_AwsSaas(t *testing.T) {
	// Point at the real testdata directory so we verify the fixture exists.
	evalsDir := filepath.Join("..", "..", "..", "testdata", "evals")

	runner := NewRunner(evalsDir, &stubProvider{})
	cases, err := runner.LoadCases()
	if err != nil {
		t.Fatalf("LoadCases: %v", err)
	}

	var found bool
	for _, c := range cases {
		if c.Name == "aws-saas" {
			found = true
			if c.PlanPath == "" {
				t.Error("aws-saas: PlanPath is empty")
			}
			if c.Golden.Name == "" {
				t.Error("aws-saas: Golden.Name is empty")
			}
			break
		}
	}
	if !found {
		t.Error("aws-saas case not found in testdata/evals")
	}
}

// ---- TestRun_PassAllCriteria ------------------------------------------------

func TestRun_PassAllCriteria(t *testing.T) {
	gc := GoldenCriteria{
		Name:                "pass-all",
		MinFindings:         1,
		RequiredFindingsAny: []string{"HIGH"},
		RequiredSections:    []string{"Security"},
		ForbiddenStrings:    []string{"PLACEHOLDER"},
		MaxResponseTokens:   4000,
	}
	evalsDir := makeCase(t, "pass-all", gc)

	stub := &stubProvider{
		findings: []rules.Finding{
			{RuleID: "CKV_AWS_1", Severity: "HIGH", Source: "llm", Resource: "aws_s3_bucket.example"},
		},
		summary: "Security: one HIGH finding detected in S3 bucket configuration.",
	}

	runner := NewRunner(evalsDir, stub)
	cases, err := runner.LoadCases()
	if err != nil {
		t.Fatalf("LoadCases: %v", err)
	}
	if len(cases) == 0 {
		t.Fatal("no cases loaded")
	}

	res := runner.Run(context.Background(), cases[0])
	if !res.Pass {
		t.Errorf("expected Pass=true, got failures: %v", res.Failures)
	}
}

// ---- TestRun_FailMinFindings ------------------------------------------------

func TestRun_FailMinFindings(t *testing.T) {
	gc := GoldenCriteria{
		Name:        "fail-min",
		MinFindings: 3,
	}
	evalsDir := makeCase(t, "fail-min", gc)

	stub := &stubProvider{
		findings: []rules.Finding{
			{RuleID: "CKV_AWS_1", Severity: "HIGH", Source: "llm"},
		},
		summary: "One finding only.",
	}

	runner := NewRunner(evalsDir, stub)
	cases, err := runner.LoadCases()
	if err != nil {
		t.Fatalf("LoadCases: %v", err)
	}

	res := runner.Run(context.Background(), cases[0])
	if res.Pass {
		t.Error("expected Pass=false for min_findings violation")
	}

	failedMinFindings := false
	for _, f := range res.Failures {
		if contains(f, "min_findings") {
			failedMinFindings = true
		}
	}
	if !failedMinFindings {
		t.Errorf("expected min_findings failure, got: %v", res.Failures)
	}
}

// ---- TestRun_FailForbiddenString --------------------------------------------

func TestRun_FailForbiddenString(t *testing.T) {
	gc := GoldenCriteria{
		Name:             "fail-forbidden",
		ForbiddenStrings: []string{"PLACEHOLDER"},
	}
	evalsDir := makeCase(t, "fail-forbidden", gc)

	stub := &stubProvider{
		summary: "PLACEHOLDER content here.",
	}

	runner := NewRunner(evalsDir, stub)
	cases, err := runner.LoadCases()
	if err != nil {
		t.Fatalf("LoadCases: %v", err)
	}

	res := runner.Run(context.Background(), cases[0])
	if res.Pass {
		t.Error("expected Pass=false for forbidden_strings violation")
	}

	failedForbidden := false
	for _, f := range res.Failures {
		if contains(f, "forbidden_strings") {
			failedForbidden = true
		}
	}
	if !failedForbidden {
		t.Errorf("expected forbidden_strings failure, got: %v", res.Failures)
	}
}

// ---- TestRun_FailRequiredSection -------------------------------------------

func TestRun_FailRequiredSection(t *testing.T) {
	gc := GoldenCriteria{
		Name:             "fail-section",
		RequiredSections: []string{"Security"},
	}
	evalsDir := makeCase(t, "fail-section", gc)

	stub := &stubProvider{
		summary: "Everything looks fine.",
	}

	runner := NewRunner(evalsDir, stub)
	cases, err := runner.LoadCases()
	if err != nil {
		t.Fatalf("LoadCases: %v", err)
	}

	res := runner.Run(context.Background(), cases[0])
	if res.Pass {
		t.Error("expected Pass=false for required_sections violation")
	}

	failedSection := false
	for _, f := range res.Failures {
		if contains(f, "required_sections") {
			failedSection = true
		}
	}
	if !failedSection {
		t.Errorf("expected required_sections failure, got: %v", res.Failures)
	}
}

// ---- TestRun_PassRequiredFindingsAny ----------------------------------------

func TestRun_PassRequiredFindingsAny(t *testing.T) {
	tests := []struct {
		name     string
		findings []rules.Finding
		subs     []string
		wantPass bool
	}{
		{
			name: "matches RuleID prefix",
			findings: []rules.Finding{
				{RuleID: "CKV_AWS_21", Severity: "MEDIUM", Source: "llm"},
			},
			subs:     []string{"CKV_AWS_"},
			wantPass: true,
		},
		{
			name: "matches Severity",
			findings: []rules.Finding{
				{RuleID: "CUSTOM_001", Severity: "CRITICAL", Source: "llm"},
			},
			subs:     []string{"CRITICAL"},
			wantPass: true,
		},
		{
			name:     "no match",
			findings: []rules.Finding{},
			subs:     []string{"CKV_AWS_", "HIGH"},
			wantPass: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gc := GoldenCriteria{
				Name:                tc.name,
				RequiredFindingsAny: tc.subs,
			}
			evalsDir := makeCase(t, tc.name, gc)

			stub := &stubProvider{
				findings: tc.findings,
				summary:  "Analysis complete.",
			}

			runner := NewRunner(evalsDir, stub)
			cases, err := runner.LoadCases()
			if err != nil {
				t.Fatalf("LoadCases: %v", err)
			}

			res := runner.Run(context.Background(), cases[0])
			if res.Pass != tc.wantPass {
				t.Errorf("Pass=%v, want %v; failures: %v", res.Pass, tc.wantPass, res.Failures)
			}
		})
	}
}

// contains is a helper for checking substring presence in failure messages.
func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(sub) == 0 ||
		func() bool {
			for i := 0; i <= len(s)-len(sub); i++ {
				if s[i:i+len(sub)] == sub {
					return true
				}
			}
			return false
		}())
}

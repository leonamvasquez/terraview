package eval

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/leonamvasquez/terraview/internal/ai"
	"github.com/leonamvasquez/terraview/internal/rules"
)

// writeFile is a tiny helper used across tests in this package.
func writeFile(path, content string) error {
	return os.WriteFile(path, []byte(content), 0o644)
}

func mkdirAll(path string) error { return os.MkdirAll(path, 0o755) }

// fakeProvider is a canned ai.Provider that returns a preset Completion
// regardless of input. Enough to drive Runner end-to-end without a live
// backend.
type fakeProvider struct {
	completion ai.Completion
	err        error
	calls      int
}

func (f *fakeProvider) Name() string                       { return "fake" }
func (f *fakeProvider) Validate(ctx context.Context) error { return nil }
func (f *fakeProvider) Analyze(ctx context.Context, req ai.Request) (ai.Completion, error) {
	f.calls++
	if f.err != nil {
		return ai.Completion{}, f.err
	}
	return f.completion, nil
}
func (f *fakeProvider) Complete(ctx context.Context, system, user string) (string, error) {
	return "", nil
}

func TestRunner_Run_Pass(t *testing.T) {
	p := &fakeProvider{
		completion: ai.Completion{
			Findings: []rules.Finding{
				{RuleID: "AI_S3_PUBLIC", Severity: "HIGH", Resource: "aws_s3_bucket.public_data", Message: "Bucket is public-read — exposes data"},
			},
			Summary:  "Overall risk: public data exposure",
			Model:    "fake-model",
			Provider: "fake",
		},
	}
	r := NewRunner(p, "en", 0)

	c, err := LoadCase(filepath.Join("testdata", "evals", "s3-public"))
	if err != nil {
		t.Fatalf("LoadCase: %v", err)
	}

	rep, err := r.Run(context.Background(), c)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !rep.Passed {
		t.Errorf("expected pass, got failures: %v", rep.Failures)
	}
	if rep.Findings != 1 {
		t.Errorf("expected 1 finding, got %d", rep.Findings)
	}
	if rep.Provider != "fake" || rep.Model != "fake-model" {
		t.Errorf("provider/model not propagated: %+v", rep)
	}
}

func TestRunner_Run_FailsOnMissingResource(t *testing.T) {
	p := &fakeProvider{
		completion: ai.Completion{
			Findings: []rules.Finding{
				// Wrong resource address — golden requires aws_s3_bucket.public_data.
				{RuleID: "AI_S3_PUBLIC", Severity: "HIGH", Resource: "aws_s3_bucket.other", Message: "public-read"},
			},
			Summary: "public",
		},
	}
	r := NewRunner(p, "en", 0)
	c, _ := LoadCase(filepath.Join("testdata", "evals", "s3-public"))

	rep, err := r.Run(context.Background(), c)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if rep.Passed {
		t.Fatal("expected case to fail on missing resource")
	}
	joined := strings.Join(rep.Failures, " ")
	if !strings.Contains(joined, "aws_s3_bucket.public_data") {
		t.Errorf("expected missing-resource failure, got %v", rep.Failures)
	}
}

func TestRunner_Run_ParseError(t *testing.T) {
	dir := t.TempDir()
	if err := writeFile(filepath.Join(dir, "plan.json"), "not json"); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := writeFile(filepath.Join(dir, "golden.yaml"), "description: bad\n"); err != nil {
		t.Fatalf("write: %v", err)
	}
	c, err := LoadCase(dir)
	if err != nil {
		t.Fatalf("LoadCase: %v", err)
	}
	r := NewRunner(&fakeProvider{}, "en", 0)
	if _, err := r.Run(context.Background(), c); err == nil {
		t.Fatal("expected parse error")
	}
}

func TestRunner_RunAll_AggregatesReports(t *testing.T) {
	// Findings must satisfy ALL cases under testdata/evals/ simultaneously,
	// because the same fakeProvider is used for every case in RunAll.
	p := &fakeProvider{
		completion: ai.Completion{
			Findings: []rules.Finding{
				// s3-public
				{Severity: "HIGH", Resource: "aws_s3_bucket.public_data", Message: "public s3 bucket exposed"},
				// sg-open
				{Severity: "HIGH", Resource: "aws_security_group.web", Message: "security group 0.0.0.0/0 ingress"},
				{Severity: "HIGH", Resource: "aws_instance.bastion", Message: "bastion exposed via security group"},
				// ecs-simple
				{Severity: "HIGH", Resource: "aws_cloudwatch_log_group.ecs", Message: "log group missing encryption at rest"},
				{Severity: "MEDIUM", Resource: "aws_lb_listener.http", Message: "listener uses plain HTTP not HTTPS"},
				// eks-cluster
				{Severity: "HIGH", Resource: "aws_eks_cluster.main", Message: "public endpoint accessible from 0.0.0.0/0"},
				{Severity: "HIGH", Resource: "aws_security_group.eks_nodes", Message: "ssh port 22 open to 0.0.0.0/0"},
				// networking-complex
				{Severity: "HIGH", Resource: "aws_security_group.bastion", Message: "ssh and rdp open to internet"},
				{Severity: "MEDIUM", Resource: "aws_lb.external", Message: "load balancer missing access logs and encryption config"},
			},
			Summary: "public exposure and wide-open security group with missing encryption and ssh access",
		},
	}
	r := NewRunner(p, "en", 0)
	cases, err := LoadCases(filepath.Join("testdata", "evals"))
	if err != nil {
		t.Fatalf("LoadCases: %v", err)
	}

	reports, err := r.RunAll(context.Background(), cases)
	if err != nil {
		t.Fatalf("RunAll: %v", err)
	}
	if len(reports) != len(cases) {
		t.Fatalf("expected %d reports, got %d", len(cases), len(reports))
	}
	for _, rep := range reports {
		if !rep.Passed {
			t.Errorf("case %s failed: %v", rep.Case, rep.Failures)
		}
	}
	if p.calls != len(cases) {
		t.Errorf("expected %d provider calls, got %d", len(cases), p.calls)
	}

	summary := Summary(reports)
	if !strings.Contains(summary, "cases passed") {
		t.Errorf("unexpected summary: %q", summary)
	}
}

func TestRunner_RunAll_RespectsContextCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r := NewRunner(&fakeProvider{}, "en", 0)
	cases, _ := LoadCases(filepath.Join("testdata", "evals"))
	reports, err := r.RunAll(ctx, cases)
	if err == nil {
		t.Fatal("expected context.Canceled error")
	}
	if len(reports) != 0 {
		t.Errorf("expected 0 reports after immediate cancel, got %d", len(reports))
	}
}

package contextanalysis

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/leonamvasquez/terraview/internal/ai"
	"github.com/leonamvasquez/terraview/internal/parser"
	"github.com/leonamvasquez/terraview/internal/rules"
)

// mockProvider implements ai.Provider without network calls.
type mockProvider struct {
	name     string
	findings []rules.Finding
	summary  string
	err      error
	calls    int
}

func (m *mockProvider) Name() string                                            { return m.name }
func (m *mockProvider) Validate(_ context.Context) error                        { return nil }
func (m *mockProvider) Complete(_ context.Context, _, _ string) (string, error) { return "", nil }
func (m *mockProvider) Analyze(_ context.Context, _ ai.Request) (ai.Completion, error) {
	m.calls++
	if m.err != nil {
		return ai.Completion{}, m.err
	}
	return ai.Completion{
		Findings: m.findings,
		Summary:  m.summary,
		Model:    "test-model",
		Provider: m.name,
	}, nil
}

// makeResources returns n NormalizedResources with action "create".
func makeResources(n int) []parser.NormalizedResource {
	rs := make([]parser.NormalizedResource, n)
	for i := range rs {
		rs[i] = parser.NormalizedResource{
			Address:  fmt.Sprintf("aws_instance.r%d", i),
			Type:     "aws_instance",
			Action:   "create",
			Provider: "aws",
		}
	}
	return rs
}

// ── runSingle ──────────────────────────────────────────────────────────

func TestRunSingle_ReturnsFindings(t *testing.T) {
	want := []rules.Finding{
		{RuleID: "CTX-001", Resource: "aws_instance.r0", Severity: "HIGH", Message: "exposed"},
	}
	p := &mockProvider{name: "mock", findings: want, summary: "one issue"}
	a := NewAnalyzer(p, "", "", 0)

	result, err := a.runSingle(context.Background(), makeResources(1), nil, 0, 0, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("want 1 finding, got %d", len(result.Findings))
	}
	if result.Findings[0].Source != "ai/context" {
		t.Errorf("source must be tagged 'ai/context', got %q", result.Findings[0].Source)
	}
	if result.Summary != "one issue" {
		t.Errorf("summary mismatch: %q", result.Summary)
	}
	if result.Model != "test-model" {
		t.Errorf("model mismatch: %q", result.Model)
	}
}

func TestRunSingle_ProviderError_Propagates(t *testing.T) {
	p := &mockProvider{name: "mock", err: errors.New("provider down")}
	a := NewAnalyzer(p, "", "", 0)

	_, err := a.runSingle(context.Background(), makeResources(1), nil, 0, 0, 0)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "context analysis failed") {
		t.Errorf("want 'context analysis failed' in error, got: %v", err)
	}
}

func TestRunSingle_TokenDebugBranch(t *testing.T) {
	t.Setenv("TERRAVIEW_TOKEN_DEBUG", "1")
	p := &mockProvider{name: "mock", findings: nil, summary: "ok"}
	a := NewAnalyzer(p, "", "", 0)

	result, err := a.runSingle(context.Background(), makeResources(2), nil, 1, 2, 5)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
}

// ── Analyze — single path ──────────────────────────────────────────────

func TestAnalyze_SingleBatch_Success(t *testing.T) {
	want := []rules.Finding{
		{RuleID: "CTX-001", Resource: "aws_instance.r0", Severity: "MEDIUM", Message: "missing monitoring"},
	}
	p := &mockProvider{name: "mock", findings: want, summary: "check monitoring"}
	a := NewAnalyzer(p, "", "", 10) // batchSize=10, resources=3 → single

	result, err := a.Analyze(context.Background(), makeResources(3), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) != 1 {
		t.Errorf("want 1 finding, got %d", len(result.Findings))
	}
	if result.Findings[0].Source != "ai/context" {
		t.Errorf("source must be 'ai/context', got %q", result.Findings[0].Source)
	}
	if p.calls != 1 {
		t.Errorf("want 1 provider call, got %d", p.calls)
	}
}

func TestAnalyze_SingleBatch_ProviderError(t *testing.T) {
	p := &mockProvider{name: "mock", err: errors.New("api error")}
	a := NewAnalyzer(p, "", "", 10)

	_, err := a.Analyze(context.Background(), makeResources(3), nil)
	if err == nil {
		t.Fatal("expected error propagation, got nil")
	}
}

func TestAnalyze_ExcludedNoOp_SetOnResult(t *testing.T) {
	// Mix: 2 active + 2 no-op. Provider returns empty findings.
	p := &mockProvider{name: "mock", findings: nil, summary: "ok"}
	a := NewAnalyzer(p, "", "", 10)

	resources := []parser.NormalizedResource{
		{Address: "aws_instance.r0", Type: "aws_instance", Action: "create"},
		{Address: "aws_vpc.v0", Type: "aws_vpc", Action: "no-op"},
		{Address: "aws_subnet.s0", Type: "aws_subnet", Action: "read"},
		{Address: "aws_sg.g0", Type: "aws_security_group", Action: "update"},
	}

	result, err := a.Analyze(context.Background(), resources, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.ExcludedNoOp != 2 {
		t.Errorf("want ExcludedNoOp=2, got %d", result.ExcludedNoOp)
	}
	if p.calls != 1 {
		t.Errorf("want 1 provider call for 2 active resources, got %d", p.calls)
	}
}

// ── runBatched ─────────────────────────────────────────────────────────

func TestRunBatched_MultipleBatches(t *testing.T) {
	callCount := 0
	p := &mockProvider{name: "mock", summary: "batch ok"}
	p.findings = []rules.Finding{
		{RuleID: "CTX-001", Resource: "aws_instance.r0", Severity: "HIGH", Message: "issue"},
	}

	// Override with a custom function by using a counting mock
	counting := &countingProvider{
		delegate: p,
		onCall: func(n int) ([]rules.Finding, string) {
			callCount = n
			return []rules.Finding{
				{RuleID: fmt.Sprintf("CTX-%03d", n), Resource: fmt.Sprintf("r%d", n), Severity: "LOW", Message: fmt.Sprintf("issue-%d", n)},
			}, "batch summary"
		},
	}

	a := NewAnalyzer(counting, "", "", 2) // batchSize=2, 5 resources → 3 batches

	result, err := a.runBatched(context.Background(), makeResources(5), nil, 2)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if callCount != 3 {
		t.Errorf("want 3 batch calls, got %d", callCount)
	}
	if len(result.Findings) != 3 {
		t.Errorf("want 3 findings (1 per batch), got %d", len(result.Findings))
	}
	if result.Summary != "batch summary" {
		t.Errorf("summary should be first batch summary, got %q", result.Summary)
	}
}

func TestRunBatched_GracefulDegradation(t *testing.T) {
	// First batch fails, second succeeds.
	callNum := 0
	p := &failFirstProvider{
		failCalls: 1,
		success: ai.Completion{
			Findings: []rules.Finding{{RuleID: "CTX-OK", Resource: "r", Severity: "HIGH", Message: "found"}},
			Summary:  "partial ok",
			Model:    "m",
			Provider: "p",
		},
		callNum: &callNum,
	}
	a := NewAnalyzer(p, "", "", 2) // batchSize=2, 4 resources → 2 batches

	result, err := a.runBatched(context.Background(), makeResources(4), nil, 2)
	if err != nil {
		t.Fatalf("expected graceful degradation, got error: %v", err)
	}
	// First batch failed (skipped), second succeeded → 1 finding
	if len(result.Findings) != 1 {
		t.Errorf("want 1 finding from successful batch, got %d", len(result.Findings))
	}
}

func TestRunBatched_AllBatchesFail(t *testing.T) {
	p := &mockProvider{name: "mock", err: errors.New("always fails")}
	a := NewAnalyzer(p, "", "", 2)

	result, err := a.runBatched(context.Background(), makeResources(4), nil, 2)
	if err != nil {
		t.Fatalf("all-fail must not return error (graceful): %v", err)
	}
	if len(result.Findings) != 0 {
		t.Errorf("want 0 findings when all batches fail, got %d", len(result.Findings))
	}
	if result.Summary != "No issues found." {
		t.Errorf("want 'No issues found.' summary, got %q", result.Summary)
	}
}

func TestRunBatched_ContextCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	callNum := 0
	p := &cancelOnCallProvider{cancel: cancel, cancelAfter: 1}
	a := NewAnalyzer(p, "", "", 2) // batchSize=2, 6 resources → 3 batches

	result, err := a.runBatched(ctx, makeResources(6), nil, 2)
	if err != nil {
		t.Fatalf("context cancel should produce graceful result, not error: %v", err)
	}
	_ = callNum
	// Only first batch ran before cancel → at most 1 finding
	if len(result.Findings) > 1 {
		t.Errorf("context cancel should stop after first batch, got %d findings", len(result.Findings))
	}
}

func TestAnalyze_BatchedPath_Triggered(t *testing.T) {
	p := &mockProvider{name: "mock", findings: nil, summary: "batched ok"}
	a := NewAnalyzer(p, "", "", 2) // batchSize=2, 5 resources → runBatched

	result, err := a.Analyze(context.Background(), makeResources(5), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.calls != 3 {
		t.Errorf("want 3 batch calls for 5 resources with batchSize=2, got %d", p.calls)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
}

// ── helper mock types ──────────────────────────────────────────────────

// countingProvider counts calls and delegates result to a function.
type countingProvider struct {
	delegate *mockProvider
	onCall   func(n int) ([]rules.Finding, string)
	n        int
}

func (c *countingProvider) Name() string                                            { return "counting" }
func (c *countingProvider) Validate(_ context.Context) error                        { return nil }
func (c *countingProvider) Complete(_ context.Context, _, _ string) (string, error) { return "", nil }
func (c *countingProvider) Analyze(_ context.Context, _ ai.Request) (ai.Completion, error) {
	c.n++
	findings, summary := c.onCall(c.n)
	return ai.Completion{Findings: findings, Summary: summary, Model: "m", Provider: "p"}, nil
}

// failFirstProvider fails the first N calls then returns success.
type failFirstProvider struct {
	failCalls int
	success   ai.Completion
	callNum   *int
}

func (f *failFirstProvider) Name() string                                            { return "failfirst" }
func (f *failFirstProvider) Validate(_ context.Context) error                        { return nil }
func (f *failFirstProvider) Complete(_ context.Context, _, _ string) (string, error) { return "", nil }
func (f *failFirstProvider) Analyze(_ context.Context, _ ai.Request) (ai.Completion, error) {
	*f.callNum++
	if *f.callNum <= f.failCalls {
		return ai.Completion{}, errors.New("simulated failure")
	}
	return f.success, nil
}

// cancelOnCallProvider cancels the context after cancelAfter calls.
type cancelOnCallProvider struct {
	cancel      context.CancelFunc
	cancelAfter int
	n           int
}

func (c *cancelOnCallProvider) Name() string                     { return "cancel" }
func (c *cancelOnCallProvider) Validate(_ context.Context) error { return nil }
func (c *cancelOnCallProvider) Complete(_ context.Context, _, _ string) (string, error) {
	return "", nil
}
func (c *cancelOnCallProvider) Analyze(_ context.Context, _ ai.Request) (ai.Completion, error) {
	c.n++
	if c.n >= c.cancelAfter {
		c.cancel()
	}
	return ai.Completion{Summary: "ok"}, nil
}

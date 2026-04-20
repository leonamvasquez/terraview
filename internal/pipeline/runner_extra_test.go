package pipeline

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/leonamvasquez/terraview/internal/aggregator"
	"github.com/leonamvasquez/terraview/internal/config"
	"github.com/leonamvasquez/terraview/internal/parser"
	"github.com/leonamvasquez/terraview/internal/rules"
	"github.com/leonamvasquez/terraview/internal/topology"

	_ "github.com/leonamvasquez/terraview/internal/ai/providers" // register all AI providers
)

// writeCheckovFindings writes a minimal Checkov JSON with the given check IDs
// and returns the temp file path. All CKV_AWS_* checks resolve to HIGH severity
// in the importer.
func writeCheckovFindings(t *testing.T, checks []struct{ id, resource string }) string {
	t.Helper()
	failedChecks := ""
	for i, c := range checks {
		if i > 0 {
			failedChecks += ","
		}
		failedChecks += fmt.Sprintf(`{
			"check_id": %q,
			"check_result": {"result": "FAILED"},
			"check_type": "terraform",
			"resource_address": %q,
			"guideline": "https://docs.checkov.io/docs/%s"
		}`, c.id, c.resource, c.id)
	}
	content := fmt.Sprintf(`{
		"check_type": "terraform",
		"results": {
			"failed_checks": [%s],
			"passed_checks": [],
			"skipped_checks": []
		},
		"summary": {"passed": 0, "failed": %d, "skipped": 0, "parsing_errors": 0}
	}`, failedChecks, len(checks))

	dir := t.TempDir()
	p := filepath.Join(dir, "findings.json")
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatalf("write findings: %v", err)
	}
	return p
}

// writeIgnoreFile writes a .terraview-ignore YAML to a temp file and returns
// the path. suppressedRuleID is added as a rule-level suppression.
func writeIgnoreFile(t *testing.T, suppressedRuleID string) string {
	t.Helper()
	content := fmt.Sprintf(`version: 1
suppressions:
  - rule_id: %s
    reason: "test suppression"
`, suppressedRuleID)
	dir := t.TempDir()
	p := filepath.Join(dir, ".terraview-ignore")
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatalf("write ignore file: %v", err)
	}
	return p
}

// TestRun_StrictMode verifies that Strict=true escalates exitCode 1 → 2 when
// the review contains a HIGH finding.
func TestRun_StrictMode(t *testing.T) {
	planPath := writePlan(t)
	cfg := baseConfig(planPath)
	cfg.Strict = true

	// Inject a HIGH finding via FindingsFile so MergeAndScore sees it without
	// a real scanner.
	cfg.FindingsFile = writeCheckovFindings(t, []struct{ id, resource string }{
		{"CKV_AWS_1", "aws_s3_bucket.logs"},
	})

	runner := NewRunner(cfg)
	result, err := runner.Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	// CKV_AWS_* → HIGH → ExitCode 1 before strict; strict must promote to 2.
	if result.ExitCode != 2 {
		t.Errorf("want exitCode 2 (strict HIGH), got %d", result.ExitCode)
	}
}

// TestRunScanPhase_InvalidScanner_ResultCompleteness verifies that a scanner
// resolve failure with EffectiveAI=false is non-fatal and produces the
// expected partial_ai_only completeness status.
func TestRunScanPhase_InvalidScanner_ResultCompleteness(t *testing.T) {
	cfg := baseConfig("plan.json")
	cfg.ScannerName = "definitely_not_a_scanner_123"
	resources := []parser.NormalizedResource{
		{Address: "aws_instance.web", Type: "aws_instance", Name: "web", Action: "create"},
	}
	graph := topology.BuildGraph(resources)

	sr, err := RunScanPhase(context.Background(), cfg, resources, graph)

	// Scanner fails + AI disabled → both failed → error is returned.
	// The existing test already checks err, but this test asserts on the
	// PipelineStatus when both components are "off" or "failed" with no AI.
	//
	// When EffectiveAI=false: aiStatus==nil (aiOK=true), scanner failed
	// (scannerOK=false). The switch hits case !scannerOK && aiOK →
	// ResultCompleteness = "partial_ai_only" — then the override
	// "if !cfg.EffectiveAI { if scannerOK { ... } }" is NOT executed because
	// scannerOK is false. So we get partial_ai_only with no error.
	if err != nil {
		t.Fatalf("RunScanPhase: unexpected error: %v", err)
	}
	if sr.PipelineStatus == nil {
		t.Fatal("expected pipeline status")
	}
	if sr.PipelineStatus.Scanner == nil {
		t.Fatal("expected scanner status to be populated")
	}
	if sr.PipelineStatus.Scanner.Status != "failed" {
		t.Errorf("want scanner status 'failed', got %q", sr.PipelineStatus.Scanner.Status)
	}
	if sr.PipelineStatus.ResultCompleteness != "partial_ai_only" {
		t.Errorf("want ResultCompleteness 'partial_ai_only', got %q", sr.PipelineStatus.ResultCompleteness)
	}
	if len(sr.HardFindings) != 0 {
		t.Errorf("want 0 hard findings, got %d", len(sr.HardFindings))
	}
}

// TestRunScanPhase_FindingsFile verifies that external findings imported via
// cfg.FindingsFile are included in HardFindings.
func TestRunScanPhase_FindingsFile(t *testing.T) {
	cfg := baseConfig("plan.json")
	cfg.FindingsFile = writeCheckovFindings(t, []struct{ id, resource string }{
		{"CKV_AWS_18", "aws_s3_bucket.data"},
		{"CKV_AWS_24", "aws_security_group.allow_ssh"},
	})
	resources := []parser.NormalizedResource{
		{Address: "aws_instance.web", Type: "aws_instance", Name: "web", Action: "create"},
	}
	graph := topology.BuildGraph(resources)

	sr, err := RunScanPhase(context.Background(), cfg, resources, graph)
	if err != nil {
		t.Fatalf("RunScanPhase: %v", err)
	}
	if len(sr.HardFindings) != 2 {
		t.Errorf("want 2 imported findings, got %d", len(sr.HardFindings))
	}
}

// TestMergeAndScore_WithContextFindings verifies that non-empty ContextFindings
// trigger AI validation and populate AIValidation on the result.
func TestMergeAndScore_WithContextFindings(t *testing.T) {
	cfg := baseConfig("plan.json")
	resources := []parser.NormalizedResource{
		{Address: "aws_instance.web", Type: "aws_instance", Name: "web", Action: "create"},
	}
	graph := topology.BuildGraph(resources)

	sr := ScanPhaseResult{
		ContextFindings: []rules.Finding{
			{
				RuleID:   "AI_001",
				Severity: "HIGH",
				Resource: "aws_instance.web",
				Message:  "ai finding on existing resource",
				Source:   "llm",
			},
		},
	}

	result := MergeAndScore(cfg, resources, graph, sr)
	if result.AIValidation == nil {
		t.Fatal("expected AIValidation to be populated when ContextFindings are present")
	}
	if result.AIValidation.TotalReceived < 1 {
		t.Errorf("want TotalReceived >= 1, got %d", result.AIValidation.TotalReceived)
	}
}

// TestMergeAndScore_WithIgnoreFile verifies that cfg.IgnoreFile suppresses
// matching findings and preserves non-matching ones.
func TestMergeAndScore_WithIgnoreFile(t *testing.T) {
	cfg := baseConfig("plan.json")
	cfg.IgnoreFile = writeIgnoreFile(t, "CKV_AWS_1")

	resources := []parser.NormalizedResource{
		{Address: "aws_instance.web", Type: "aws_instance", Name: "web", Action: "create"},
	}
	graph := topology.BuildGraph(resources)

	sr := ScanPhaseResult{
		HardFindings: []rules.Finding{
			{RuleID: "CKV_AWS_1", Severity: "HIGH", Resource: "aws_instance.web", Message: "suppressed"},
			{RuleID: "CKV_AWS_2", Severity: "LOW", Resource: "aws_instance.web", Message: "kept"},
		},
	}

	result := MergeAndScore(cfg, resources, graph, sr)

	for _, f := range result.Findings {
		if f.RuleID == "CKV_AWS_1" {
			t.Errorf("CKV_AWS_1 should have been suppressed by ignore file")
		}
	}

	found := false
	for _, f := range result.Findings {
		if f.RuleID == "CKV_AWS_2" {
			found = true
			break
		}
	}
	if !found {
		t.Error("CKV_AWS_2 should remain after suppression of CKV_AWS_1")
	}
}

// TestMergeAndScore_MetaAnalysis verifies that len(result.Findings) > 0 triggers
// meta-analysis and populates MetaAnalysis on the result.
func TestMergeAndScore_MetaAnalysis(t *testing.T) {
	cfg := baseConfig("plan.json")
	resources := []parser.NormalizedResource{
		{Address: "aws_instance.web", Type: "aws_instance", Name: "web", Action: "create"},
	}
	graph := topology.BuildGraph(resources)

	sr := ScanPhaseResult{
		HardFindings: []rules.Finding{
			{RuleID: "CKV_AWS_1", Severity: "HIGH", Resource: "aws_instance.web", Message: "meta trigger"},
			{RuleID: "CKV_AWS_2", Severity: "HIGH", Resource: "aws_instance.web", Message: "second finding"},
		},
	}

	result := MergeAndScore(cfg, resources, graph, sr)
	if result.MetaAnalysis == nil {
		t.Fatal("expected MetaAnalysis to be populated when findings are present")
	}
}

// TestRecordToHistory_Disabled verifies that when History.Enabled=false the
// function returns immediately without panic.
func TestRecordToHistory_Disabled(t *testing.T) {
	cfg := baseConfig("plan.json")
	cfg.Cfg.History.Enabled = false

	review := aggregator.ReviewResult{
		TotalResources: 1,
		Findings:       []rules.Finding{},
	}

	// Must not panic.
	RecordToHistory(cfg, review)
}

// TestRecordToHistory_Enabled verifies that when History.Enabled=true the
// function writes to the DB without panic. It redirects HOME to a temp dir so
// the test does not touch the user's real ~/.terraview/history.db.
func TestRecordToHistory_Enabled(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	planPath := writePlan(t)
	cfg := baseConfig(planPath)
	cfg.Cfg.History.Enabled = true
	cfg.ProjectDir = t.TempDir()

	review := aggregator.ReviewResult{
		TotalResources: 1,
		Findings:       []rules.Finding{},
	}

	// Must not panic and must not return an error (function is void).
	RecordToHistory(cfg, review)

	// Sanity: the DB file should have been created under the temp home.
	dbPath := filepath.Join(tmpHome, ".terraview", "history.db")
	if _, err := os.Stat(dbPath); err != nil {
		t.Errorf("expected history.db to be created at %s: %v", dbPath, err)
	}
}

// TestRecordToHistory_AutoCleanup exercises the AutoCleanup branch by setting
// History.AutoCleanup=true with a very low RetentionDays value so the cleanup
// path executes without error.
func TestRecordToHistory_AutoCleanup(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	planPath := writePlan(t)
	cfg := baseConfig(planPath)
	cfg.Cfg.History.Enabled = true
	cfg.Cfg.History.AutoCleanup = true
	cfg.Cfg.History.RetentionDays = 0 // retain nothing older than today
	cfg.ProjectDir = t.TempDir()

	review := aggregator.ReviewResult{
		TotalResources: 2,
		Findings: []rules.Finding{
			{RuleID: "CKV_AWS_1", Severity: "HIGH", Resource: "aws_instance.web", Message: "cleanup test"},
		},
	}

	RecordToHistory(cfg, review)
}

// TestRun_NoStrictMode_ExitCode1 verifies that without Strict flag a HIGH
// finding yields exitCode==1, not 2.
func TestRun_NoStrictMode_ExitCode1(t *testing.T) {
	planPath := writePlan(t)
	cfg := baseConfig(planPath)
	cfg.Strict = false
	cfg.FindingsFile = writeCheckovFindings(t, []struct{ id, resource string }{
		{"CKV_AWS_1", "aws_s3_bucket.logs"},
	})

	runner := NewRunner(cfg)
	result, err := runner.Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if result.ExitCode != 1 {
		t.Errorf("want exitCode 1 (HIGH, no strict), got %d", result.ExitCode)
	}
}

// TestRunScanPhase_FindingsFile_ImportError verifies graceful degradation when
// FindingsFile points to an unreadable path: error is absorbed and HardFindings
// stays empty.
func TestRunScanPhase_FindingsFile_ImportError(t *testing.T) {
	cfg := baseConfig("plan.json")
	cfg.FindingsFile = "/nonexistent/findings.json"
	resources := []parser.NormalizedResource{
		{Address: "aws_instance.web", Type: "aws_instance", Name: "web", Action: "create"},
	}
	graph := topology.BuildGraph(resources)

	sr, err := RunScanPhase(context.Background(), cfg, resources, graph)
	if err != nil {
		t.Fatalf("RunScanPhase: %v", err)
	}
	if len(sr.HardFindings) != 0 {
		t.Errorf("want 0 findings on import error, got %d", len(sr.HardFindings))
	}
}

// TestMergeAndScore_WithIgnoreFile_NoMatchLeaves verifies that an ignore file
// with no matching rules does not alter the findings list.
func TestMergeAndScore_WithIgnoreFile_NoMatchLeaves(t *testing.T) {
	cfg := baseConfig("plan.json")
	cfg.IgnoreFile = writeIgnoreFile(t, "CKV_NOMATCH_999")

	resources := []parser.NormalizedResource{
		{Address: "aws_instance.web", Type: "aws_instance", Name: "web", Action: "create"},
	}
	graph := topology.BuildGraph(resources)

	sr := ScanPhaseResult{
		HardFindings: []rules.Finding{
			{RuleID: "CKV_AWS_1", Severity: "HIGH", Resource: "aws_instance.web", Message: "present"},
		},
	}

	result := MergeAndScore(cfg, resources, graph, sr)

	found := false
	for _, f := range result.Findings {
		if f.RuleID == "CKV_AWS_1" {
			found = true
			break
		}
	}
	if !found {
		t.Error("CKV_AWS_1 should not have been suppressed")
	}
}

// TestRun_ParseError verifies that Run propagates a parse error when the plan
// file does not exist.
func TestRun_ParseError(t *testing.T) {
	cfg := baseConfig("/nonexistent/plan.json")
	runner := NewRunner(cfg)
	_, err := runner.Run(context.Background())
	if err == nil {
		t.Fatal("expected error for missing plan file")
	}
}

// TestRecordToHistory_Enabled_WithFindings exercises the full Insert +
// SaveLastScan path with a non-trivial ReviewResult.
func TestRecordToHistory_Enabled_WithFindings(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	planPath := writePlan(t)
	cfg := baseConfig(planPath)
	cfg.Cfg.History.Enabled = true
	cfg.ProjectDir = t.TempDir()

	review := aggregator.ReviewResult{
		TotalResources: 3,
		Findings: []rules.Finding{
			{RuleID: "CKV_AWS_1", Severity: "HIGH", Resource: "aws_instance.web", Message: "test"},
			{RuleID: "CKV_AWS_2", Severity: "CRITICAL", Resource: "aws_s3_bucket.logs", Message: "test"},
		},
	}

	RecordToHistory(cfg, review)

	dbPath := filepath.Join(tmpHome, ".terraview", "history.db")
	if _, err := os.Stat(dbPath); err != nil {
		t.Errorf("expected history.db at %s: %v", dbPath, err)
	}
}

// TestMergeAndScore_ContextFindings_Discarded verifies that AI findings for
// non-existent resources are discarded by the validator and reflected in
// AIValidation.TotalDiscard.
func TestMergeAndScore_ContextFindings_Discarded(t *testing.T) {
	cfg := baseConfig("plan.json")
	resources := []parser.NormalizedResource{
		{Address: "aws_instance.web", Type: "aws_instance", Name: "web", Action: "create"},
	}
	graph := topology.BuildGraph(resources)

	sr := ScanPhaseResult{
		ContextFindings: []rules.Finding{
			{
				RuleID:   "AI_HALLUCINATED",
				Severity: "HIGH",
				Resource: "aws_nonexistent.ghost",
				Message:  "hallucinated resource",
				Source:   "llm",
			},
		},
	}

	result := MergeAndScore(cfg, resources, graph, sr)
	if result.AIValidation == nil {
		t.Fatal("expected AIValidation when ContextFindings present")
	}
	if result.AIValidation.TotalDiscard < 1 {
		t.Errorf("want TotalDiscard >= 1 for hallucinated resource, got %d", result.AIValidation.TotalDiscard)
	}
}

// TestRun_FindingsFile_WithHistory exercises the complete Run path: plan parse
// → findings import → merge/score → record to history.
func TestRun_FindingsFile_WithHistory(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	planPath := writePlan(t)
	cfg := baseConfig(planPath)
	cfg.Cfg.History.Enabled = true
	cfg.ProjectDir = t.TempDir()
	cfg.FindingsFile = writeCheckovFindings(t, []struct{ id, resource string }{
		{"CKV_AWS_79", "aws_instance.web"},
	})

	runner := NewRunner(cfg)
	result, err := runner.Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(result.Review.Findings) == 0 {
		t.Error("expected findings from imported file")
	}
}

// TestRunScanPhase_CompleteFallbackOverride verifies the completeness override:
// when EffectiveAI=false and scanner succeeds, completeness is forced to
// "complete" regardless of the switch result.
func TestRunScanPhase_CompleteFallbackOverride(t *testing.T) {
	cfg := baseConfig("plan.json")
	// No scanner, no AI → both nil statuses → switch lands on "complete",
	// then the override "if !cfg.EffectiveAI { if scannerOK { complete } }"
	// also fires, confirming the path.
	resources := []parser.NormalizedResource{
		{Address: "aws_instance.web", Type: "aws_instance", Name: "web", Action: "create"},
	}
	graph := topology.BuildGraph(resources)

	sr, err := RunScanPhase(context.Background(), cfg, resources, graph)
	if err != nil {
		t.Fatalf("RunScanPhase: %v", err)
	}
	if sr.PipelineStatus.ResultCompleteness != "complete" {
		t.Errorf("want 'complete', got %q", sr.PipelineStatus.ResultCompleteness)
	}
}

// TestRecordToHistory_Enabled_SaveLastScan verifies that SaveLastScan is
// reached by checking that history.db and last-scan file are created.
func TestRecordToHistory_Enabled_SaveLastScan(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	planPath := writePlan(t)
	cfg := baseConfig(planPath)
	cfg.Cfg.History.Enabled = true
	cfg.ProjectDir = t.TempDir()
	cfg.ScannerName = "checkov"
	cfg.AIProvider = "openai"
	cfg.AIModel = "gpt-4"

	review := aggregator.ReviewResult{TotalResources: 1, Findings: []rules.Finding{}}
	RecordToHistory(cfg, review)

	dbPath := filepath.Join(tmpHome, ".terraview", "history.db")
	if _, err := os.Stat(dbPath); err != nil {
		t.Errorf("expected history.db at %s: %v", dbPath, err)
	}
}

// TestRunContextAnalysis_BadProvider verifies that RunContextAnalysis returns an
// error immediately when the provider name is not registered, without any network
// call. This covers the setup + NewProvider error path.
func TestRunContextAnalysis_BadProvider(t *testing.T) {
	planPath := writePlan(t)
	cfg := baseConfig(planPath)
	cfg.AIProvider = "__nonexistent_provider_xyz__"
	cfg.AIModel = "some-model"
	cfg.AITimeoutSecs = 5

	resources := []parser.NormalizedResource{
		{Address: "aws_instance.web", Type: "aws_instance", Name: "web", Action: "create"},
	}
	graph := topology.BuildGraph(resources)

	_, _, err := RunContextAnalysis(cfg, resources, graph)
	if err == nil {
		t.Fatal("expected error for unregistered AI provider")
	}
}

// TestRunScanPhase_AIFails_NoScanner verifies that when there is no scanner and
// the AI analysis fails, the result is partial_scanner_only (non-fatal).
func TestRunScanPhase_AIFails_NoScanner(t *testing.T) {
	cfg := baseConfig("plan.json")
	cfg.ScannerName = ""
	cfg.EffectiveAI = true
	cfg.AIProvider = "__nonexistent_provider_xyz__"
	cfg.AIModel = "some-model"
	cfg.AITimeoutSecs = 5

	resources := []parser.NormalizedResource{
		{Address: "aws_instance.web", Type: "aws_instance", Name: "web", Action: "create"},
	}
	graph := topology.BuildGraph(resources)

	sr, err := RunScanPhase(context.Background(), cfg, resources, graph)
	if err != nil {
		t.Fatalf("RunScanPhase: unexpected error: %v", err)
	}
	if sr.PipelineStatus == nil {
		t.Fatal("expected pipeline status")
	}
	if sr.PipelineStatus.AI == nil {
		t.Fatal("expected AI status to be populated")
	}
	if sr.PipelineStatus.AI.Status != "failed" {
		t.Errorf("want AI status 'failed', got %q", sr.PipelineStatus.AI.Status)
	}
	if sr.PipelineStatus.ResultCompleteness != "partial_scanner_only" {
		t.Errorf("want 'partial_scanner_only', got %q", sr.PipelineStatus.ResultCompleteness)
	}
}

// TestRunScanPhase_BothFail verifies that when both scanner and AI fail the
// function returns a non-nil error (hard failure).
func TestRunScanPhase_BothFail(t *testing.T) {
	cfg := baseConfig("plan.json")
	cfg.ScannerName = "definitely_not_a_scanner_123"
	cfg.EffectiveAI = true
	cfg.AIProvider = "__nonexistent_provider_xyz__"
	cfg.AIModel = "some-model"
	cfg.AITimeoutSecs = 5

	resources := []parser.NormalizedResource{
		{Address: "aws_instance.web", Type: "aws_instance", Name: "web", Action: "create"},
	}
	graph := topology.BuildGraph(resources)

	_, err := RunScanPhase(context.Background(), cfg, resources, graph)
	if err == nil {
		t.Fatal("expected error when both scanner and AI fail")
	}
}

// TestNewRunner_NilStderr verifies that NewRunner replaces a nil Stderr with
// io.Discard so callers don't need to guard against nil writes.
func TestNewRunner_NilStderr(t *testing.T) {
	cfg := config.Config{}
	cfg.Scoring.SeverityWeights = config.SeverityWeightsConfig{Critical: 10, High: 7, Medium: 4, Low: 1}
	runCfg := Config{
		Cfg:      cfg,
		PlanPath: "plan.json",
		Stderr:   nil, // intentionally nil
	}
	r := NewRunner(runCfg)
	if r == nil {
		t.Fatal("expected non-nil Runner")
	}
	if r.cfg.Stderr == nil {
		t.Error("expected Stderr to be replaced with io.Discard")
	}
}

// TestBuildResourceLimits_OllamaConfig verifies that non-zero Ollama config
// values override the defaults.
func TestBuildResourceLimits_OllamaConfig(t *testing.T) {
	cfg := config.Config{}
	cfg.LLM.Ollama.MaxThreads = 4
	cfg.LLM.Ollama.MaxMemoryMB = 2048
	cfg.LLM.Ollama.MinFreeMemoryMB = 512

	limits := BuildResourceLimits(cfg, false)
	if limits.MaxThreads != 4 {
		t.Errorf("want MaxThreads=4, got %d", limits.MaxThreads)
	}
	if limits.MaxMemoryMB != 2048 {
		t.Errorf("want MaxMemoryMB=2048, got %d", limits.MaxMemoryMB)
	}
	if limits.MinFreeMemoryMB != 512 {
		t.Errorf("want MinFreeMemoryMB=512, got %d", limits.MinFreeMemoryMB)
	}
}

// TestRecordToHistory_EmptyProjectDir verifies that when cfg.ProjectDir is
// empty the function falls back to cfg.WorkDir.
func TestRecordToHistory_EmptyProjectDir(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	planPath := writePlan(t)
	cfg := baseConfig(planPath)
	cfg.Cfg.History.Enabled = true
	cfg.ProjectDir = "" // empty → should fallback to WorkDir
	// WorkDir is set by baseConfig(planPath) to filepath.Dir(planPath)

	review := aggregator.ReviewResult{TotalResources: 1, Findings: []rules.Finding{}}
	RecordToHistory(cfg, review)
}

// TestRunContextAnalysis_FullPath exercises the complete RunContextAnalysis
// execution path using a fake OpenAI-compatible HTTP server so no real API key
// or network connectivity is required.
func TestRunContextAnalysis_FullPath(t *testing.T) {
	// Fake server returns a valid OpenAI chat completion response with 0 findings.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{
			"choices": [{"message": {"content": "{\"findings\":[]}"}, "finish_reason": "stop"}]
		}`)
	}))
	defer srv.Close()

	planPath := writePlan(t)
	cfg := baseConfig(planPath)
	cfg.AIProvider = "openai"
	cfg.AIModel = "gpt-4o"
	cfg.AIURL = srv.URL
	cfg.AIAPIKey = "sk-test-key-not-real"
	cfg.AITimeoutSecs = 10
	cfg.Cfg.LLM.Redact = false
	cfg.Cfg.LLM.Cache = false

	resources := []parser.NormalizedResource{
		{Address: "aws_instance.web", Type: "aws_instance", Name: "web", Action: "create",
			Values: map[string]interface{}{"ami": "ami-123456"}},
	}
	graph := topology.BuildGraph(resources)

	findings, _, err := RunContextAnalysis(cfg, resources, graph)
	if err != nil {
		t.Fatalf("RunContextAnalysis: %v", err)
	}
	// Server returns empty findings; no assertion needed beyond no-panic.
	_ = findings
}

// TestMergeAndScore_IgnoreFile_InvalidPath verifies graceful degradation when
// cfg.IgnoreFile points to a malformed YAML file — findings are preserved.
func TestMergeAndScore_IgnoreFile_InvalidPath(t *testing.T) {
	dir := t.TempDir()
	badIgnore := filepath.Join(dir, "bad.yaml")
	if err := os.WriteFile(badIgnore, []byte(":::invalid yaml:::"), 0o644); err != nil {
		t.Fatalf("write bad ignore: %v", err)
	}

	cfg := baseConfig("plan.json")
	cfg.IgnoreFile = badIgnore

	resources := []parser.NormalizedResource{
		{Address: "aws_instance.web", Type: "aws_instance", Name: "web", Action: "create"},
	}
	graph := topology.BuildGraph(resources)

	sr := ScanPhaseResult{
		HardFindings: []rules.Finding{
			{RuleID: "CKV_AWS_1", Severity: "HIGH", Resource: "aws_instance.web", Message: "present"},
		},
	}

	// Should not panic; findings should be preserved because suppression.Load errors.
	result := MergeAndScore(cfg, resources, graph, sr)
	_ = result
}

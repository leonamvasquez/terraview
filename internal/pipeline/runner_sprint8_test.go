package pipeline

import (
	"context"
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

	_ "github.com/leonamvasquez/terraview/internal/ai/providers"
)

// fakeOpenAIServer returns a test server that responds with valid OpenAI-style
// JSON containing a configurable findings payload. Callers pass the raw JSON
// string for the "content" field.
func fakeOpenAIServer(t *testing.T, content string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		// Minimal OpenAI chat-completion envelope.
		io.WriteString(w, `{"choices":[{"message":{"content":`+content+`},"finish_reason":"stop"}]}`) //nolint:errcheck
	}))
}

// ---------------------------------------------------------------------------
// RunContextAnalysis — nil Stderr path (L489-491)
// ---------------------------------------------------------------------------

// TestRunContextAnalysis_NilStderr verifies that passing Stderr=nil does not
// panic (the function must default to io.Discard internally).
func TestRunContextAnalysis_NilStderr(t *testing.T) {
	srv := fakeOpenAIServer(t, `"{\"findings\":[]}"`)
	defer srv.Close()

	planPath := writePlan(t)
	cfg := baseConfig(planPath)
	cfg.AIProvider = "openai"
	cfg.AIModel = "gpt-4o"
	cfg.AIURL = srv.URL
	cfg.AIAPIKey = "sk-test"
	cfg.AITimeoutSecs = 10
	cfg.Stderr = nil // intentionally nil — must not panic

	resources := []parser.NormalizedResource{
		{Address: "aws_instance.web", Type: "aws_instance", Name: "web", Action: "create",
			Values: map[string]interface{}{"ami": "ami-123456"}},
	}
	graph := topology.BuildGraph(resources)

	_, _, err := RunContextAnalysis(cfg, resources, graph)
	if err != nil {
		t.Fatalf("RunContextAnalysis with nil Stderr: %v", err)
	}
}

// ---------------------------------------------------------------------------
// RunContextAnalysis — disk cache path (L603-628, L659-669)
// ---------------------------------------------------------------------------

// TestRunContextAnalysis_CacheWrite exercises the cache.Put path on a
// successful AI call (LLM.Cache=true). The cache entry is written but we do
// not attempt a second call because NewProvider always validates the endpoint,
// so a hit from a dead server cannot be tested here without provider-level
// stubbing (which would modify the product).
func TestRunContextAnalysis_CacheWrite(t *testing.T) {
	srv := fakeOpenAIServer(t, `"{\"findings\":[]}"`)
	defer srv.Close()

	planPath := writePlan(t)

	// Redirect HOME so the disk cache lands in a temp dir.
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	cfg := baseConfig(planPath)
	cfg.AIProvider = "openai"
	cfg.AIModel = "gpt-4o-mini"
	cfg.AIURL = srv.URL
	cfg.AIAPIKey = "sk-test"
	cfg.AITimeoutSecs = 10
	cfg.Cfg.LLM.Cache = true
	cfg.Cfg.LLM.CacheTTLHours = 24
	cfg.Cfg.LLM.Redact = false

	resources := []parser.NormalizedResource{
		{Address: "aws_s3_bucket.data", Type: "aws_s3_bucket", Name: "data", Action: "create"},
	}
	graph := topology.BuildGraph(resources)

	_, _, err := RunContextAnalysis(cfg, resources, graph)
	if err != nil {
		t.Fatalf("CacheWrite call: %v", err)
	}
}

// TestRunContextAnalysis_CachePlanReadError exercises the branch that logs
// "cache: failed to read plan" when os.ReadFile fails (plan path does not
// exist). RunContextAnalysis must still succeed without cache.
func TestRunContextAnalysis_CachePlanReadError(t *testing.T) {
	srv := fakeOpenAIServer(t, `"{\"findings\":[]}"`)
	defer srv.Close()

	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	cfg := baseConfig("/nonexistent/missing_plan.json") // plan does not exist
	cfg.AIProvider = "openai"
	cfg.AIModel = "gpt-4o-mini"
	cfg.AIURL = srv.URL
	cfg.AIAPIKey = "sk-test"
	cfg.AITimeoutSecs = 10
	cfg.Cfg.LLM.Cache = true // cache enabled → tries to ReadFile(PlanPath) → fails
	cfg.Cfg.LLM.Redact = false
	cfg.WorkDir = t.TempDir()

	resources := []parser.NormalizedResource{
		{Address: "aws_instance.web", Type: "aws_instance", Name: "web", Action: "create"},
	}
	graph := topology.BuildGraph(resources)

	_, _, err := RunContextAnalysis(cfg, resources, graph)
	if err != nil {
		t.Fatalf("CachePlanReadError: %v", err)
	}
}

// ---------------------------------------------------------------------------
// RunContextAnalysis — maxResources truncation (L518-520)
// ---------------------------------------------------------------------------

// TestRunContextAnalysis_MaxResources exercises the branch that caps the
// number of resources sent to the AI (effectiveResources < len(resources)).
func TestRunContextAnalysis_MaxResources(t *testing.T) {
	srv := fakeOpenAIServer(t, `"{\"findings\":[]}"`)
	defer srv.Close()

	planPath := writePlan(t)
	cfg := baseConfig(planPath)
	cfg.AIProvider = "openai"
	cfg.AIModel = "gpt-4o"
	cfg.AIURL = srv.URL
	cfg.AIAPIKey = "sk-test"
	cfg.AITimeoutSecs = 10
	cfg.AIMaxResources = 1 // cap at 1 to trigger the truncation branch

	resources := []parser.NormalizedResource{
		{Address: "aws_instance.web", Type: "aws_instance", Name: "web", Action: "create"},
		{Address: "aws_s3_bucket.logs", Type: "aws_s3_bucket", Name: "logs", Action: "create"},
		{Address: "aws_vpc.main", Type: "aws_vpc", Name: "main", Action: "create"},
	}
	graph := topology.BuildGraph(resources)

	_, _, err := RunContextAnalysis(cfg, resources, graph)
	if err != nil {
		t.Fatalf("RunContextAnalysis MaxResources: %v", err)
	}
}

// ---------------------------------------------------------------------------
// RunContextAnalysis — redact path (L574-593)
// ---------------------------------------------------------------------------

// TestRunContextAnalysis_Redact exercises the sensitive-data sanitization
// branch (cfg.Cfg.LLM.Redact=true, cfg.NoRedact=false).
func TestRunContextAnalysis_Redact(t *testing.T) {
	srv := fakeOpenAIServer(t, `"{\"findings\":[]}"`)
	defer srv.Close()

	planPath := writePlan(t)
	cfg := baseConfig(planPath)
	cfg.AIProvider = "openai"
	cfg.AIModel = "gpt-4o"
	cfg.AIURL = srv.URL
	cfg.AIAPIKey = "sk-test"
	cfg.AITimeoutSecs = 10
	cfg.Cfg.LLM.Redact = true
	cfg.NoRedact = false

	resources := []parser.NormalizedResource{
		{Address: "aws_instance.web", Type: "aws_instance", Name: "web", Action: "create",
			Values: map[string]interface{}{
				"password": "super-secret",
				"ami":      "ami-123456",
			}},
	}
	graph := topology.BuildGraph(resources)

	_, _, err := RunContextAnalysis(cfg, resources, graph)
	if err != nil {
		t.Fatalf("RunContextAnalysis Redact: %v", err)
	}
}

// ---------------------------------------------------------------------------
// RunContextAnalysis — verbose callback (L502 verbose path)
// ---------------------------------------------------------------------------

// TestRunContextAnalysis_Verbose exercises the verbose logging path to ensure
// the callback is invoked without panic.
func TestRunContextAnalysis_Verbose(t *testing.T) {
	srv := fakeOpenAIServer(t, `"{\"findings\":[]}"`)
	defer srv.Close()

	planPath := writePlan(t)
	cfg := baseConfig(planPath)
	cfg.AIProvider = "openai"
	cfg.AIModel = "gpt-4o"
	cfg.AIURL = srv.URL
	cfg.AIAPIKey = "sk-test"
	cfg.AITimeoutSecs = 10
	cfg.Verbose = func(format string, args ...any) {} // non-nil verbose

	resources := []parser.NormalizedResource{
		{Address: "aws_instance.web", Type: "aws_instance", Name: "web", Action: "create"},
	}
	graph := topology.BuildGraph(resources)

	_, _, err := RunContextAnalysis(cfg, resources, graph)
	if err != nil {
		t.Fatalf("RunContextAnalysis Verbose: %v", err)
	}
}

// ---------------------------------------------------------------------------
// RecordToHistory — nil Stderr path (L739-741)
// ---------------------------------------------------------------------------

// TestRecordToHistory_NilStderr verifies that Stderr=nil does not panic when
// history is enabled.
func TestRecordToHistory_NilStderr(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	planPath := writePlan(t)
	cfg := baseConfig(planPath)
	cfg.Cfg.History.Enabled = true
	cfg.ProjectDir = t.TempDir()
	cfg.Stderr = nil // intentionally nil

	review := aggregator.ReviewResult{TotalResources: 1, Findings: []rules.Finding{}}
	// Must not panic.
	RecordToHistory(cfg, review)
}

// ---------------------------------------------------------------------------
// RecordToHistory — NewStore error path (L748-751)
// ---------------------------------------------------------------------------

// TestRecordToHistory_StoreOpenError exercises the error branch triggered when
// the history DB directory cannot be created (path is a regular file, not a
// directory).
func TestRecordToHistory_StoreOpenError(t *testing.T) {
	tmpHome := t.TempDir()

	// Create a file where the .terraview directory should be so MkdirAll fails.
	blockerPath := filepath.Join(tmpHome, ".terraview")
	if err := os.WriteFile(blockerPath, []byte("blocker"), 0o644); err != nil {
		t.Fatalf("setup blocker: %v", err)
	}

	t.Setenv("HOME", tmpHome)

	planPath := writePlan(t)
	cfg := baseConfig(planPath)
	cfg.Cfg.History.Enabled = true
	cfg.ProjectDir = t.TempDir()
	cfg.Stderr = io.Discard

	review := aggregator.ReviewResult{TotalResources: 1, Findings: []rules.Finding{}}
	// Must not panic even though NewStore will fail.
	RecordToHistory(cfg, review)
}

// ---------------------------------------------------------------------------
// RecordToHistory — SaveLastScan error path (L785-787)
// ---------------------------------------------------------------------------

// TestRecordToHistory_SaveLastScanError exercises the SaveLastScan error path
// by making ~/.terraview/last-scan.json unwritable. The Insert must succeed
// first (so the DB is healthy) but the last-scan directory is blocked.
func TestRecordToHistory_SaveLastScanError(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	// Pre-create the .terraview directory so NewStore succeeds.
	tvDir := filepath.Join(tmpHome, ".terraview")
	if err := os.MkdirAll(tvDir, 0o755); err != nil {
		t.Fatalf("mkdir .terraview: %v", err)
	}

	// Block last-scan.json by placing a directory at its expected path.
	// history.SaveLastScan writes to ~/.terraview/last-scan.json — block it
	// by creating a directory with that name so os.WriteFile fails.
	lastScanPath := filepath.Join(tvDir, "last-scan.json")
	if err := os.Mkdir(lastScanPath, 0o755); err != nil {
		t.Fatalf("mkdir last-scan.json: %v", err)
	}

	planPath := writePlan(t)
	cfg := baseConfig(planPath)
	cfg.Cfg.History.Enabled = true
	cfg.ProjectDir = t.TempDir()
	cfg.Stderr = io.Discard

	review := aggregator.ReviewResult{TotalResources: 1, Findings: []rules.Finding{}}
	// Must not panic; SaveLastScan error must be silently absorbed.
	RecordToHistory(cfg, review)
}

// ---------------------------------------------------------------------------
// RecordToHistory — AutoCleanup verbose path (L794-798)
// ---------------------------------------------------------------------------

// TestRecordToHistory_AutoCleanup_Verbose verifies that AutoCleanup with a
// non-nil verbose callback exercises the "removed > 0" branch.
func TestRecordToHistory_AutoCleanup_Verbose(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	planPath := writePlan(t)
	cfg := baseConfig(planPath)
	cfg.Cfg.History.Enabled = true
	cfg.Cfg.History.AutoCleanup = true
	cfg.Cfg.History.RetentionDays = 0 // purge everything
	cfg.ProjectDir = t.TempDir()
	var verboseLogs []string
	cfg.Verbose = func(format string, args ...any) {
		verboseLogs = append(verboseLogs, format)
	}

	review := aggregator.ReviewResult{
		TotalResources: 1,
		Findings: []rules.Finding{
			{RuleID: "CKV_AWS_1", Severity: "HIGH", Resource: "aws_instance.web", Message: "test"},
		},
	}
	RecordToHistory(cfg, review)
	// Verbose may or may not fire depending on whether records were cleaned;
	// the important assertion is that nothing panicked.
	_ = verboseLogs
}

// ---------------------------------------------------------------------------
// Run — RunScanPhase returns error (L131-133)
// ---------------------------------------------------------------------------

// TestRun_ScanPhaseError verifies that Run propagates a non-nil error from
// RunScanPhase (both scanner + AI failed path).
func TestRun_ScanPhaseError(t *testing.T) {
	planPath := writePlan(t)
	cfg := baseConfig(planPath)
	// Configure both scanner and AI to fail so RunScanPhase returns an error.
	cfg.ScannerName = "definitely_not_a_scanner_xyz"
	cfg.EffectiveAI = true
	cfg.AIProvider = "__nonexistent_provider_xyz__"
	cfg.AIModel = "some-model"
	cfg.AITimeoutSecs = 5

	runner := NewRunner(cfg)
	_, err := runner.Run(context.Background())
	if err == nil {
		t.Fatal("expected Run to propagate RunScanPhase error when both components fail")
	}
}

// ---------------------------------------------------------------------------
// RunScanPhase — scanner success with non-empty ScannerStats (L277-284)
// ---------------------------------------------------------------------------

// TestRunScanPhase_FindingsFile_WithStats verifies that an external findings
// import combined with a successful (no-op) scanner path populates
// PipelineStatus correctly including the scanner success branch.
//
// We abuse FindingsFile to get HardFindings without launching a real scanner,
// so scanner is intentionally absent (empty ScannerName). The test focuses on
// the AI success branch: EffectiveAI=true with a working fake server so
// aiStatus.Status="success" and contextFindings are populated.
func TestRunScanPhase_AISuccess_WithFindings(t *testing.T) {
	srv := fakeOpenAIServer(t, `"{\"findings\":[{\"rule_id\":\"AI_TEST\",\"severity\":\"HIGH\",\"resource\":\"aws_instance.web\",\"message\":\"ai finding\",\"source\":\"llm\"}]}"`)
	defer srv.Close()

	cfg := baseConfig("plan.json")
	cfg.EffectiveAI = true
	cfg.AIProvider = "openai"
	cfg.AIModel = "gpt-4o"
	cfg.AIURL = srv.URL
	cfg.AIAPIKey = "sk-test"
	cfg.AITimeoutSecs = 10
	cfg.Cfg.LLM.Redact = false
	cfg.Cfg.LLM.Cache = false

	resources := []parser.NormalizedResource{
		{Address: "aws_instance.web", Type: "aws_instance", Name: "web", Action: "create"},
	}
	graph := topology.BuildGraph(resources)

	sr, err := RunScanPhase(context.Background(), cfg, resources, graph)
	if err != nil {
		t.Fatalf("RunScanPhase: %v", err)
	}
	if sr.PipelineStatus == nil {
		t.Fatal("expected pipeline status")
	}
	if sr.PipelineStatus.AI == nil {
		t.Fatal("expected AI status to be set when EffectiveAI=true")
	}
	if sr.PipelineStatus.AI.Status != "success" {
		t.Errorf("want AI status 'success', got %q", sr.PipelineStatus.AI.Status)
	}
}

// ---------------------------------------------------------------------------
// MergeAndScore — nil Stderr path (L379-381)
// ---------------------------------------------------------------------------

// TestMergeAndScore_NilStderr verifies that Stderr=nil does not panic inside
// MergeAndScore when findings trigger the AI-validation discard warning.
func TestMergeAndScore_NilStderr(t *testing.T) {
	cfg := baseConfig("plan.json")
	cfg.Stderr = nil // must default to io.Discard internally

	resources := []parser.NormalizedResource{
		{Address: "aws_instance.web", Type: "aws_instance", Name: "web", Action: "create"},
	}
	graph := topology.BuildGraph(resources)

	sr := ScanPhaseResult{
		ContextFindings: []rules.Finding{
			{RuleID: "AI_GHOST", Severity: "HIGH", Resource: "aws_nonexistent.ghost",
				Message: "hallucinated", Source: "llm"},
		},
	}

	// Must not panic.
	result := MergeAndScore(cfg, resources, graph, sr)
	if result.AIValidation == nil {
		t.Fatal("expected AIValidation to be populated")
	}
}

// ---------------------------------------------------------------------------
// RunContextAnalysis — analyzeErr non-nil path (L655-657)
// ---------------------------------------------------------------------------

// TestRunContextAnalysis_AnalyzeError verifies that when the AI server returns
// a non-parseable response the error is propagated cleanly.
func TestRunContextAnalysis_AnalyzeError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		io.WriteString(w, `{"error":"server error"}`) //nolint:errcheck
	}))
	defer srv.Close()

	planPath := writePlan(t)
	cfg := baseConfig(planPath)
	cfg.AIProvider = "openai"
	cfg.AIModel = "gpt-4o"
	cfg.AIURL = srv.URL
	cfg.AIAPIKey = "sk-test"
	cfg.AITimeoutSecs = 5
	cfg.Cfg.LLM.Redact = false
	cfg.Cfg.LLM.Cache = false

	resources := []parser.NormalizedResource{
		{Address: "aws_instance.web", Type: "aws_instance", Name: "web", Action: "create"},
	}
	graph := topology.BuildGraph(resources)

	_, _, err := RunContextAnalysis(cfg, resources, graph)
	if err == nil {
		t.Fatal("expected error when AI server returns 500")
	}
}

// ---------------------------------------------------------------------------
// baseConfig with real plan path (helper used by several tests)
// ---------------------------------------------------------------------------

// realCfg returns a Config whose PlanPath is an actual file on disk so cache
// read (os.ReadFile) can succeed.
func realCfg(t *testing.T) Config {
	t.Helper()
	planPath := writePlan(t)
	cfg := config.Config{}
	cfg.Scoring.SeverityWeights = config.SeverityWeightsConfig{Critical: 10, High: 7, Medium: 4, Low: 1}
	return Config{
		Cfg:             cfg,
		PlanPath:        planPath,
		WorkDir:         filepath.Dir(planPath),
		EffectiveAI:     false,
		EffectiveFormat: "json",
		ShowSpinner:     false,
		Stderr:          io.Discard,
	}
}

// TestRunContextAnalysis_CacheWrite_RealPlan exercises the cache write path
// using realCfg (plan file exists on disk) so os.ReadFile succeeds and
// planHash is set — covering the DiskCache.Put branch.
func TestRunContextAnalysis_CacheWrite_RealPlan(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	srv := fakeOpenAIServer(t, `"{\"findings\":[]}"`)
	defer srv.Close()

	cfg := realCfg(t)
	cfg.AIProvider = "openai"
	cfg.AIModel = "gpt-4o"
	cfg.AIURL = srv.URL
	cfg.AIAPIKey = "sk-test"
	cfg.AITimeoutSecs = 10
	cfg.Cfg.LLM.Cache = true
	cfg.Cfg.LLM.CacheTTLHours = 24
	cfg.Cfg.LLM.Redact = false

	resources := []parser.NormalizedResource{
		{Address: "aws_vpc.main", Type: "aws_vpc", Name: "main", Action: "create"},
	}
	graph := topology.BuildGraph(resources)

	// Single call: exercises cache miss → Put path (L659-669).
	findings, _, err := RunContextAnalysis(cfg, resources, graph)
	if err != nil {
		t.Fatalf("CacheWrite_RealPlan: %v", err)
	}
	_ = findings
}

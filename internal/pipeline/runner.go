// Package pipeline implements TerraView's scan pipeline as a reusable Runner.
//
// The pipeline runs: Parse → [Scanner ‖ AI Context] → Merge → Score → Record.
// It is consumed by both the CLI (cmd/scan.go) and the MCP handler
// (internal/mcp/handler_scan.go) so both entrypoints share a single
// implementation and cannot drift.
package pipeline

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/leonamvasquez/terraview/internal/aggregator"
	"github.com/leonamvasquez/terraview/internal/ai"
	"github.com/leonamvasquez/terraview/internal/aicache"
	"github.com/leonamvasquez/terraview/internal/config"
	"github.com/leonamvasquez/terraview/internal/contextanalysis"
	"github.com/leonamvasquez/terraview/internal/history"
	"github.com/leonamvasquez/terraview/internal/importer"
	"github.com/leonamvasquez/terraview/internal/meta"
	"github.com/leonamvasquez/terraview/internal/normalizer"
	"github.com/leonamvasquez/terraview/internal/output"
	"github.com/leonamvasquez/terraview/internal/parser"
	"github.com/leonamvasquez/terraview/internal/rules"
	"github.com/leonamvasquez/terraview/internal/runtime"
	"github.com/leonamvasquez/terraview/internal/sanitizer"
	"github.com/leonamvasquez/terraview/internal/scanner"
	"github.com/leonamvasquez/terraview/internal/scoring"
	"github.com/leonamvasquez/terraview/internal/suppression"
	"github.com/leonamvasquez/terraview/internal/topology"
	"github.com/leonamvasquez/terraview/internal/util"
	"github.com/leonamvasquez/terraview/internal/validator"
)

// Config carries every resolved parameter the pipeline needs for one run.
// All CLI/MCP flags are flattened into this struct; the pipeline package
// itself never reads global state.
type Config struct {
	Cfg         config.Config
	ScannerName string
	PlanPath    string
	WorkDir     string

	// Feature toggles
	EffectiveAI     bool
	EffectiveFormat string
	Strict          bool
	StaticOnly      bool
	NoRedact        bool

	// Suppression / import
	IgnoreFile   string
	FindingsFile string

	// AI resolution
	AIProvider     string
	AIModel        string
	AIURL          string
	AITimeoutSecs  int
	AITemperature  float64
	AIAPIKey       string
	AIMaxResources int
	AINumCtx       int

	// Presentation
	Lang        string // "", "pt-BR"
	ShowSpinner bool   // false in MCP mode
	Stderr      io.Writer

	// History
	ProjectDir string

	// Logging hook; optional
	Verbose func(format string, args ...any)
}

// ScanPhaseResult is the output of the parallel Scanner ‖ AI phase before
// merge/score.
type ScanPhaseResult struct {
	HardFindings    []rules.Finding
	ScannerResult   *scanner.AggregatedResult
	ContextFindings []rules.Finding
	ContextSummary  string
	PipelineStatus  *aggregator.PipelineStatus
}

// RunResult is everything the caller needs to render output or act on the
// scan. Callers own rendering; the pipeline never writes reports.
type RunResult struct {
	Plan          *parser.TerraformPlan
	Resources     []parser.NormalizedResource
	Topology      *topology.Graph
	Review        aggregator.ReviewResult
	ScannerResult *scanner.AggregatedResult
	ExitCode      int
}

// Runner is the single entrypoint for the scan pipeline.
type Runner struct {
	cfg Config
}

// NewRunner builds a Runner. The Config is copied by value; mutating the
// original afterwards has no effect on the run.
func NewRunner(cfg Config) *Runner {
	if cfg.Stderr == nil {
		cfg.Stderr = io.Discard
	}
	if cfg.Verbose == nil {
		cfg.Verbose = func(string, ...any) {}
	}
	return &Runner{cfg: cfg}
}

// Run executes the full pipeline: parse → scan+AI → merge → record → exit code.
// Returns a RunResult even on non-fatal degradation (scanner or AI failed).
// Only hard failures (both phases failed, parse error) return a non-nil error.
func (r *Runner) Run(ctx context.Context) (*RunResult, error) {
	plan, resources, topoGraph, err := ParsePlan(r.cfg.PlanPath, r.cfg.Verbose)
	if err != nil {
		return nil, err
	}

	sr, err := RunScanPhase(ctx, r.cfg, resources, topoGraph)
	if err != nil {
		return nil, err
	}

	review := MergeAndScore(r.cfg, resources, topoGraph, sr)

	// History recording is fail-safe; errors are surfaced to stderr only.
	RecordToHistory(r.cfg, review)

	exitCode := review.ExitCode
	if r.cfg.Strict && exitCode == 1 {
		exitCode = 2
	}

	return &RunResult{
		Plan:          plan,
		Resources:     resources,
		Topology:      topoGraph,
		Review:        review,
		ScannerResult: sr.ScannerResult,
		ExitCode:      exitCode,
	}, nil
}

// ParsePlan reads and normalizes a Terraform plan JSON file.
func ParsePlan(planPath string, verbose func(string, ...any)) (*parser.TerraformPlan, []parser.NormalizedResource, *topology.Graph, error) {
	if verbose == nil {
		verbose = func(string, ...any) {}
	}
	verbose("Parsing plan: %s", planPath)
	p := parser.NewParser()
	plan, err := p.ParseFile(planPath)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("parse error: %w", err)
	}

	resources := p.NormalizeResources(plan)
	verbose("Found %d resource changes", len(resources))

	topoGraph := topology.BuildGraph(resources)
	return plan, resources, topoGraph, nil
}

// RunScanPhase runs the security scanner and AI context analysis in parallel.
// Both components degrade gracefully: partial failure produces a partial
// result with a warning on Config.Stderr.
func RunScanPhase(ctx context.Context, cfg Config, resources []parser.NormalizedResource, topoGraph *topology.Graph) (ScanPhaseResult, error) {
	_ = ctx // reserved for future cancellation plumbing into subprocess/AI calls.

	type scannerOutput struct {
		findings   []rules.Finding
		result     *scanner.AggregatedResult
		err        error
		durationMs int64
	}
	type contextOutput struct {
		findings   []rules.Finding
		summary    string
		err        error
		durationMs int64
	}

	stderr := cfg.Stderr
	if stderr == nil {
		stderr = io.Discard
	}
	verbose := cfg.Verbose
	if verbose == nil {
		verbose = func(string, ...any) {}
	}

	scannerCh := make(chan scannerOutput, 1)
	contextCh := make(chan contextOutput, 1)

	ps := &aggregator.PipelineStatus{}

	// Scanner goroutine
	if cfg.ScannerName != "" {
		go func() {
			start := time.Now()
			resolvedScanner, err := scanner.Resolve(cfg.ScannerName)
			if err != nil {
				scannerCh <- scannerOutput{err: err, durationMs: time.Since(start).Milliseconds()}
				return
			}

			scanCtx := scanner.ScanContext{
				PlanPath:  cfg.PlanPath,
				SourceDir: cfg.WorkDir,
				WorkDir:   cfg.WorkDir,
			}

			var stopSpinner func(bool)
			if cfg.ShowSpinner {
				sp := output.NewSpinner(fmt.Sprintf("Running scanner: %s...", resolvedScanner.Name()))
				sp.Start()
				stopSpinner = sp.Stop
			}
			rawResults := scanner.RunAll([]scanner.Scanner{resolvedScanner}, scanCtx)
			aggResult := scanner.Aggregate(rawResults)
			if stopSpinner != nil {
				stopSpinner(true)
			}

			scannerCh <- scannerOutput{
				findings:   aggResult.Findings,
				result:     &aggResult,
				durationMs: time.Since(start).Milliseconds(),
			}
		}()
	} else {
		scannerCh <- scannerOutput{}
		verbose("No scanner specified, skipping security scan")
	}

	// AI Context Analysis goroutine (runs in parallel with scanner)
	if cfg.EffectiveAI {
		go func() {
			start := time.Now()
			ctxFindings, ctxSummary, ctxErr := RunContextAnalysis(cfg, resources, topoGraph)
			contextCh <- contextOutput{
				findings:   ctxFindings,
				summary:    ctxSummary,
				err:        ctxErr,
				durationMs: time.Since(start).Milliseconds(),
			}
		}()
	} else {
		contextCh <- contextOutput{}
		verbose("AI contextual analysis disabled (no provider configured or --static)")
	}

	// Collect scanner results (graceful degradation, non-fatal)
	scanOut := <-scannerCh
	var scannerStatus *aggregator.ComponentStatus
	if cfg.ScannerName != "" {
		scannerStatus = &aggregator.ComponentStatus{
			Tool:       cfg.ScannerName,
			DurationMs: scanOut.durationMs,
		}
		if scanOut.err != nil {
			scannerStatus.Status = "failed"
			scannerStatus.Error = scanOut.err.Error()
			fmt.Fprintf(stderr, "%s ⚠ Scanner failed: %v. Showing AI results only (reduced confidence).\n",
				output.Prefix(), scanOut.err)
			verbose("Scanner failed (non-fatal): %v", scanOut.err)
		} else {
			scannerStatus.Status = "success"
			if scanOut.result != nil {
				if len(scanOut.result.ScannerStats) > 0 {
					scannerStatus.Version = scanOut.result.ScannerStats[0].Version
				}
				verbose("Scanner %s: %d findings (%d raw, %d after dedup)",
					cfg.ScannerName, len(scanOut.result.Findings), scanOut.result.TotalRaw, scanOut.result.TotalDeduped)
			}
		}
	}
	ps.Scanner = scannerStatus

	// Collect AI results (graceful degradation — errors are warnings)
	ctxOut := <-contextCh
	var contextFindings []rules.Finding
	var contextSummary string
	var aiStatus *aggregator.ComponentStatus
	if cfg.EffectiveAI {
		aiStatus = &aggregator.ComponentStatus{
			Provider:   cfg.AIProvider,
			Model:      cfg.AIModel,
			DurationMs: ctxOut.durationMs,
		}
		if ctxOut.err != nil {
			aiStatus.Status = "failed"
			aiStatus.Error = ctxOut.err.Error()
			fmt.Fprintf(stderr, "%s ⚠ AI analysis failed: %v. Showing scanner results only.\n",
				output.Prefix(), ctxOut.err)
			verbose("AI analysis failed (non-fatal): %v", ctxOut.err)
		} else {
			aiStatus.Status = "success"
			contextFindings = ctxOut.findings
			contextSummary = ctxOut.summary
			if len(contextFindings) > 0 {
				verbose("AI context analysis: %d findings", len(contextFindings))
			}
		}
	}
	ps.AI = aiStatus

	// Determine result completeness
	scannerOK := scannerStatus == nil || scannerStatus.Status == "success"
	aiOK := aiStatus == nil || aiStatus.Status == "success"

	switch {
	case scannerOK && aiOK:
		ps.ResultCompleteness = "complete"
	case scannerOK && !aiOK:
		ps.ResultCompleteness = "partial_scanner_only"
	case !scannerOK && aiOK:
		ps.ResultCompleteness = "partial_ai_only"
	default:
		scanErr := ""
		aiErr := ""
		if scannerStatus != nil {
			scanErr = scannerStatus.Error
		}
		if aiStatus != nil {
			aiErr = aiStatus.Error
		}
		return ScanPhaseResult{PipelineStatus: ps}, fmt.Errorf(
			"both scanner and AI failed.\n  Scanner: %s\n  AI: %s", scanErr, aiErr)
	}

	if cfg.ScannerName == "" {
		if aiOK || aiStatus == nil {
			ps.ResultCompleteness = "complete"
		}
	}
	if !cfg.EffectiveAI {
		if scannerOK {
			ps.ResultCompleteness = "complete"
		}
	}

	// Import external findings if specified
	hardFindings := scanOut.findings
	if cfg.FindingsFile != "" {
		externalFindings, err := importer.Import(cfg.FindingsFile)
		if err != nil {
			fmt.Fprintf(stderr, "%s ⚠ Failed to import findings from %s: %v\n", output.Prefix(), cfg.FindingsFile, err)
		} else {
			hardFindings = append(hardFindings, externalFindings...)
			verbose("Imported %d external findings from %s", len(externalFindings), cfg.FindingsFile)
		}
	}

	return ScanPhaseResult{
		HardFindings:    hardFindings,
		ScannerResult:   scanOut.result,
		ContextFindings: contextFindings,
		ContextSummary:  contextSummary,
		PipelineStatus:  ps,
	}, nil
}

// MergeAndScore deduplicates findings, validates AI hallucinations against
// topology, scores, and enriches the result with meta-analysis and
// suppression data.
func MergeAndScore(cfg Config, resources []parser.NormalizedResource, topoGraph *topology.Graph, sr ScanPhaseResult) aggregator.ReviewResult {
	stderr := cfg.Stderr
	if stderr == nil {
		stderr = io.Discard
	}
	verbose := cfg.Verbose
	if verbose == nil {
		verbose = func(string, ...any) {}
	}

	hardFindings := sr.HardFindings

	var aiValidationReport *aggregator.AIValidationReport
	validatedAIFindings := sr.ContextFindings
	if len(sr.ContextFindings) > 0 && topoGraph != nil {
		valid, discarded, report := validator.ValidateAIFindings(sr.ContextFindings, topoGraph)
		validatedAIFindings = valid

		aiReport := &aggregator.AIValidationReport{
			TotalReceived: report.TotalReceived,
			TotalValid:    report.TotalValid,
			TotalDiscard:  report.TotalDiscard,
		}
		if report.TotalDiscard > 0 {
			fmt.Fprintf(stderr, "%s ⚠ Discarded %d AI findings (hallucinated/invalid)\n",
				output.Prefix(), report.TotalDiscard)
			for _, d := range discarded {
				verbose("  ✗ [%s] %s: %s — %s", d.Reason, d.Finding.Resource, d.Finding.Message, d.Detail)
				aiReport.Discarded = append(aiReport.Discarded, aggregator.AIDiscardedFinding{
					Resource: d.Finding.Resource,
					Message:  d.Finding.Message,
					Reason:   string(d.Reason),
					Detail:   d.Detail,
				})
			}
		}
		aiValidationReport = aiReport

		verbose("AI validation: %d received, %d valid, %d discarded",
			report.TotalReceived, report.TotalValid, report.TotalDiscard)
	}

	if len(hardFindings) > 0 || len(validatedAIFindings) > 0 {
		dr := normalizer.Deduplicate(hardFindings, validatedAIFindings)
		hardFindings = dr.Findings
		verbose("Dedup: %s", dr.Summary)
		hardFindings = normalizer.ConsolidateIAMFindings(hardFindings)

		if aiValidationReport != nil {
			aiValidationReport.AIUniqueKept = dr.AIUniqueKept
			aiValidationReport.AIEnriched = dr.AIEnriched
		}
	}

	sw := cfg.Cfg.Scoring.SeverityWeights
	scorer := scoring.NewScorerWithWeights(sw.Critical, sw.High, sw.Medium, sw.Low)
	agg := aggregator.NewAggregator(scorer)
	result := agg.Aggregate(cfg.PlanPath, len(resources), hardFindings, nil, sr.ContextSummary, cfg.Strict)

	result.PipelineStatus = sr.PipelineStatus
	result.AIValidation = aiValidationReport

	if len(cfg.Cfg.Rules.DisabledRules) > 0 {
		result.Findings = FilterDisabledRules(result.Findings, cfg.Cfg.Rules.DisabledRules)
		verbose("Filtered %d disabled rules from findings", len(cfg.Cfg.Rules.DisabledRules))
	}

	if cfg.IgnoreFile != "" {
		if ignoreData, err := suppression.Load(cfg.IgnoreFile); err != nil {
			fmt.Fprintf(stderr, "%s ⚠ Could not load ignore file: %v\n", output.Prefix(), err)
		} else if len(ignoreData.Suppressions) > 0 {
			filtered, suppressedFindings := suppression.Apply(result.Findings, ignoreData)
			result.Findings = filtered
			if len(suppressedFindings) > 0 {
				fmt.Fprintf(stderr, "%s ⊘ Suppressed %d finding(s) via %s\n",
					output.Prefix(), len(suppressedFindings), cfg.IgnoreFile)
				for _, s := range suppressedFindings {
					reason := s.Reason
					if reason == "" {
						reason = "no reason provided"
					}
					verbose("  ⊘ [%s] %s: %s", s.Finding.RuleID, s.Finding.Resource, reason)
				}
			}
		}
	}

	if len(result.Findings) > 0 {
		metaAnalyzer := meta.NewAnalyzer()
		metaResult := metaAnalyzer.Analyze(result.Findings)
		result.MetaAnalysis = metaResult
		verbose("Meta-analysis: %s", metaResult.Summary)
	}

	return result
}

// cachedAnalysis is the serialized form of an AI context analysis result.
type cachedAnalysis struct {
	Findings []rules.Finding `json:"findings"`
	Summary  string          `json:"summary"`
}

// RunContextAnalysis executes AI-powered contextual analysis of the
// topology. Honors sanitization, Ollama lifecycle, and disk caching just like
// the original CLI implementation.
func RunContextAnalysis(cfg Config, resources []parser.NormalizedResource, graph *topology.Graph) ([]rules.Finding, string, error) {
	verbose := cfg.Verbose
	if verbose == nil {
		verbose = func(string, ...any) {}
	}
	stderr := cfg.Stderr
	if stderr == nil {
		stderr = io.Discard
	}

	providerName := cfg.AIProvider
	model := cfg.AIModel
	url := cfg.AIURL
	timeoutSecs := cfg.AITimeoutSecs
	temp := cfg.AITemperature
	apiKey := cfg.AIAPIKey
	maxResources := cfg.AIMaxResources
	numCtx := cfg.AINumCtx

	verbose("AI context analysis: %s (model: %s)", providerName, model)

	// Ollama lifecycle management
	limits := BuildResourceLimits(cfg.Cfg, false)
	var ollamaCleanup func()
	if providerName == "ollama" {
		lc := runtime.NewOllamaLifecycle(limits, url)
		bgCtx := context.Background()
		cleanup, err := lc.Ensure(bgCtx)
		if err != nil {
			return nil, "", fmt.Errorf("ollama unavailable: %w", err)
		}
		ollamaCleanup = cleanup
	}

	effectiveResources := len(resources)
	if maxResources > 0 && effectiveResources > maxResources {
		effectiveResources = maxResources
	}
	scaledTimeout := timeoutSecs + effectiveResources*3 + util.ContextTimeoutGraceSecs
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(scaledTimeout)*time.Second)
	defer cancel()
	verbose("AI timeout: %ds (base %d + %d resources × 3s + %ds grace)",
		scaledTimeout, timeoutSecs, effectiveResources, util.ContextTimeoutGraceSecs)

	var monitor *runtime.Monitor
	if providerName == "ollama" {
		monitor = runtime.NewMonitor(limits, cancel)
		monitor.Start(ctx)
	}

	providerCfg := ai.ProviderConfig{
		Model:        model,
		APIKey:       apiKey,
		BaseURL:      url,
		Temperature:  temp,
		TimeoutSecs:  timeoutSecs,
		MaxTokens:    util.DefaultAnalyzeMaxTokens,
		MaxRetries:   2,
		MaxResources: maxResources,
		NumCtx:       numCtx,
	}

	provider, err := ai.NewProvider(ctx, providerName, providerCfg)
	if err != nil {
		if monitor != nil {
			monitor.Stop()
		}
		if ollamaCleanup != nil {
			ollamaCleanup()
		}
		return nil, "", fmt.Errorf("ai provider %s: %w", providerName, err)
	}

	// Load the context-analysis prompt from prompts directory (if available)
	contextPrompt := ""
	execPath, exErr := os.Executable()
	if exErr == nil {
		promptDir := filepath.Join(filepath.Dir(execPath), "prompts")
		if _, statErr := os.Stat(promptDir); statErr != nil {
			promptDir = filepath.Join(".", "prompts")
		}
		pl := ai.NewPromptLoader(promptDir)
		if prompts, loadErr := pl.LoadForModel(providerName, model); loadErr == nil {
			contextPrompt = prompts.ContextAnalysis
		}
	}

	analyzer := contextanalysis.NewAnalyzer(provider, cfg.Lang, contextPrompt, maxResources)

	// Sensitive data sanitization
	shouldRedact := cfg.Cfg.LLM.Redact && !cfg.NoRedact
	if providerName == "ollama" && !cfg.Cfg.LLM.Redact {
		shouldRedact = false
	}

	if shouldRedact {
		sess := sanitizer.NewSession()
		for i := range resources {
			resources[i].Values = sess.SanitizeMap(resources[i].Values, resources[i].Address+".values")
			if resources[i].BeforeValues != nil {
				resources[i].BeforeValues = sess.SanitizeMap(resources[i].BeforeValues, resources[i].Address+".before_values")
			}
		}
		manifest := sess.Manifest()
		if manifest.Count() > 0 {
			fmt.Fprintf(stderr, "%s ⚠ Redacted %d sensitive values (%d unique) before sending to AI\n",
				output.Prefix(), manifest.Count(), manifest.UniqueCount())
			if cfg.Cfg.LLM.RedactLog {
				for plac, paths := range manifest.Entries {
					verbose("  %s → %v", plac, paths)
				}
			}
		}
	} else {
		verbose("Sensitive data redaction disabled")
	}

	// Build cache key based on SHA-256 hash of plan content
	var diskCache *aicache.DiskCache
	var planHash string
	if cfg.Cfg.LLM.Cache {
		rawPlan, readErr := os.ReadFile(cfg.PlanPath)
		if readErr != nil {
			verbose("cache: failed to read plan %s: %v", cfg.PlanPath, readErr)
		} else {
			planHash = aicache.PlanHash(rawPlan)
		}
		ttl := cfg.Cfg.LLM.CacheTTLHours
		if ttl <= 0 {
			ttl = 24
		}
		diskCache = aicache.NewDiskCache(aicache.DiskCacheDir(), providerName, model, cfg.ScannerName, ttl)

		if planHash != "" {
			if cached, ok := diskCache.Get(planHash); ok {
				verbose("cache hit for AI context analysis (%s/%s, hash=%s)", providerName, model, planHash[:12])
				if monitor != nil {
					monitor.Stop()
				}
				if ollamaCleanup != nil {
					ollamaCleanup()
				}
				var cachedResult cachedAnalysis
				if err := json.Unmarshal([]byte(cached), &cachedResult); err == nil {
					return cachedResult.Findings, cachedResult.Summary, nil
				}
			}
		}
	}

	displayModel := model
	if providerName != "" && !strings.Contains(model, "/") {
		displayModel = providerName + "/" + model
	}
	var stopSpinner func(bool)
	if cfg.ShowSpinner {
		sp := output.NewSpinner(fmt.Sprintf("AI context analysis (%s)...", displayModel))
		sp.Start()
		stopSpinner = sp.Stop
	}
	result, analyzeErr := analyzer.Analyze(ctx, resources, graph)
	if stopSpinner != nil {
		stopSpinner(analyzeErr == nil)
	}

	if monitor != nil {
		monitor.Stop()
	}
	if ollamaCleanup != nil {
		ollamaCleanup()
	}

	if analyzeErr != nil {
		return nil, "", analyzeErr
	}

	if diskCache != nil && planHash != "" {
		cached := cachedAnalysis{Findings: result.Findings, Summary: result.Summary}
		if data, err := json.Marshal(cached); err == nil {
			diskCache.Put(planHash, string(data))
			verbose("AI analysis result cached (%s/%s, hash=%s)", providerName, model, planHash[:12])
		}
	}

	if result.ExcludedNoOp > 0 {
		verbose("AI context: %d no-op/read resources excluded from analysis", result.ExcludedNoOp)
	}
	verbose("AI context (%s/%s): %d findings", providerName, model, len(result.Findings))
	return result.Findings, result.Summary, nil
}

// BuildResourceLimits constructs runtime limits from config and safe mode.
func BuildResourceLimits(cfg config.Config, safe bool) runtime.ResourceLimits {
	if safe {
		return runtime.SafeResourceLimits()
	}

	limits := runtime.DefaultResourceLimits()

	if cfg.LLM.Ollama.MaxThreads > 0 {
		limits.MaxThreads = cfg.LLM.Ollama.MaxThreads
	}
	if cfg.LLM.Ollama.MaxMemoryMB > 0 {
		limits.MaxMemoryMB = cfg.LLM.Ollama.MaxMemoryMB
	}
	if cfg.LLM.Ollama.MinFreeMemoryMB > 0 {
		limits.MinFreeMemoryMB = cfg.LLM.Ollama.MinFreeMemoryMB
	}

	return limits
}

// FilterDisabledRules removes findings whose RuleID matches any disabled rule pattern.
// Supports exact match and prefix match (e.g., "CKV_AWS" disables all Checkov AWS rules).
func FilterDisabledRules(findings []rules.Finding, disabled []string) []rules.Finding {
	if len(disabled) == 0 {
		return findings
	}

	disabledSet := make(map[string]bool, len(disabled))
	var prefixes []string
	for _, r := range disabled {
		upper := strings.ToUpper(strings.TrimSpace(r))
		disabledSet[upper] = true
		if !strings.Contains(upper, "_") || strings.HasSuffix(upper, "_") {
			prefixes = append(prefixes, upper)
		}
	}

	filtered := make([]rules.Finding, 0, len(findings))
	for _, f := range findings {
		id := strings.ToUpper(f.RuleID)
		if disabledSet[id] {
			continue
		}
		skip := false
		for _, prefix := range prefixes {
			if strings.HasPrefix(id, prefix) {
				skip = true
				break
			}
		}
		if !skip {
			filtered = append(filtered, f)
		}
	}
	return filtered
}

// RecordToHistory stores the scan result in the local history database.
// Fail-safe: any error is logged to Config.Stderr and silently ignored.
func RecordToHistory(cfg Config, result aggregator.ReviewResult) {
	if !cfg.Cfg.History.Enabled {
		return
	}
	stderr := cfg.Stderr
	if stderr == nil {
		stderr = io.Discard
	}
	verbose := cfg.Verbose
	if verbose == nil {
		verbose = func(string, ...any) {}
	}

	store, err := history.NewStore(history.DefaultDBPath())
	if err != nil {
		fmt.Fprintf(stderr, "[history] %v\n", err)
		return
	}
	defer store.Close()

	projectDir := cfg.ProjectDir
	if projectDir == "" {
		projectDir = cfg.WorkDir
	}

	rec := history.NewRecordFromResult(
		result,
		projectDir,
		cfg.ScannerName,
		cfg.AIProvider,
		cfg.AIModel,
		0,
		cfg.StaticOnly,
	)

	if _, err := store.Insert(rec); err != nil {
		fmt.Fprintf(stderr, "[history] %v\n", err)
		return
	}

	ls := history.LastScan{
		Timestamp:          rec.Timestamp,
		ProjectDir:         projectDir,
		PlanFile:           cfg.PlanPath,
		Scanner:            cfg.ScannerName,
		Provider:           cfg.AIProvider,
		Model:              cfg.AIModel,
		TotalResources:     result.TotalResources,
		Findings:           result.Findings,
		ScoreDecomposition: result.ScoreDecomposition,
	}
	if err := history.SaveLastScan(ls); err != nil {
		fmt.Fprintf(stderr, "[history] last-scan: %v\n", err)
	}

	if cfg.Cfg.History.AutoCleanup {
		cleanupCfg := history.CleanupConfig{
			RetentionDays: cfg.Cfg.History.RetentionDays,
			MaxSizeMB:     cfg.Cfg.History.MaxSizeMB,
		}
		if removed, err := store.Cleanup(cleanupCfg); err != nil {
			fmt.Fprintf(stderr, "[history] cleanup: %v\n", err)
		} else if removed > 0 {
			verbose("History cleanup: removed %d old records", removed)
		}
	}
}

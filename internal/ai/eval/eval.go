// Package eval provides a runner for evaluating AI provider output against
// golden-file criteria. Each eval case pairs a Terraform plan fixture with a
// golden.json that defines acceptance criteria (min findings, required sections,
// forbidden strings, etc.). This enables regression testing of AI analysis quality
// without coupling to any specific provider implementation.
package eval

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/leonamvasquez/terraview/internal/ai"
	"github.com/leonamvasquez/terraview/internal/contextanalysis"
	"github.com/leonamvasquez/terraview/internal/parser"
	"github.com/leonamvasquez/terraview/internal/rules"
	"github.com/leonamvasquez/terraview/internal/topology"
)

// GoldenCriteria defines the acceptance criteria for an eval case.
type GoldenCriteria struct {
	Name                string     `json:"name"`
	Description         string     `json:"description"`
	RequiredFindingsAny []string   `json:"required_findings_any"`
	MinFindings         int        `json:"min_findings"`
	ScoreRange          ScoreRange `json:"score_range"`
	RequiredSections    []string   `json:"required_sections"`
	ForbiddenStrings    []string   `json:"forbidden_strings"`
	MaxResponseTokens   int        `json:"max_response_tokens"`
}

// ScoreRange specifies inclusive bounds for an acceptable overall score.
type ScoreRange struct {
	Min float64 `json:"min"`
	Max float64 `json:"max"`
}

// EvalCase groups a fixture plan with its acceptance criteria.
type EvalCase struct {
	Name     string
	PlanPath string
	Golden   GoldenCriteria
}

// Result captures the outcome of a single eval run.
type Result struct {
	Case     EvalCase
	Pass     bool
	Failures []string
	Findings []rules.Finding
	Summary  string
}

// Runner discovers and executes eval cases against an AI provider.
type Runner struct {
	evalsDir string
	provider ai.Provider
}

// NewRunner creates a Runner that loads cases from evalsDir and uses provider
// for AI analysis. evalsDir must contain subdirectories, each with plan.json
// and golden.json.
func NewRunner(evalsDir string, provider ai.Provider) *Runner {
	return &Runner{evalsDir: evalsDir, provider: provider}
}

// LoadCases discovers eval cases by scanning evalsDir for subdirectories that
// contain both plan.json and golden.json.
func (r *Runner) LoadCases() ([]EvalCase, error) {
	entries, err := os.ReadDir(r.evalsDir)
	if err != nil {
		return nil, fmt.Errorf("eval: read dir %s: %w", r.evalsDir, err)
	}

	var cases []EvalCase
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}

		name := e.Name()
		planPath := filepath.Join(r.evalsDir, name, "plan.json")
		goldenPath := filepath.Join(r.evalsDir, name, "golden.json")

		if _, err := os.Stat(planPath); err != nil {
			continue
		}
		if _, err := os.Stat(goldenPath); err != nil {
			continue
		}

		gc, err := loadGolden(goldenPath)
		if err != nil {
			return nil, fmt.Errorf("eval: load golden %s: %w", goldenPath, err)
		}

		cases = append(cases, EvalCase{
			Name:     name,
			PlanPath: planPath,
			Golden:   gc,
		})
	}
	return cases, nil
}

// Run executes a single eval case and returns its Result.
func (r *Runner) Run(ctx context.Context, ec EvalCase) Result {
	res := Result{Case: ec}

	p := parser.NewParser()
	plan, err := p.ParseFile(ec.PlanPath)
	if err != nil {
		res.Failures = append(res.Failures, fmt.Sprintf("parse plan: %v", err))
		return res
	}

	resources := p.NormalizeResources(plan)
	graph := topology.BuildGraph(resources)

	analyzer := contextanalysis.NewAnalyzer(r.provider, "en", "", 0)
	result, err := analyzer.Analyze(ctx, resources, graph)
	if err != nil {
		// Non-fatal: record the failure but still evaluate whatever partial
		// data came back (result may be nil on hard failure).
		res.Failures = append(res.Failures, fmt.Sprintf("contextanalysis: %v", err))
		res.Pass = false
		return res
	}

	res.Findings = result.Findings
	res.Summary = result.Summary

	evaluate(ec.Golden, &res)
	return res
}

// RunAll loads all cases from evalsDir and runs each one sequentially.
func (r *Runner) RunAll(ctx context.Context) []Result {
	cases, err := r.LoadCases()
	if err != nil {
		return []Result{{
			Failures: []string{fmt.Sprintf("load cases: %v", err)},
		}}
	}

	results := make([]Result, 0, len(cases))
	for _, ec := range cases {
		results = append(results, r.Run(ctx, ec))
	}
	return results
}

// evaluate checks result against golden criteria and populates res.Failures and res.Pass.
func evaluate(gc GoldenCriteria, res *Result) {
	// min_findings: number of findings must meet the minimum threshold.
	if len(res.Findings) < gc.MinFindings {
		res.Failures = append(res.Failures,
			fmt.Sprintf("min_findings: got %d, want >= %d", len(res.Findings), gc.MinFindings))
	}

	// required_findings_any: at least one finding must match one of the substrings
	// against RuleID, Severity, or Source.
	if len(gc.RequiredFindingsAny) > 0 {
		matched := false
	outer:
		for _, f := range res.Findings {
			for _, sub := range gc.RequiredFindingsAny {
				if strings.Contains(f.RuleID, sub) ||
					strings.Contains(f.Severity, sub) ||
					strings.Contains(f.Source, sub) {
					matched = true
					break outer
				}
			}
		}
		if !matched {
			res.Failures = append(res.Failures,
				fmt.Sprintf("required_findings_any: no finding matched any of %v", gc.RequiredFindingsAny))
		}
	}

	// required_sections: at least one of the substrings must appear in Summary (case-insensitive).
	if len(gc.RequiredSections) > 0 {
		summaryLower := strings.ToLower(res.Summary)
		matched := false
		for _, sec := range gc.RequiredSections {
			if strings.Contains(summaryLower, strings.ToLower(sec)) {
				matched = true
				break
			}
		}
		if !matched {
			res.Failures = append(res.Failures,
				fmt.Sprintf("required_sections: summary contains none of %v", gc.RequiredSections))
		}
	}

	// forbidden_strings: none of the substrings may appear in Summary (case-insensitive).
	summaryLower := strings.ToLower(res.Summary)
	for _, fs := range gc.ForbiddenStrings {
		if strings.Contains(summaryLower, strings.ToLower(fs)) {
			res.Failures = append(res.Failures,
				fmt.Sprintf("forbidden_strings: summary contains %q", fs))
		}
	}

	// max_response_tokens: approximate token count via len/4 heuristic.
	if gc.MaxResponseTokens > 0 {
		approx := len(res.Summary) / 4
		if approx > gc.MaxResponseTokens {
			res.Failures = append(res.Failures,
				fmt.Sprintf("max_response_tokens: approx %d tokens exceeds limit %d", approx, gc.MaxResponseTokens))
		}
	}

	res.Pass = len(res.Failures) == 0
}

// loadGolden deserializes golden.json from the given path.
func loadGolden(path string) (GoldenCriteria, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return GoldenCriteria{}, fmt.Errorf("read: %w", err)
	}
	var gc GoldenCriteria
	if err := json.Unmarshal(data, &gc); err != nil {
		return GoldenCriteria{}, fmt.Errorf("unmarshal: %w", err)
	}
	return gc, nil
}

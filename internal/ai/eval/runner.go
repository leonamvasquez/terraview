package eval

import (
	"context"
	"fmt"
	"time"

	"github.com/leonamvasquez/terraview/internal/ai"
	"github.com/leonamvasquez/terraview/internal/contextanalysis"
	"github.com/leonamvasquez/terraview/internal/parser"
	"github.com/leonamvasquez/terraview/internal/topology"
)

// Report captures the outcome of running one Case.
type Report struct {
	Case     string
	Passed   bool
	Failures []string
	Findings int
	Duration time.Duration
	// Model and Provider are populated from the AI response so reports can
	// annotate which backend produced the run.
	Model    string
	Provider string
}

// Runner wires the production pipeline (parser → topology → analyzer) to
// the comparison layer. It never mutates production packages — it only
// consumes their exported APIs.
type Runner struct {
	Provider     ai.Provider
	Lang         string // "en" or "pt-BR"
	MaxResources int    // 0 = analyzer default
}

// NewRunner builds a Runner. The provider must already be validated by the
// caller; the runner makes no attempt to probe connectivity.
func NewRunner(p ai.Provider, lang string, maxResources int) *Runner {
	return &Runner{Provider: p, Lang: lang, MaxResources: maxResources}
}

// Run executes a single Case and returns a Report. Errors from the
// parser/analyzer layer are surfaced directly; Compare failures are
// reported via Report.Failures with Passed=false.
func (r *Runner) Run(ctx context.Context, c Case) (*Report, error) {
	start := time.Now()

	p := parser.NewParser()
	plan, err := p.ParseFile(c.PlanPath)
	if err != nil {
		return nil, fmt.Errorf("case %q: parse plan: %w", c.Name, err)
	}
	resources := p.NormalizeResources(plan)
	graph := topology.BuildGraph(resources)

	analyzer := contextanalysis.NewAnalyzer(r.Provider, r.Lang, "", r.MaxResources)
	result, err := analyzer.Analyze(ctx, resources, graph)
	if err != nil {
		return nil, fmt.Errorf("case %q: analyze: %w", c.Name, err)
	}

	failures := Compare(result.Findings, result.Summary, c.Golden)
	return &Report{
		Case:     c.Name,
		Passed:   len(failures) == 0,
		Failures: failures,
		Findings: len(result.Findings),
		Duration: time.Since(start),
		Model:    result.Model,
		Provider: result.Provider,
	}, nil
}

// RunAll runs every case sequentially. A failing case does not halt the
// run — callers use the returned reports to compute pass/fail ratios.
// The first error returned is a hard runtime error (e.g. plan parse
// failure); comparison failures are captured in the Report itself.
func (r *Runner) RunAll(ctx context.Context, cases []Case) ([]Report, error) {
	reports := make([]Report, 0, len(cases))
	for _, c := range cases {
		if ctx.Err() != nil {
			return reports, ctx.Err()
		}
		rep, err := r.Run(ctx, c)
		if err != nil {
			return reports, err
		}
		reports = append(reports, *rep)
	}
	return reports, nil
}

// Summary renders a terse overview of a batch run — one line per case
// plus a footer with pass/fail counts. Intended for -v test output and
// CI logs.
func Summary(reports []Report) string {
	var out string
	passed := 0
	for _, r := range reports {
		status := "PASS"
		if !r.Passed {
			status = "FAIL"
		} else {
			passed++
		}
		out += fmt.Sprintf("[%s] %s — %d finding(s) in %s\n", status, r.Case, r.Findings, r.Duration.Round(time.Millisecond))
		for _, f := range r.Failures {
			out += "       • " + f + "\n"
		}
	}
	out += fmt.Sprintf("\n%d/%d cases passed\n", passed, len(reports))
	return out
}

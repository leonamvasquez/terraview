// Package eval runs golden-file evaluations against an ai.Provider.
//
// Prompt tuning is otherwise blind: any edit to prompts/*.md is judged by
// eyeballing the next scan. The eval framework replaces that with a
// reproducible loop — each Case ships a sanitized Terraform plan plus a
// Golden spec describing the findings the provider must produce. Because
// LLM output is non-deterministic, assertions are structural (required
// topics, minimum severity counts, resource addresses, summary substrings)
// rather than byte-exact.
//
// A typical run looks like:
//
//	cases, _ := eval.LoadCases("testdata/evals")
//	runner := eval.NewRunner(provider, "en", 0)
//	reports, _ := runner.RunAll(ctx, cases)
//
// The exported Runner makes no changes to the production analyzer — it
// simply wires parser → topology → contextanalysis.Analyzer using the
// provider passed in, then feeds the findings to Compare.
package eval

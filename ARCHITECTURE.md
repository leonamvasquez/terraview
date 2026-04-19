# TerraView — Architecture

> Decision record and package map for contributors. Not a replacement for
> the README — this file focuses on *why* things are the way they are.

---

## Pipeline Contract

TerraView's core loop is **scan → diagram → explain → fix**. Every command
and MCP tool is a thin slice over this pipeline:

```
parsePlan()         → parser.ParseFile → NormalizedResource[] + topology.Graph
                                              │
               ┌──────────────────────────────┤
               ▼                              ▼
runScanners()  scanner subprocess         contextanalysis.Analyzer   (parallel)
               └──────────────────────────────┘
                              │
                    mergeAndScore()
                    normalizer → resolver → scorer → aggregator.ReviewResult
                              │
                    renderOutput()
                    pretty / json / sarif / html
```

### pipeline.Runner

`internal/pipeline/runner.go` owns the above sequence as a reusable struct.
Both `cmd/scan.go` (CLI) and `internal/mcp/handler_scan.go` (MCP) call it —
no duplication, no drift. If you need to change scan behavior, change it in
`Runner`, not in cmd/.

### Exit codes (CLI only)

| Code | Meaning |
|------|---------|
| 0 | No findings (or only LOW/MEDIUM) |
| 1 | HIGH findings present |
| 2 | CRITICAL findings present |

---

## Package Map

| Package | Responsibility |
|---------|---------------|
| `cmd/` | Cobra commands: scan, diagram, explain, fix, history, mcp, status, version |
| `internal/pipeline` | Reusable scan pipeline (parse → scan ‖ AI → merge → score → record) |
| `internal/parser` | Terraform plan JSON → `NormalizedResource[]` + `TerraformPlan` |
| `internal/topology` | Dependency graph from resource references |
| `internal/scanner` | Subprocess adapters: Checkov, tfsec, Terrascan |
| `internal/contextanalysis` | AI-based findings via `ai.Provider.Analyze` |
| `internal/ai` | `Provider` interface + factory (`NewProvider`) |
| `internal/ai/providers` | Concrete providers: Anthropic, OpenAI, Gemini, Gemini-CLI, Ollama |
| `internal/ai/eval` | Offline eval framework: golden files + `Runner` |
| `internal/aicache` | Deterministic SHA-256 cache for AI responses |
| `internal/aggregator` | Merge scanner + AI findings, deduplicate, build `ReviewResult` |
| `internal/normalizer` | Strip duplicates, canonical rule IDs |
| `internal/resolver` | Match findings to NormalizedResources |
| `internal/scoring` | Risk score (0–100) from severity distribution |
| `internal/rules` | `Finding` type + rule catalogue |
| `internal/fix` | `Suggester` (HCL generation), `ApplySession` (interactive apply), `PlanIndex` |
| `internal/diagram` | ASCII diagram generation (topo + flat modes) |
| `internal/explain` | Prompt builder for `explain` command |
| `internal/history` | SQLite scan log: store, list, trend, compare |
| `internal/mcp` | JSON-RPC server + 11 MCP tools (terraview_scan, explain, diagram, fix_suggest, …) |
| `internal/config` | `.terraview.yaml` loader |
| `internal/output` | Renderers: pretty, JSON, SARIF, HTML |
| `internal/blast` | Blast-radius analysis from topology graph |
| `internal/regression` | New-finding detection vs previous scan |
| `internal/suppression` | `.terraview-suppress.yaml` filter |
| `internal/terraformexec` | `terraform`/`tofu`/`terragrunt` executor abstraction |
| `internal/workspace` | Working directory validation |
| `internal/riskvec` | Risk vector encoding for scoring |
| `internal/importer` | Import block generation |
| `internal/bininstaller` | Managed download of scanner binaries |
| `internal/feature` | Feature flags |
| `internal/i18n` | Locale helpers (pt-BR) |
| `prompts/` | Markdown prompt templates for AI analysis (one per dimension) |

---

## ADR-001 — Extract pipeline.Runner from cmd/scan.go

**Context.** Before Sprint 1 (April 2026), the entire scan pipeline lived
inside `runScan()` in `cmd/scan.go`. When the MCP server needed to offer
`terraview_scan` as a tool, the only option was to duplicate that logic in
`internal/mcp/handler_scan.go`.

**Decision.** Extract `pipeline.Runner` with a `Run(ctx, opts) ReviewResult`
API. Both cmd/ and mcp/ call it. The runner owns plan parsing, parallel
scanner + AI execution, merge, score, and history recording.

**Consequences.**
- Single implementation; any change to scan behavior propagates to both CLI
  and MCP without touching cmd/.
- cmd/scan.go becomes a thin flag → options translation layer (~60 lines).
- Easier to unit-test the pipeline without Cobra.

---

## ADR-002 — External scanners instead of built-in rules

**Context.** TerraView could bundle its own security rules (a la Checkov
in pure Python or tfsec in Go). This would remove the installation
requirement.

**Decision.** Delegate static analysis to established scanners (Checkov,
tfsec, Terrascan) via subprocess. TerraView provides the orchestration,
deduplication, scoring, and AI enrichment layer.

**Trade-offs.**

| Pro | Con |
|-----|-----|
| Rules maintained by dedicated security teams | Requires scanner installed in PATH |
| Thousands of rules out of the box | Subprocess overhead (~2–5 s) |
| Scanner output formats are stable contracts | Version skew across environments |

**Mitigation.** `internal/bininstaller` manages binary downloads; `--scanner`
flag lets users pick or force a scanner. A built-in fallback (TODO-001) is
planned to handle the zero-scanner case.

---

## ADR-003 — MCP as primary integration interface

**Context.** AI-native editors (Cursor, Windsurf, VS Code + Copilot) and
agentic workflows need to call TerraView programmatically without shelling
out. Options: REST API, gRPC, or Model Context Protocol (MCP).

**Decision.** Implement MCP (JSON-RPC 2.0 over stdin/stdout) as the primary
machine interface. CLI flags remain the human interface.

**Reasoning.**
- MCP is natively understood by Claude, Cursor, and other LLM tools — no
  client library needed.
- stdin/stdout transport avoids port management and firewall rules.
- Same binary serves both human (CLI) and agent (MCP) clients.

**Consequences.**
- All new capabilities must be exposed as both a CLI flag and an MCP tool.
- Breaking changes to MCP tool schemas require a version bump in
  `mcpProtocolVersion` (`internal/mcp/server.go`).
- REST API is intentionally *not* implemented; if needed in the future,
  it should wrap the same `pipeline.Runner`, not duplicate logic.

package output

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"html/template"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/leonamvasquez/terraview/assets"
	"github.com/leonamvasquez/terraview/internal/aggregator"
	"github.com/leonamvasquez/terraview/internal/rules"
)

var urlRe = regexp.MustCompile(`https?://\S+`)

// linkifyText converts plain-text URLs into HTML anchor tags.
// It returns template.HTML so html/template does not double-escape the tags.
func linkifyText(s string) template.HTML {
	var buf strings.Builder
	last := 0
	for _, loc := range urlRe.FindAllStringIndex(s, -1) {
		buf.WriteString(template.HTMLEscapeString(s[last:loc[0]]))
		rawURL := s[loc[0]:loc[1]]
		trimmed := strings.TrimRight(rawURL, ".,;:)}")
		buf.WriteString(`<a href="`)
		buf.WriteString(template.HTMLEscapeString(trimmed))
		buf.WriteString(`" target="_blank" rel="noopener noreferrer">`)
		buf.WriteString(template.HTMLEscapeString(trimmed))
		buf.WriteString(`</a>`)
		if suffix := rawURL[len(trimmed):]; suffix != "" {
			buf.WriteString(template.HTMLEscapeString(suffix))
		}
		last = loc[1]
	}
	buf.WriteString(template.HTMLEscapeString(s[last:]))
	return template.HTML(buf.String())
}

// WriteHTML writes the review result as a self-contained HTML report.
func (w *Writer) WriteHTML(result aggregator.ReviewResult, path string) error {
	html, err := renderHTML(result)
	if err != nil {
		return fmt.Errorf("failed to render HTML: %w", err)
	}
	if err := os.WriteFile(path, []byte(html), 0644); err != nil {
		return fmt.Errorf("failed to write %s: %w", path, err)
	}
	return nil
}

// ---- template data types ----

type htmlReport struct {
	PlanFile       string
	GeneratedAt    string
	TotalResources int
	Scanner        string
	Safe           bool
	VerdictLabel   string
	Reasons        []string
	Confidence     string
	Summary         string
	SeverityRows    []htmlSevRow
	Scores          []htmlScoreRow
	Diagram         string
	ScannerFindings []htmlFinding
	AIFindings      []htmlFinding
	TotalFindings   int
	PipelineCards  []htmlPipelineCard
	ExitCode       int
	LogoDataURI    template.URL // base64 data URI for terraview-logo.png (URL type skips html/template URL-escaping)
}

type htmlSevRow struct {
	Label string
	Class string
	Count int
}

type htmlScoreRow struct {
	Label      string
	Value      float64
	Pct        float64 // 0–100 (kept for compat)
	Class      string  // score-high | score-med | score-low
	ColorClass string  // sc-good | sc-fair | sc-poor | sc-crit
	Rating     string  // Good | Fair | Poor | Critical
	Delay      int
}

type htmlFinding struct {
	RuleID      string
	SevLabel    string
	SevClass    string
	Resource    string
	Message     string
	Remediation string
	Category    string
	Source      string
}

type htmlPipelineCard struct {
	Title  string
	Value  string
	Detail string
	Class  string // success | failed | skipped
}

// ---- builder ----

func renderHTML(result aggregator.ReviewResult) (string, error) {
	data := buildHTMLData(result)
	tmpl, err := template.New("report").
		Funcs(template.FuncMap{"linkify": linkifyText}).
		Parse(htmlTempl)
	if err != nil {
		return "", err
	}
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", err
	}
	return buf.String(), nil
}

func buildHTMLData(r aggregator.ReviewResult) htmlReport {
	data := htmlReport{
		PlanFile:       r.PlanFile,
		GeneratedAt:    time.Now().UTC().Format("2006-01-02 15:04:05 UTC"),
		TotalResources: r.TotalResources,
		Safe:           r.Verdict.Safe,
		VerdictLabel:   r.Verdict.Label,
		Reasons:        r.Verdict.Reasons,
		Confidence:     r.Verdict.Confidence,
		Summary:        r.Summary,
		Diagram:        r.Diagram,
		TotalFindings:  len(r.Findings),
		ExitCode:       r.ExitCode,
		LogoDataURI:    template.URL("data:image/png;base64," + base64.StdEncoding.EncodeToString(assets.LogoPNG)),
	}

	if r.PipelineStatus != nil && r.PipelineStatus.Scanner != nil {
		data.Scanner = strings.ToUpper(r.PipelineStatus.Scanner.Tool)
	}

	sevDefs := []struct {
		key   string
		label string
		class string
	}{
		{rules.SeverityCritical, "CRITICAL", "critical"},
		{rules.SeverityHigh, "HIGH", "high"},
		{rules.SeverityMedium, "MEDIUM", "medium"},
		{rules.SeverityLow, "LOW", "low"},
		{rules.SeverityInfo, "INFO", "info"},
	}
	for _, s := range sevDefs {
		data.SeverityRows = append(data.SeverityRows, htmlSevRow{
			Label: s.label,
			Class: s.class,
			Count: r.SeverityCounts[s.key],
		})
	}

	mkScore := func(label string, v float64, delay int) htmlScoreRow {
		rating, cc := scoreRatingAndClass(v)
		return htmlScoreRow{Label: label, Value: v, Pct: v * 10, Class: scoreClass(v), ColorClass: cc, Rating: rating, Delay: delay}
	}
	data.Scores = []htmlScoreRow{
		mkScore("SECURITY", r.Score.SecurityScore, 0),
		mkScore("COMPLIANCE", r.Score.ComplianceScore, 1),
		mkScore("MAINTAINABILITY", r.Score.MaintainabilityScore, 2),
	}

	for _, f := range r.Findings {
		hf := htmlFinding{
			RuleID:      f.RuleID,
			SevLabel:    f.Severity,
			SevClass:    strings.ToLower(f.Severity),
			Resource:    f.Resource,
			Message:     f.Message,
			Remediation: f.Remediation,
			Category:    f.Category,
			Source:      sourceLabel(f.Source),
		}
		if strings.HasPrefix(f.Source, "scanner:") {
			data.ScannerFindings = append(data.ScannerFindings, hf)
		} else {
			data.AIFindings = append(data.AIFindings, hf)
		}
	}

	if r.PipelineStatus != nil {
		if s := r.PipelineStatus.Scanner; s != nil {
			detail := ""
			if s.Error != "" {
				detail = s.Error
			}
			data.PipelineCards = append(data.PipelineCards, htmlPipelineCard{
				Title:  "SCANNER",
				Value:  strings.ToUpper(s.Tool),
				Detail: detail,
				Class:  pipelineClass(s.Status),
			})
		}
		if a := r.PipelineStatus.AI; a != nil {
			label := a.Provider
			if a.Model != "" {
				label = a.Provider + " / " + a.Model
			}
			detail := ""
			if a.Error != "" {
				detail = a.Error
			}
			data.PipelineCards = append(data.PipelineCards, htmlPipelineCard{
				Title:  "AI ANALYSIS",
				Value:  label,
				Detail: detail,
				Class:  pipelineClass(a.Status),
			})
		}
		if r.PipelineStatus.ResultCompleteness != "" {
			data.PipelineCards = append(data.PipelineCards, htmlPipelineCard{
				Title: "COMPLETENESS",
				Value: strings.ToUpper(r.PipelineStatus.ResultCompleteness),
				Class: "success",
			})
		}
	}

	return data
}

func scoreClass(v float64) string {
	switch {
	case v >= 8.0:
		return "score-high"
	case v >= 6.0:
		return "score-med"
	default:
		return "score-low"
	}
}

func scoreRatingAndClass(v float64) (string, string) {
	switch {
	case v >= 8.0:
		return "Good", "sc-good"
	case v >= 6.0:
		return "Fair", "sc-fair"
	case v >= 4.0:
		return "Poor", "sc-poor"
	default:
		return "Critical", "sc-crit"
	}
}


func pipelineClass(status string) string {
	switch status {
	case "success":
		return "success"
	case "failed":
		return "failed"
	default:
		return "skipped"
	}
}

// ---- HTML template ----

const htmlTempl = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>TerraView — Scan Report</title>
<link rel="icon" type="image/png" href="{{.LogoDataURI}}">
<style>
/* ── Reset & base ─────────────────────────────────────────────────── */
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
html{font-size:14px}
body{font-family:Arial,Helvetica,sans-serif;font-size:13px;line-height:1.5;color:#222;background:#fff}
a{color:#1a5590}
a:hover{text-decoration:underline}
table{border-collapse:collapse;width:100%}
th,td{padding:6px 10px;border:1px solid #ccc;text-align:left;vertical-align:top}
thead th{background:#f0f0f0;font-size:11px;font-weight:bold;letter-spacing:.4px;text-transform:uppercase;color:#444}
h2{font-size:13px;font-weight:bold;margin:0}

/* ── Layout ───────────────────────────────────────────────────────── */
.wrap{max-width:1140px;margin:0 auto;padding:0 20px}
.page{padding:24px 0 48px;display:flex;flex-direction:column;gap:28px}

/* ── Header ───────────────────────────────────────────────────────── */
.hdr{background:#fff;border-bottom:3px solid #b01c00;padding:10px 0}
.hdr-inner{display:flex;align-items:center;justify-content:space-between;gap:16px;flex-wrap:wrap}
.brand{display:flex;align-items:center;gap:10px}
.brand img{height:42px;display:block}
.brand-text .brand-name{font-size:20px;font-weight:bold;color:#b01c00;letter-spacing:1px}
.brand-text .brand-sub{font-size:11px;color:#666;margin-top:1px}
.hdr-meta{font-size:11px;color:#555;text-align:right;line-height:1.7}
.hdr-meta span{display:block}

/* ── Verdict bar ──────────────────────────────────────────────────── */
.verdict{padding:8px 0;border-bottom:1px solid #ccc}
.verdict.safe  {background:#f5fdf0}
.verdict.unsafe{background:#fdf0f0}
.verdict-inner{display:flex;align-items:baseline;gap:12px;flex-wrap:wrap}
.verdict-label{font-size:14px;font-weight:bold}
.verdict.safe   .verdict-label{color:#1a6b1a}
.verdict.unsafe .verdict-label{color:#b01c00}
.verdict-conf{font-size:12px;color:#555}
.verdict-reasons{display:flex;flex-wrap:wrap;gap:6px;margin-left:auto}
.v-reason{font-size:11px;border:1px solid #bbb;padding:1px 8px;color:#333}

/* ── Section heading ──────────────────────────────────────────────── */
.sec-head{display:flex;align-items:center;gap:8px;margin-bottom:8px;border-bottom:1px solid #ccc;padding-bottom:4px}
.sec-head h2{font-size:13px}
.sec-count{font-size:11px;color:#666;font-weight:normal}

/* ── Severity overview table ──────────────────────────────────────── */
.sev-table{width:auto}
.sev-table td{min-width:80px;text-align:center;font-weight:bold;font-size:18px;padding:10px 18px;border:1px solid #ccc}
.sev-table .sev-lbl{display:block;font-size:10px;font-weight:normal;letter-spacing:.5px;text-transform:uppercase;color:#555;margin-top:2px}
.sev-critical{background:#fdf0f0;color:#9b1b00}
.sev-high    {background:#fdf6ee;color:#b04a00}
.sev-medium  {background:#fefde8;color:#7a6000}
.sev-low     {background:#f5fdf0;color:#3a6b00}
.sev-info    {background:#f0f6ff;color:#1a5590}

/* ── Scorecard table ──────────────────────────────────────────────── */
.score-tbl td{padding:7px 12px}
.sc-good{color:#1a6b1a;font-weight:bold}
.sc-fair{color:#7a6000;font-weight:bold}
.sc-poor{color:#b04a00;font-weight:bold}
.sc-crit{color:#9b1b00;font-weight:bold}

/* ── Pipeline info table ──────────────────────────────────────────── */
.pipe-tbl td:first-child{font-weight:bold;width:140px;background:#f8f8f8;white-space:nowrap}
.pipe-success{color:#1a6b1a}
.pipe-failed {color:#9b1b00}
.pipe-skipped{color:#888}

/* ── Summary block ────────────────────────────────────────────────── */
.summary-box{border:1px solid #ccc;padding:12px 14px;background:#fafafa;font-size:13px;line-height:1.7;color:#333}

/* ── Diagram block ────────────────────────────────────────────────── */
pre.diagram{font-family:"Courier New",Courier,monospace;font-size:12px;line-height:1.55;color:#333;padding:14px 16px;background:#fafafa;border:1px solid #ccc;overflow-x:auto}

/* ── Findings table ───────────────────────────────────────────────── */
.ftbl{table-layout:auto}
.ftbl thead th{font-size:11px}
.ftbl tbody tr.f-row{cursor:pointer}
.ftbl tbody tr.f-row:hover{background:#f5f5f5}
.ftbl tbody tr.f-row td{border-bottom:1px solid #ddd;padding:7px 10px;font-size:12px}
.ftbl tbody tr.f-row:last-of-type td{border-bottom:none}

/* row tints by severity */
.f-row.sev-critical{background:#fdf0f0}
.f-row.sev-high    {background:#fdf6ee}
.f-row.sev-medium  {background:#fefde8}
.f-row.sev-low     {background:#f5fdf0}
.f-row.sev-info    {background:#f0f6ff}

/* severity text colors */
.fc-critical{color:#9b1b00;font-weight:bold}
.fc-high    {color:#b04a00;font-weight:bold}
.fc-medium  {color:#7a6000;font-weight:bold}
.fc-low     {color:#3a6b00;font-weight:bold}
.fc-info    {color:#1a5590;font-weight:bold}

.td-rule{font-family:"Courier New",Courier,monospace;font-size:11px;white-space:nowrap}
.td-res {font-family:"Courier New",Courier,monospace;font-size:11px;max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.td-chev{width:22px;text-align:center;color:#888;font-size:13px;user-select:none}

/* detail rows */
.f-detail{display:none}
.f-detail.open{display:table-row}
.f-detail td{background:#f8f8f8;border-bottom:1px solid #ddd;padding:10px 12px 10px 32px;font-size:12px;color:#333}
.det-lbl{font-weight:bold;font-size:11px;text-transform:uppercase;letter-spacing:.3px;color:#555;margin-bottom:2px}
.det-val{line-height:1.65;margin-bottom:8px}
.det-val:last-child{margin-bottom:0}

/* empty state */
.empty-msg{font-style:italic;color:#888;padding:12px 10px;font-size:12px}

/* ── Footer ───────────────────────────────────────────────────────── */
.ftr{border-top:1px solid #ccc;background:#f8f8f8;padding:8px 0;margin-top:16px}
.ftr-inner{display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:6px}
.ftr-left{font-size:11px;color:#777}
.ftr-right{font-size:11px;color:#555;font-family:"Courier New",Courier,monospace}

/* ── Print ────────────────────────────────────────────────────────── */
@media print{
  .hdr{position:static}
  .f-detail{display:table-row !important}
  .td-chev{display:none}
}
</style>
</head>
<body>

<header class="hdr">
  <div class="wrap">
    <div class="hdr-inner">
      <div class="brand">
        <img src="{{.LogoDataURI}}" alt="TerraView logo">
        <div class="brand-text">
          <div class="brand-name">TERRAVIEW</div>
          <div class="brand-sub">Infrastructure Security Scanner &mdash; IaC Static Analysis</div>
        </div>
      </div>
      <div class="hdr-meta">
        <span><strong>Plan:</strong> {{.PlanFile}}</span>
        <span><strong>Generated:</strong> {{.GeneratedAt}}</span>
        <span><strong>Resources:</strong> {{.TotalResources}} &nbsp; <strong>Findings:</strong> {{.TotalFindings}}</span>
      </div>
    </div>
  </div>
</header>

<div class="verdict {{if .Safe}}safe{{else}}unsafe{{end}}">
  <div class="wrap">
    <div class="verdict-inner">
      <span class="verdict-label">{{.VerdictLabel}}</span>
      {{if .Confidence}}<span class="verdict-conf">Confidence: {{.Confidence}}</span>{{end}}
      {{if .Reasons}}
      <div class="verdict-reasons">
        {{range .Reasons}}<span class="v-reason">{{.}}</span>{{end}}
      </div>
      {{end}}
    </div>
  </div>
</div>

<main>
  <div class="wrap">
    <div class="page">

      <!-- Severity Overview -->
      <section>
        <div class="sec-head">
          <h2>Severity Overview</h2>
          <span class="sec-count">{{.TotalFindings}} total findings</span>
        </div>
        <table class="sev-table">
          <tbody>
            <tr>
              {{range .SeverityRows}}
              <td class="sev-{{.Class}}">
                {{.Count}}
                <span class="sev-lbl">{{.Label}}</span>
              </td>
              {{end}}
            </tr>
          </tbody>
        </table>
      </section>

      <!-- Scorecard -->
      <section>
        <div class="sec-head"><h2>Scorecard</h2></div>
        <table class="score-tbl">
          <thead>
            <tr>
              <th>Category</th>
              <th>Score</th>
            </tr>
          </thead>
          <tbody>
            {{range .Scores}}
            <tr>
              <td>{{.Label}}</td>
              <td class="{{.ColorClass}}">{{printf "%.1f" .Value}} / 10</td>
            </tr>
            {{end}}
          </tbody>
        </table>
      </section>

      {{if .PipelineCards}}
      <!-- Pipeline Status -->
      <section>
        <div class="sec-head"><h2>Pipeline Status</h2></div>
        <table class="pipe-tbl">
          <tbody>
            {{range .PipelineCards}}
            <tr>
              <td>{{.Title}}</td>
              <td class="pipe-{{.Class}}">{{.Value}}{{if .Detail}} &mdash; <span style="font-weight:normal;color:#555">{{.Detail}}</span>{{end}}</td>
            </tr>
            {{end}}
          </tbody>
        </table>
      </section>
      {{end}}

      {{if .Summary}}
      <!-- Analysis Summary -->
      <section>
        <div class="sec-head"><h2>Analysis Summary</h2></div>
        <div class="summary-box">{{.Summary}}</div>
      </section>
      {{end}}

      {{if .Diagram}}
      <!-- Infrastructure Diagram -->
      <section>
        <div class="sec-head"><h2>Infrastructure Diagram</h2></div>
        <pre class="diagram">{{.Diagram}}</pre>
      </section>
      {{end}}

      <!-- Scanner Findings -->
      <section>
        <div class="sec-head">
          <h2>Scanner Findings</h2>
          <span class="sec-count">({{len .ScannerFindings}})</span>
        </div>
        {{if .ScannerFindings}}
        <table class="ftbl">
          <thead>
            <tr>
              <th class="td-chev"></th>
              <th>Rule ID</th>
              <th>Severity</th>
              <th>Resource</th>
              <th>Category</th>
              <th>Source</th>
            </tr>
          </thead>
          <tbody>
            {{range $i, $f := .ScannerFindings}}
            <tr class="f-row sev-{{$f.SevClass}}"
                id="sr{{$i}}"
                onclick="toggle('s',{{$i}})"
                tabindex="0"
                aria-expanded="false"
                aria-controls="sd{{$i}}"
                onkeydown="if(event.key==='Enter'||event.key===' ')toggle('s',{{$i}})">
              <td class="td-chev" id="sico{{$i}}">&#9658;</td>
              <td class="td-rule">{{$f.RuleID}}</td>
              <td class="fc-{{$f.SevClass}}">{{$f.SevLabel}}</td>
              <td class="td-res" title="{{$f.Resource}}">{{$f.Resource}}</td>
              <td>{{$f.Category}}</td>
              <td>{{$f.Source}}</td>
            </tr>
            <tr class="f-detail" id="sd{{$i}}">
              <td colspan="6">
                <div class="det-lbl">Message</div>
                <div class="det-val">{{$f.Message}}</div>
                {{if $f.Remediation}}
                <div class="det-lbl">Remediation</div>
                <div class="det-val">{{$f.Remediation | linkify}}</div>
                {{end}}
              </td>
            </tr>
            {{end}}
          </tbody>
        </table>
        {{else}}
        <p class="empty-msg">No findings.</p>
        {{end}}
      </section>

      <!-- AI Analysis Findings -->
      <section>
        <div class="sec-head">
          <h2>AI Analysis Findings</h2>
          <span class="sec-count">({{len .AIFindings}})</span>
        </div>
        {{if .AIFindings}}
        <table class="ftbl">
          <thead>
            <tr>
              <th class="td-chev"></th>
              <th>Rule ID</th>
              <th>Severity</th>
              <th>Resource</th>
              <th>Category</th>
              <th>Source</th>
            </tr>
          </thead>
          <tbody>
            {{range $i, $f := .AIFindings}}
            <tr class="f-row sev-{{$f.SevClass}}"
                id="ar{{$i}}"
                onclick="toggle('a',{{$i}})"
                tabindex="0"
                aria-expanded="false"
                aria-controls="ad{{$i}}"
                onkeydown="if(event.key==='Enter'||event.key===' ')toggle('a',{{$i}})">
              <td class="td-chev" id="aico{{$i}}">&#9658;</td>
              <td class="td-rule">{{$f.RuleID}}</td>
              <td class="fc-{{$f.SevClass}}">{{$f.SevLabel}}</td>
              <td class="td-res" title="{{$f.Resource}}">{{$f.Resource}}</td>
              <td>{{$f.Category}}</td>
              <td>{{$f.Source}}</td>
            </tr>
            <tr class="f-detail" id="ad{{$i}}">
              <td colspan="6">
                <div class="det-lbl">Message</div>
                <div class="det-val">{{$f.Message}}</div>
                {{if $f.Remediation}}
                <div class="det-lbl">Remediation</div>
                <div class="det-val">{{$f.Remediation | linkify}}</div>
                {{end}}
              </td>
            </tr>
            {{end}}
          </tbody>
        </table>
        {{else}}
        <p class="empty-msg">No findings.</p>
        {{end}}
      </section>

    </div>
  </div>
</main>

<footer class="ftr">
  <div class="wrap">
    <div class="ftr-inner">
      <span class="ftr-left">terraview &middot; {{.GeneratedAt}}</span>
      <span class="ftr-right">exit code: {{.ExitCode}}</span>
    </div>
  </div>
</footer>

<script>
function toggle(p, i) {
  var det = document.getElementById(p + 'd' + i);
  var row = document.getElementById(p + 'r' + i);
  var ico = document.getElementById(p + 'ico' + i);
  var open = det.classList.contains('open');
  det.classList.toggle('open', !open);
  row.setAttribute('aria-expanded', String(!open));
  if (ico) ico.innerHTML = open ? '&#9658;' : '&#9660;';
}
</script>
</body>
</html>`

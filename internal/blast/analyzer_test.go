package blast

import (
	"strings"
	"testing"

	"github.com/leonamvasquez/terraview/internal/parser"
	"github.com/leonamvasquez/terraview/internal/topology"
)

func TestAnalyzer_NoResources(t *testing.T) {
	analyzer := NewAnalyzer()
	result := analyzer.Analyze(nil)
	if result.MaxRadius != 0 {
		t.Errorf("expected max radius 0, got %d", result.MaxRadius)
	}
	if len(result.Impacts) != 0 {
		t.Errorf("expected 0 impacts, got %d", len(result.Impacts))
	}
}

func TestAnalyzer_NoOpSkipped(t *testing.T) {
	analyzer := NewAnalyzer()
	resources := []parser.NormalizedResource{
		{Address: "aws_instance.a", Action: "no-op", Type: "aws_instance"},
		{Address: "aws_instance.b", Action: "read", Type: "aws_instance"},
	}
	result := analyzer.Analyze(resources)
	if len(result.Impacts) != 0 {
		t.Errorf("expected 0 impacts for no-op/read, got %d", len(result.Impacts))
	}
}

func TestAnalyzer_SingleCreate(t *testing.T) {
	analyzer := NewAnalyzer()
	resources := []parser.NormalizedResource{
		{Address: "aws_instance.web", Action: "create", Type: "aws_instance"},
	}
	result := analyzer.Analyze(resources)
	if len(result.Impacts) != 1 {
		t.Fatalf("expected 1 impact, got %d", len(result.Impacts))
	}
	if result.Impacts[0].Resource != "aws_instance.web" {
		t.Errorf("expected resource aws_instance.web, got %s", result.Impacts[0].Resource)
	}
}

func TestComputeRisk(t *testing.T) {
	tests := []struct {
		action   string
		affected int
		want     string
	}{
		{"create", 0, "low"},
		{"create", 3, "medium"},
		{"create", 6, "high"},
		{"create", 10, "critical"},
		{"delete", 0, "low"},
		{"delete", 2, "medium"},
		{"delete", 3, "high"},
		{"delete", 5, "critical"},
	}
	for _, tt := range tests {
		got := computeRisk(tt.action, tt.affected)
		if got != tt.want {
			t.Errorf("computeRisk(%s, %d) = %s, want %s", tt.action, tt.affected, got, tt.want)
		}
	}
}

func TestBlastResult_FormatPretty_Empty(t *testing.T) {
	br := &BlastResult{}
	out := br.FormatPretty()
	if out == "" {
		t.Error("expected non-empty output")
	}
}

func TestActionIcon(t *testing.T) {
	if actionIcon("create") != "[+]" {
		t.Error("create should be [+]")
	}
	if actionIcon("delete") != "[-]" {
		t.Error("delete should be [-]")
	}
	if actionIcon("update") != "[~]" {
		t.Error("update should be [~]")
	}
	if actionIcon("replace") != "[!]" {
		t.Error("replace should be [!]")
	}
}

// ---------------------------------------------------------------------------
// AnalyzeWithGraph — dependency chain tests
// ---------------------------------------------------------------------------

func TestAnalyzeWithGraph_DirectDeps(t *testing.T) {
	analyzer := NewAnalyzer()
	resources := []parser.NormalizedResource{
		{Address: "aws_vpc.main", Action: "update", Type: "aws_vpc"},
		{Address: "aws_subnet.a", Action: "update", Type: "aws_subnet"},
	}
	g := &topology.Graph{
		Nodes: []topology.Node{
			{Address: "aws_vpc.main"},
			{Address: "aws_subnet.a"},
		},
		Edges: []topology.Edge{
			{From: "aws_subnet.a", To: "aws_vpc.main"},
		},
	}

	result := analyzer.AnalyzeWithGraph(resources, g)

	// aws_vpc.main has 1 direct dep (subnet depends on it)
	var vpcImpact *Impact
	for i := range result.Impacts {
		if result.Impacts[i].Resource == "aws_vpc.main" {
			vpcImpact = &result.Impacts[i]
			break
		}
	}
	if vpcImpact == nil {
		t.Fatal("expected impact for aws_vpc.main")
	}
	if len(vpcImpact.DirectDeps) != 1 || vpcImpact.DirectDeps[0] != "aws_subnet.a" {
		t.Errorf("expected DirectDeps [aws_subnet.a], got %v", vpcImpact.DirectDeps)
	}
}

func TestAnalyzeWithGraph_IndirectDeps(t *testing.T) {
	analyzer := NewAnalyzer()
	resources := []parser.NormalizedResource{
		{Address: "aws_vpc.main", Action: "delete", Type: "aws_vpc"},
	}
	g := &topology.Graph{
		Nodes: []topology.Node{
			{Address: "aws_vpc.main"},
			{Address: "aws_subnet.a"},
			{Address: "aws_instance.web"},
		},
		Edges: []topology.Edge{
			{From: "aws_subnet.a", To: "aws_vpc.main"},
			{From: "aws_instance.web", To: "aws_subnet.a"},
		},
	}

	result := analyzer.AnalyzeWithGraph(resources, g)

	if len(result.Impacts) != 1 {
		t.Fatalf("expected 1 impact, got %d", len(result.Impacts))
	}
	imp := result.Impacts[0]
	if imp.TotalAffected != 2 {
		t.Errorf("expected 2 total affected, got %d", imp.TotalAffected)
	}
	if len(imp.DirectDeps) != 1 {
		t.Errorf("expected 1 direct dep, got %d", len(imp.DirectDeps))
	}
	if len(imp.IndirectDeps) != 1 {
		t.Errorf("expected 1 indirect dep, got %d", len(imp.IndirectDeps))
	}
}

func TestAnalyzeWithGraph_MaxRadius(t *testing.T) {
	analyzer := NewAnalyzer()
	resources := []parser.NormalizedResource{
		{Address: "r1", Action: "create", Type: "aws_instance"},
		{Address: "r2", Action: "create", Type: "aws_instance"},
	}
	g := &topology.Graph{
		Edges: []topology.Edge{
			{From: "dep1", To: "r1"},
			{From: "dep2", To: "r1"},
			{From: "dep3", To: "r1"},
			{From: "dep4", To: "r2"},
		},
	}

	result := analyzer.AnalyzeWithGraph(resources, g)

	// r1 has 3 deps, r2 has 1 dep → maxRadius = 3
	if result.MaxRadius != 3 {
		t.Errorf("expected max radius 3, got %d", result.MaxRadius)
	}
	// Sorted by TotalAffected desc
	if result.Impacts[0].Resource != "r1" {
		t.Errorf("expected r1 first (most affected), got %s", result.Impacts[0].Resource)
	}
}

func TestAnalyzeWithGraph_SummaryFormat(t *testing.T) {
	analyzer := NewAnalyzer()
	resources := []parser.NormalizedResource{
		{Address: "r1", Action: "create", Type: "aws_instance"},
	}
	g := &topology.Graph{}

	result := analyzer.AnalyzeWithGraph(resources, g)
	if !strings.Contains(result.Summary, "1 changes") {
		t.Errorf("expected '1 changes' in summary, got %q", result.Summary)
	}
}

// ---------------------------------------------------------------------------
// computeRisk extended
// ---------------------------------------------------------------------------

func TestComputeRisk_ReplaceWeight(t *testing.T) {
	// replace has weight 2, so 3*2=6 → high
	if got := computeRisk("replace", 3); got != "high" {
		t.Errorf("expected high for replace+3, got %s", got)
	}
	// replace with 5: 5*2=10 → critical
	if got := computeRisk("replace", 5); got != "critical" {
		t.Errorf("expected critical for replace+5, got %s", got)
	}
}

func TestComputeRisk_UpdateWeight(t *testing.T) {
	// update has weight 1, so 5*1=5 → medium
	if got := computeRisk("update", 5); got != "medium" {
		t.Errorf("expected medium for update+5, got %s", got)
	}
}

// ---------------------------------------------------------------------------
// FormatPretty
// ---------------------------------------------------------------------------

func TestBlastResult_FormatPretty_WithImpacts(t *testing.T) {
	br := &BlastResult{
		Impacts: []Impact{
			{
				Resource:      "aws_vpc.main",
				Action:        "delete",
				DirectDeps:    []string{"aws_subnet.a"},
				IndirectDeps:  []string{"aws_instance.web"},
				TotalAffected: 2,
				RiskLevel:     "high",
			},
			{
				Resource:      "aws_s3_bucket.data",
				Action:        "create",
				DirectDeps:    nil,
				IndirectDeps:  nil,
				TotalAffected: 0,
				RiskLevel:     "low",
			},
		},
		MaxRadius: 2,
		Summary:   "2 changes, max blast radius: 2 resources",
	}

	out := br.FormatPretty()

	if !strings.Contains(out, "[-] aws_vpc.main") {
		t.Error("expected delete icon and resource")
	}
	if !strings.Contains(out, "[+] aws_s3_bucket.data") {
		t.Error("expected create icon and resource")
	}
	if !strings.Contains(out, "aws_subnet.a") {
		t.Error("expected direct dep in output")
	}
	if !strings.Contains(out, "aws_instance.web") {
		t.Error("expected indirect dep in output")
	}
	if !strings.Contains(out, "HIGH") {
		t.Error("expected HIGH risk level")
	}
	if !strings.Contains(out, "(none)") {
		t.Error("expected (none) for empty deps")
	}
}

// ---------------------------------------------------------------------------
// containsStr
// ---------------------------------------------------------------------------

func TestContainsStr(t *testing.T) {
	tests := []struct {
		slice []string
		s     string
		want  bool
	}{
		{[]string{"a", "b", "c"}, "b", true},
		{[]string{"a", "b", "c"}, "d", false},
		{nil, "a", false},
		{[]string{}, "a", false},
	}
	for _, tt := range tests {
		if got := containsStr(tt.slice, tt.s); got != tt.want {
			t.Errorf("containsStr(%v, %q) = %v, want %v", tt.slice, tt.s, got, tt.want)
		}
	}
}

// ---------------------------------------------------------------------------
// actionIcon extended
// ---------------------------------------------------------------------------

func TestActionIcon_Unknown(t *testing.T) {
	if got := actionIcon("unknown"); got != "[ ]" {
		t.Errorf("expected [ ] for unknown, got %s", got)
	}
	if got := actionIcon(""); got != "[ ]" {
		t.Errorf("expected [ ] for empty, got %s", got)
	}
}

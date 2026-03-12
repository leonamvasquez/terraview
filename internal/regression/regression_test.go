package regression

import (
	"math"
	"strings"
	"testing"

	"github.com/leonamvasquez/terraview/internal/aggregator"
	"github.com/leonamvasquez/terraview/internal/blast"
	"github.com/leonamvasquez/terraview/internal/parser"
	"github.com/leonamvasquez/terraview/internal/rules"
	"github.com/leonamvasquez/terraview/internal/scoring"
	"github.com/leonamvasquez/terraview/internal/topology"
)

// ================================================================
// PHASE 3: BLAST RADIUS
// ================================================================

func TestBlast_DirectDependencies(t *testing.T) {
	resources := []parser.NormalizedResource{
		{Address: "aws_vpc.main", Type: "aws_vpc", Name: "main", Action: "create", Values: map[string]interface{}{}},
		{Address: "aws_subnet.a", Type: "aws_subnet", Name: "a", Action: "create", Values: map[string]interface{}{"vpc_id": "aws_vpc.main"}},
		{Address: "aws_subnet.b", Type: "aws_subnet", Name: "b", Action: "create", Values: map[string]interface{}{"vpc_id": "aws_vpc.main"}},
	}
	analyzer := blast.NewAnalyzer()
	result := analyzer.Analyze(resources)

	var vpcImpact *blast.Impact
	for i := range result.Impacts {
		if result.Impacts[i].Resource == "aws_vpc.main" {
			vpcImpact = &result.Impacts[i]
			break
		}
	}
	if vpcImpact == nil {
		t.Fatal("expected impact for aws_vpc.main")
	}
	if vpcImpact.TotalAffected < 2 {
		t.Errorf("VPC change should affect >= 2 subnets, got %d", vpcImpact.TotalAffected)
	}
	directStr := strings.Join(vpcImpact.DirectDeps, ",")
	if !strings.Contains(directStr, "aws_subnet.a") || !strings.Contains(directStr, "aws_subnet.b") {
		t.Errorf("expected both subnets in direct deps, got %v", vpcImpact.DirectDeps)
	}
}

func TestBlast_IndirectDependenciesBFS(t *testing.T) {
	// Chain: VPC <- subnet (vpc_id) <- eni (subnet_id) <- instance (network_interface_id)
	resources := []parser.NormalizedResource{
		{Address: "aws_vpc.main", Type: "aws_vpc", Name: "main", Action: "create", Values: map[string]interface{}{}},
		{Address: "aws_subnet.a", Type: "aws_subnet", Name: "a", Action: "create", Values: map[string]interface{}{"vpc_id": "aws_vpc.main"}},
		{Address: "aws_network_interface.eni", Type: "aws_network_interface", Name: "eni", Action: "create", Values: map[string]interface{}{"subnet_id": "aws_subnet.a"}},
		{Address: "aws_instance.web", Type: "aws_instance", Name: "web", Action: "create", Values: map[string]interface{}{"network_interface_id": "aws_network_interface.eni"}},
	}
	analyzer := blast.NewAnalyzer()
	result := analyzer.Analyze(resources)

	var vpcImpact *blast.Impact
	for i := range result.Impacts {
		if result.Impacts[i].Resource == "aws_vpc.main" {
			vpcImpact = &result.Impacts[i]
			break
		}
	}
	if vpcImpact == nil {
		t.Fatal("expected impact for aws_vpc.main")
	}
	if vpcImpact.TotalAffected < 3 {
		t.Errorf("VPC should transitively affect >= 3 resources, got %d (direct: %v, indirect: %v)",
			vpcImpact.TotalAffected, vpcImpact.DirectDeps, vpcImpact.IndirectDeps)
	}
}

func TestBlast_DeleteHigherRiskThanCreate(t *testing.T) {
	resources := []parser.NormalizedResource{
		{Address: "aws_vpc.main", Type: "aws_vpc", Name: "main", Action: "create", Values: map[string]interface{}{}},
		{Address: "aws_vpc.del", Type: "aws_vpc", Name: "del", Action: "delete", Values: map[string]interface{}{}},
		{Address: "aws_subnet.a1", Type: "aws_subnet", Name: "a1", Action: "create", Values: map[string]interface{}{"vpc_id": "aws_vpc.main"}},
		{Address: "aws_subnet.a2", Type: "aws_subnet", Name: "a2", Action: "create", Values: map[string]interface{}{"vpc_id": "aws_vpc.main"}},
		{Address: "aws_subnet.a3", Type: "aws_subnet", Name: "a3", Action: "create", Values: map[string]interface{}{"vpc_id": "aws_vpc.main"}},
		{Address: "aws_subnet.b1", Type: "aws_subnet", Name: "b1", Action: "create", Values: map[string]interface{}{"vpc_id": "aws_vpc.del"}},
		{Address: "aws_subnet.b2", Type: "aws_subnet", Name: "b2", Action: "create", Values: map[string]interface{}{"vpc_id": "aws_vpc.del"}},
		{Address: "aws_subnet.b3", Type: "aws_subnet", Name: "b3", Action: "create", Values: map[string]interface{}{"vpc_id": "aws_vpc.del"}},
	}
	analyzer := blast.NewAnalyzer()
	result := analyzer.Analyze(resources)

	var createRisk, deleteRisk string
	for _, imp := range result.Impacts {
		if imp.Resource == "aws_vpc.main" {
			createRisk = imp.RiskLevel
		}
		if imp.Resource == "aws_vpc.del" {
			deleteRisk = imp.RiskLevel
		}
	}
	if createRisk == "" || deleteRisk == "" {
		t.Fatal("expected impacts for both VPCs")
	}
	if createRisk == deleteRisk {
		t.Errorf("delete should have higher risk than create with same deps: create=%s, delete=%s", createRisk, deleteRisk)
	}
}

func TestBlast_Consistency(t *testing.T) {
	resources := []parser.NormalizedResource{
		{Address: "aws_vpc.main", Type: "aws_vpc", Name: "main", Action: "create", Values: map[string]interface{}{}},
		{Address: "aws_subnet.a", Type: "aws_subnet", Name: "a", Action: "create", Values: map[string]interface{}{"vpc_id": "aws_vpc.main"}},
		{Address: "aws_sg.sg", Type: "aws_security_group", Name: "sg", Action: "update", Values: map[string]interface{}{"vpc_id": "aws_vpc.main"}},
		{Address: "aws_instance.web", Type: "aws_instance", Name: "web", Action: "create", Values: map[string]interface{}{"subnet_id": "aws_subnet.a", "vpc_security_group_ids": "aws_sg.sg"}},
	}
	analyzer := blast.NewAnalyzer()
	r1 := analyzer.Analyze(resources)
	r2 := analyzer.Analyze(resources)
	r3 := analyzer.Analyze(resources)
	if r1.MaxRadius != r2.MaxRadius || r2.MaxRadius != r3.MaxRadius {
		t.Errorf("max radius inconsistent: %d, %d, %d", r1.MaxRadius, r2.MaxRadius, r3.MaxRadius)
	}
}

func TestBlast_AnalyzeVsAnalyzeWithGraph(t *testing.T) {
	resources := []parser.NormalizedResource{
		{Address: "aws_vpc.main", Type: "aws_vpc", Name: "main", Action: "create", Values: map[string]interface{}{}},
		{Address: "aws_subnet.a", Type: "aws_subnet", Name: "a", Action: "create", Values: map[string]interface{}{"vpc_id": "aws_vpc.main"}},
		{Address: "aws_instance.web", Type: "aws_instance", Name: "web", Action: "create", Values: map[string]interface{}{"subnet_id": "aws_subnet.a"}},
	}
	analyzer := blast.NewAnalyzer()
	r1 := analyzer.Analyze(resources)
	g := topology.BuildGraph(resources)
	r2 := analyzer.AnalyzeWithGraph(resources, g)

	if r1.MaxRadius != r2.MaxRadius {
		t.Errorf("Analyze vs AnalyzeWithGraph MaxRadius differ: %d vs %d", r1.MaxRadius, r2.MaxRadius)
	}
	if len(r1.Impacts) != len(r2.Impacts) {
		t.Fatalf("impact count differs: %d vs %d", len(r1.Impacts), len(r2.Impacts))
	}
	for i := range r1.Impacts {
		if r1.Impacts[i].TotalAffected != r2.Impacts[i].TotalAffected {
			t.Errorf("TotalAffected differs for %s: %d vs %d",
				r1.Impacts[i].Resource, r1.Impacts[i].TotalAffected, r2.Impacts[i].TotalAffected)
		}
	}
}

// ================================================================
// PHASE 4: DEDUPLICATION
// ================================================================

func TestDedup_SeverityMerge(t *testing.T) {
	scorer := scoring.NewScorerWithWeights(5, 3, 1, 0.5)
	agg := aggregator.NewAggregator(scorer)
	hard := []rules.Finding{
		{RuleID: "SEC001", Severity: rules.SeverityHigh, Category: rules.CategorySecurity,
			Resource: "aws_sg.test", Source: "checkov", Remediation: "restrict CIDR"},
	}
	llm := []rules.Finding{
		{RuleID: "SEC001", Severity: rules.SeverityCritical, Category: rules.CategorySecurity,
			Resource: "aws_sg.test", Source: "llm"},
	}
	result := agg.Aggregate("test.json", 3, hard, llm, "", false)

	if len(result.Findings) != 1 {
		t.Fatalf("expected 1 deduplicated finding, got %d", len(result.Findings))
	}
	f := result.Findings[0]
	if f.Severity != rules.SeverityCritical {
		t.Errorf("expected CRITICAL (highest), got %s", f.Severity)
	}
	if f.Remediation != "restrict CIDR" {
		t.Errorf("expected remediation from scanner, got %q", f.Remediation)
	}
	if !strings.Contains(f.Source, "checkov") || !strings.Contains(f.Source, "llm") {
		t.Errorf("expected merged sources, got %q", f.Source)
	}
}

func TestDedup_CaseInsensitive(t *testing.T) {
	scorer := scoring.NewScorerWithWeights(5, 3, 1, 0.5)
	agg := aggregator.NewAggregator(scorer)
	hard := []rules.Finding{
		{RuleID: "SEC001", Severity: rules.SeverityHigh, Category: rules.CategorySecurity,
			Resource: "aws_sg.Test", Source: "scanner"},
	}
	llm := []rules.Finding{
		{RuleID: "sec001", Severity: rules.SeverityMedium, Category: rules.CategorySecurity,
			Resource: "AWS_SG.test", Source: "llm"},
	}
	result := agg.Aggregate("test.json", 3, hard, llm, "", false)
	if len(result.Findings) != 1 {
		t.Errorf("expected 1 finding after case-insensitive dedup, got %d", len(result.Findings))
	}
}

func TestDedup_DifferentResourcesKept(t *testing.T) {
	scorer := scoring.NewScorerWithWeights(5, 3, 1, 0.5)
	agg := aggregator.NewAggregator(scorer)
	findings := []rules.Finding{
		{RuleID: "SEC001", Severity: rules.SeverityHigh, Category: rules.CategorySecurity,
			Resource: "aws_sg.alpha", Source: "scanner"},
		{RuleID: "SEC001", Severity: rules.SeverityHigh, Category: rules.CategorySecurity,
			Resource: "aws_sg.beta", Source: "scanner"},
	}
	result := agg.Aggregate("test.json", 3, findings, nil, "", false)
	if len(result.Findings) != 2 {
		t.Errorf("same RuleID on different resources must NOT be collapsed, got %d", len(result.Findings))
	}
}

func TestDedup_SameRuleDifferentMessages(t *testing.T) {
	scorer := scoring.NewScorerWithWeights(5, 3, 1, 0.5)
	agg := aggregator.NewAggregator(scorer)
	findings := []rules.Finding{
		{RuleID: "SEC001", Severity: rules.SeverityHigh, Category: rules.CategorySecurity,
			Resource: "aws_sg.test", Message: "Port 22 open", Source: "scanner"},
		{RuleID: "SEC001", Severity: rules.SeverityHigh, Category: rules.CategorySecurity,
			Resource: "aws_sg.test", Message: "SG allows all", Source: "llm"},
	}
	result := agg.Aggregate("test.json", 3, findings, nil, "", false)
	if len(result.Findings) != 1 {
		t.Errorf("same resource + ruleID should dedup regardless of message, got %d", len(result.Findings))
	}
}

func TestDedup_ThreeSourcesMerge(t *testing.T) {
	scorer := scoring.NewScorerWithWeights(5, 3, 1, 0.5)
	agg := aggregator.NewAggregator(scorer)
	hard := []rules.Finding{
		{RuleID: "SEC001", Severity: rules.SeverityMedium, Category: rules.CategorySecurity,
			Resource: "aws_sg.test", Source: "tfsec"},
		{RuleID: "SEC001", Severity: rules.SeverityHigh, Category: rules.CategorySecurity,
			Resource: "aws_sg.test", Source: "checkov"},
	}
	llm := []rules.Finding{
		{RuleID: "SEC001", Severity: rules.SeverityCritical, Category: rules.CategorySecurity,
			Resource: "aws_sg.test", Source: "llm"},
	}
	result := agg.Aggregate("test.json", 3, hard, llm, "", false)

	if len(result.Findings) != 1 {
		t.Fatalf("expected 1 finding from 3 sources, got %d", len(result.Findings))
	}
	f := result.Findings[0]
	if f.Severity != rules.SeverityCritical {
		t.Errorf("expected CRITICAL, got %s", f.Severity)
	}
	for _, src := range []string{"tfsec", "checkov", "llm"} {
		if !strings.Contains(f.Source, src) {
			t.Errorf("missing %q in source: %q", src, f.Source)
		}
	}
}

// ================================================================
// PHASE 7: SCORING
// ================================================================

func TestScoring_MediumOnlyFloor(t *testing.T) {
	s := scoring.NewScorerWithWeights(5, 3, 1, 0.5)
	f := []rules.Finding{
		{Severity: rules.SeverityMedium, Category: rules.CategorySecurity},
		{Severity: rules.SeverityMedium, Category: rules.CategorySecurity},
		{Severity: rules.SeverityMedium, Category: rules.CategorySecurity},
	}
	sc := s.Calculate(f, 3)
	if sc.SecurityScore < 5.0 {
		t.Errorf("MEDIUM-only security should be >= 5.0, got %.1f", sc.SecurityScore)
	}
}

func TestScoring_HighFloor(t *testing.T) {
	s := scoring.NewScorerWithWeights(5, 3, 1, 0.5)
	f := []rules.Finding{
		{Severity: rules.SeverityHigh, Category: rules.CategorySecurity},
		{Severity: rules.SeverityHigh, Category: rules.CategorySecurity},
	}
	sc := s.Calculate(f, 2)
	if sc.SecurityScore < 2.0 {
		t.Errorf("HIGH no CRITICAL should be >= 2.0, got %.1f", sc.SecurityScore)
	}
}

func TestScoring_CriticalCanZero(t *testing.T) {
	s := scoring.NewScorerWithWeights(5, 3, 1, 0.5)
	f := make([]rules.Finding, 10)
	for i := range f {
		f[i] = rules.Finding{Severity: rules.SeverityCritical, Category: rules.CategorySecurity}
	}
	sc := s.Calculate(f, 3)
	if sc.SecurityScore != 0.0 {
		t.Errorf("10 CRITICAL should zero security, got %.1f", sc.SecurityScore)
	}
}

func TestScoring_ReliabilityBlending(t *testing.T) {
	s := scoring.NewScorerWithWeights(5, 3, 1, 0.5)
	f := []rules.Finding{
		{Severity: rules.SeverityHigh, Category: rules.CategoryReliability},
	}
	sc := s.Calculate(f, 5)
	if sc.SecurityScore >= 10.0 {
		t.Errorf("reliability should blend into security, got %.1f", sc.SecurityScore)
	}
	if sc.ComplianceScore >= 10.0 {
		t.Errorf("reliability should blend into compliance, got %.1f", sc.ComplianceScore)
	}
}

func TestScoring_CustomWeightsDiffer(t *testing.T) {
	def := scoring.NewScorerWithWeights(5, 3, 1, 0.5)
	fin := scoring.NewScorerWithWeights(10, 5, 2, 1)
	f := []rules.Finding{
		{Severity: rules.SeverityMedium, Category: rules.CategorySecurity},
	}
	ds := def.Calculate(f, 5)
	fs := fin.Calculate(f, 5)
	if fs.OverallScore >= ds.OverallScore {
		t.Errorf("fintech should score lower: default=%.1f fintech=%.1f", ds.OverallScore, fs.OverallScore)
	}
}

func TestScoring_Range(t *testing.T) {
	s := scoring.NewScorerWithWeights(5, 3, 1, 0.5)
	cases := []struct {
		name string
		f    []rules.Finding
		n    int
	}{
		{"empty", nil, 0},
		{"clean", nil, 10},
		{"1crit", []rules.Finding{
			{Severity: rules.SeverityCritical, Category: rules.CategorySecurity},
		}, 1},
		{"50crit", func() []rules.Finding {
			r := make([]rules.Finding, 50)
			for i := range r {
				r[i] = rules.Finding{Severity: rules.SeverityCritical, Category: rules.CategorySecurity}
			}
			return r
		}(), 2},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			sc := s.Calculate(c.f, c.n)
			for _, v := range []float64{sc.SecurityScore, sc.MaintainabilityScore, sc.ComplianceScore, sc.OverallScore} {
				if v < 0 || v > 10 {
					t.Errorf("out of [0,10]: %.1f", v)
				}
				if math.IsNaN(v) || math.IsInf(v, 0) {
					t.Errorf("NaN/Inf: %f", v)
				}
			}
		})
	}
}

// ================================================================
// STRICT MODE + EXIT CODE
// ================================================================

func TestStrictMode_HighNotSafe(t *testing.T) {
	scorer := scoring.NewScorerWithWeights(5, 3, 1, 0.5)
	agg := aggregator.NewAggregator(scorer)
	f := []rules.Finding{
		{RuleID: "SEC001", Severity: rules.SeverityHigh, Category: rules.CategorySecurity, Resource: "test"},
	}
	ns := agg.Aggregate("t.json", 5, f, nil, "", false)
	if !ns.Verdict.Safe {
		t.Error("non-strict: HIGH should be SAFE")
	}
	st := agg.Aggregate("t.json", 5, f, nil, "", true)
	if st.Verdict.Safe {
		t.Error("strict: HIGH should be NOT SAFE")
	}
}

func TestExitCode_Matrix(t *testing.T) {
	scorer := scoring.NewScorerWithWeights(5, 3, 1, 0.5)
	agg := aggregator.NewAggregator(scorer)
	tests := []struct {
		sev  string
		code int
	}{
		{rules.SeverityCritical, 2},
		{rules.SeverityHigh, 1},
		{rules.SeverityMedium, 0},
		{rules.SeverityLow, 0},
	}
	for _, tt := range tests {
		t.Run(tt.sev, func(t *testing.T) {
			f := []rules.Finding{
				{RuleID: "T", Severity: tt.sev, Category: rules.CategorySecurity, Resource: "r"},
			}
			r := agg.Aggregate("t.json", 5, f, nil, "", false)
			if r.ExitCode != tt.code {
				t.Errorf("%s: expected exit code %d, got %d", tt.sev, tt.code, r.ExitCode)
			}
		})
	}
}

// ================================================================
// VOLUME PENALTY: large infra dilution fix
// ================================================================

func TestScoring_LargeInfraNotDiluted(t *testing.T) {
	s := scoring.NewScorerWithWeights(5, 3, 1, 0.5)
	findings := make([]rules.Finding, 0, 174)
	for i := 0; i < 174; i++ {
		findings = append(findings, rules.Finding{
			Severity: rules.SeverityHigh,
			Category: rules.CategorySecurity,
		})
	}
	sc := s.Calculate(findings, 380)
	// Old formula: 10-(174*3/380*2)=7.26 → too high
	// New formula: volume penalty log2(175)*0.5 ≈ 3.73 → ~6.3
	if sc.SecurityScore >= 7.5 {
		t.Errorf("174 HIGH on 380 resources should be < 7.5, got %.1f", sc.SecurityScore)
	}
	if sc.SecurityScore < 2.0 {
		t.Errorf("HIGH floor violated: got %.1f", sc.SecurityScore)
	}
}

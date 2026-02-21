package regression

import (
	"fmt"
	"math"
	"strings"
	"testing"

	"github.com/leonamvasquez/terraview/internal/aggregator"
	"github.com/leonamvasquez/terraview/internal/blast"
	"github.com/leonamvasquez/terraview/internal/config"
	"github.com/leonamvasquez/terraview/internal/parser"
	"github.com/leonamvasquez/terraview/internal/profile"
	"github.com/leonamvasquez/terraview/internal/rules"
	"github.com/leonamvasquez/terraview/internal/scoring"
	"github.com/leonamvasquez/terraview/internal/smell"
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
			Resource: "aws_sg.test", Source: "hard-rule", Remediation: "restrict CIDR"},
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
		t.Errorf("expected remediation from hard-rule, got %q", f.Remediation)
	}
	if !strings.Contains(f.Source, "hard-rule") || !strings.Contains(f.Source, "llm") {
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
			Resource: "aws_sg.test", Source: "hard-rule"},
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
	for _, src := range []string{"hard-rule", "checkov", "llm"} {
		if !strings.Contains(f.Source, src) {
			t.Errorf("missing %q in source: %q", src, f.Source)
		}
	}
}

// ================================================================
// PHASE 5: PROFILE
// ================================================================

func TestProfile_StrictModeTrue(t *testing.T) {
	cfg := &config.Config{}
	trueVal := true
	p := &profile.Profile{Name: "test", StrictMode: &trueVal}
	profile.Apply(cfg, p)
	if cfg.Rules.StrictMode == nil || !*cfg.Rules.StrictMode {
		t.Error("expected StrictMode true")
	}
}

func TestProfile_StrictModeFalse(t *testing.T) {
	cfg := &config.Config{}
	falseVal := false
	p := &profile.Profile{Name: "test", StrictMode: &falseVal}
	profile.Apply(cfg, p)
	if cfg.Rules.StrictMode == nil {
		t.Fatal("expected StrictMode set (false)")
	}
	if *cfg.Rules.StrictMode {
		t.Error("expected StrictMode false")
	}
}

func TestProfile_StrictModeNil(t *testing.T) {
	cfg := &config.Config{}
	p := &profile.Profile{Name: "test"}
	profile.Apply(cfg, p)
	if cfg.Rules.StrictMode != nil {
		t.Error("expected StrictMode nil when not set in profile")
	}
}

func TestProfile_DisabledRules(t *testing.T) {
	cfg := &config.Config{}
	p := &profile.Profile{Name: "test", DisabledRules: []string{"REL001", "TAG001"}}
	profile.Apply(cfg, p)
	if len(cfg.Rules.DisabledRules) != 2 {
		t.Fatalf("expected 2 disabled rules, got %d", len(cfg.Rules.DisabledRules))
	}
}

func TestProfile_EnabledRules(t *testing.T) {
	cfg := &config.Config{}
	p := &profile.Profile{Name: "test", EnabledRules: []string{"SEC001", "SEC002"}}
	profile.Apply(cfg, p)
	if len(cfg.Rules.EnabledRules) != 2 {
		t.Fatalf("expected 2 enabled rules, got %d", len(cfg.Rules.EnabledRules))
	}
}

func TestProfile_WeightsOverride(t *testing.T) {
	cfg := &config.Config{}
	cfg.Scoring.SeverityWeights.Critical = 5.0
	p := &profile.Profile{
		Name: "test",
		Scoring: profile.ScoringOverride{
			Weights: profile.SeverityWeights{
				Critical: 10.0, High: 5.0, Medium: 2.0, Low: 1.0,
			},
		},
	}
	profile.Apply(cfg, p)
	if cfg.Scoring.SeverityWeights.Critical != 10.0 {
		t.Errorf("expected critical 10.0, got %.1f", cfg.Scoring.SeverityWeights.Critical)
	}
}

func TestProfile_LoadAll(t *testing.T) {
	for _, name := range []string{"prod", "dev", "fintech", "startup"} {
		t.Run(name, func(t *testing.T) {
			p, err := profile.Load(name)
			if err != nil {
				t.Fatalf("load %q: %v", name, err)
			}
			if p.Name == "" {
				t.Error("empty name")
			}
		})
	}
}

func TestProfile_ProdStrictMode(t *testing.T) {
	p, err := profile.Load("prod")
	if err != nil {
		t.Fatal(err)
	}
	if p.StrictMode == nil || !*p.StrictMode {
		t.Error("prod should have strict_mode: true")
	}
}

func TestProfile_DevRelaxed(t *testing.T) {
	p, err := profile.Load("dev")
	if err != nil {
		t.Fatal(err)
	}
	if p.StrictMode == nil {
		t.Error("dev should explicitly set strict_mode")
		return
	}
	if *p.StrictMode {
		t.Error("dev should have strict_mode: false")
	}
}

func TestProfile_FintechStrict(t *testing.T) {
	p, err := profile.Load("fintech")
	if err != nil {
		t.Fatal(err)
	}
	if p.StrictMode == nil || !*p.StrictMode {
		t.Error("fintech should have strict_mode: true")
	}
}

func TestProfile_StartupYAMLStructure(t *testing.T) {
	p, err := profile.Load("startup")
	if err != nil {
		t.Fatal(err)
	}
	if len(p.DisabledRules) == 0 {
		t.Errorf("REGRESSION: startup disabled_rules empty — YAML uses rules.disabled_rules instead of top-level")
	}
	if p.Scoring.Weights.Critical == 0 && p.Scoring.Weights.High == 0 {
		t.Errorf("REGRESSION: startup scoring weights zero — YAML uses scoring.severity_weights instead of scoring.weights")
	}
}

// ================================================================
// PHASE 6: SMELL
// ================================================================

func TestSmell_HardcodedPassword(t *testing.T) {
	resources := []parser.NormalizedResource{
		{Address: "aws_db_instance.main", Type: "aws_db_instance", Name: "main", Action: "create",
			Values: map[string]interface{}{"password": "Secret123!", "tags": map[string]interface{}{"Name": "db"}}},
	}
	detector := smell.NewDetector()
	result := detector.Detect(resources)
	found := false
	for _, s := range result.Smells {
		if s.Type == "hardcoded-values" && s.Resource == "aws_db_instance.main" {
			found = true
			if s.Severity != "CRITICAL" {
				t.Errorf("expected CRITICAL, got %s", s.Severity)
			}
		}
	}
	if !found {
		t.Error("expected hardcoded-values smell")
	}
}

func TestSmell_AllSensitiveFields(t *testing.T) {
	fields := []string{"password", "secret", "api_key", "access_key", "secret_key",
		"private_key", "token", "credentials", "connection_string"}
	for _, field := range fields {
		t.Run(field, func(t *testing.T) {
			resources := []parser.NormalizedResource{
				{Address: "aws_instance.t", Type: "aws_instance", Name: "t", Action: "create",
					Values: map[string]interface{}{field: "hardcoded-value", "tags": map[string]interface{}{"Name": "t"}}},
			}
			result := smell.NewDetector().Detect(resources)
			found := false
			for _, s := range result.Smells {
				if s.Type == "hardcoded-values" {
					found = true
				}
			}
			if !found {
				t.Errorf("field %q not detected", field)
			}
		})
	}
}

func TestSmell_VarRefNotDetected(t *testing.T) {
	resources := []parser.NormalizedResource{
		{Address: "aws_db_instance.main", Type: "aws_db_instance", Name: "main", Action: "create",
			Values: map[string]interface{}{"password": "var.db_password", "tags": map[string]interface{}{"Name": "db"}}},
	}
	result := smell.NewDetector().Detect(resources)
	for _, s := range result.Smells {
		if s.Type == "hardcoded-values" && s.Resource == "aws_db_instance.main" {
			t.Error("var.* should NOT trigger hardcoded-values")
		}
	}
}

func TestSmell_DataRefNotDetected(t *testing.T) {
	resources := []parser.NormalizedResource{
		{Address: "aws_instance.main", Type: "aws_instance", Name: "main", Action: "create",
			Values: map[string]interface{}{"token": "data.aws_ssm.token", "tags": map[string]interface{}{"Name": "t"}}},
	}
	result := smell.NewDetector().Detect(resources)
	for _, s := range result.Smells {
		if s.Type == "hardcoded-values" && s.Resource == "aws_instance.main" {
			t.Error("data.* should NOT trigger hardcoded-values")
		}
	}
}

func TestSmell_EmptyValueNotDetected(t *testing.T) {
	resources := []parser.NormalizedResource{
		{Address: "aws_instance.main", Type: "aws_instance", Name: "main", Action: "create",
			Values: map[string]interface{}{"password": "", "tags": map[string]interface{}{"Name": "t"}}},
	}
	result := smell.NewDetector().Detect(resources)
	for _, s := range result.Smells {
		if s.Type == "hardcoded-values" && s.Resource == "aws_instance.main" {
			t.Error("empty value should NOT trigger hardcoded-values")
		}
	}
}

func TestSmell_NoBackup(t *testing.T) {
	resources := []parser.NormalizedResource{
		{Address: "aws_db_instance.main", Type: "aws_db_instance", Name: "main", Action: "create",
			Values: map[string]interface{}{"engine": "mysql", "tags": map[string]interface{}{"Name": "db"}}},
	}
	result := smell.NewDetector().Detect(resources)
	found := false
	for _, s := range result.Smells {
		if s.Type == "no-backup" && s.Resource == "aws_db_instance.main" {
			found = true
			if s.Severity != "HIGH" {
				t.Errorf("expected HIGH, got %s", s.Severity)
			}
		}
	}
	if !found {
		t.Error("expected no-backup smell")
	}
}

func TestSmell_BackupPresentNoSmell(t *testing.T) {
	resources := []parser.NormalizedResource{
		{Address: "aws_db_instance.main", Type: "aws_db_instance", Name: "main", Action: "create",
			Values: map[string]interface{}{
				"engine": "mysql", "backup_retention_period": 7,
				"tags": map[string]interface{}{"Name": "db"},
			}},
	}
	result := smell.NewDetector().Detect(resources)
	for _, s := range result.Smells {
		if s.Type == "no-backup" && s.Resource == "aws_db_instance.main" {
			t.Error("should NOT detect no-backup with backup_retention_period")
		}
	}
}

func TestSmell_BackupMultiProvider(t *testing.T) {
	tests := []struct {
		rtype string
		field string
	}{
		{"aws_rds_cluster", "backup_retention_period"},
		{"aws_dynamodb_table", "point_in_time_recovery"},
		{"azurerm_mssql_database", "short_term_retention_policy"},
		{"azurerm_cosmosdb_account", "backup"},
		{"google_sql_database_instance", "settings"},
	}
	for _, tt := range tests {
		t.Run(tt.rtype+"_without", func(t *testing.T) {
			r := []parser.NormalizedResource{{
				Address: tt.rtype + ".t", Type: tt.rtype, Name: "t", Action: "create",
				Values: map[string]interface{}{},
			}}
			result := smell.NewDetector().Detect(r)
			found := false
			for _, s := range result.Smells {
				if s.Type == "no-backup" {
					found = true
				}
			}
			if !found {
				t.Errorf("expected no-backup for %s", tt.rtype)
			}
		})
		t.Run(tt.rtype+"_with", func(t *testing.T) {
			r := []parser.NormalizedResource{{
				Address: tt.rtype + ".t", Type: tt.rtype, Name: "t", Action: "create",
				Values: map[string]interface{}{tt.field: "ok"},
			}}
			result := smell.NewDetector().Detect(r)
			for _, s := range result.Smells {
				if s.Type == "no-backup" && s.Resource == tt.rtype+".t" {
					t.Errorf("false positive for %s with %s", tt.rtype, tt.field)
				}
			}
		})
	}
}

func TestSmell_MonolithAndNoModules(t *testing.T) {
	resources := make([]parser.NormalizedResource, 25)
	for i := range resources {
		resources[i] = parser.NormalizedResource{
			Address: fmt.Sprintf("aws_instance.i%d", i),
			Type:    "aws_instance",
			Name:    fmt.Sprintf("i%d", i),
			Action:  "create",
			Values:  map[string]interface{}{"tags": map[string]interface{}{"Name": fmt.Sprintf("i%d", i)}},
		}
	}
	result := smell.NewDetector().Detect(resources)
	foundMonolith, foundNoModules := false, false
	for _, s := range result.Smells {
		if s.Type == "monolith-risk" {
			foundMonolith = true
		}
		if s.Type == "no-modules" {
			foundNoModules = true
		}
	}
	if !foundMonolith {
		t.Error("expected monolith-risk for 25 root resources")
	}
	if !foundNoModules {
		t.Error("expected no-modules for 25 root resources")
	}
}

func TestSmell_BelowMonolithThreshold(t *testing.T) {
	resources := make([]parser.NormalizedResource, 10)
	for i := range resources {
		resources[i] = parser.NormalizedResource{
			Address: fmt.Sprintf("aws_instance.i%d", i),
			Type:    "aws_instance",
			Name:    fmt.Sprintf("i%d", i),
			Action:  "create",
			Values:  map[string]interface{}{"tags": map[string]interface{}{"Name": fmt.Sprintf("i%d", i)}},
		}
	}
	result := smell.NewDetector().Detect(resources)
	for _, s := range result.Smells {
		if s.Type == "monolith-risk" {
			t.Error("10 resources should NOT trigger monolith-risk")
		}
		if s.Type == "no-modules" {
			t.Error("10 resources should NOT trigger no-modules")
		}
	}
}

func TestSmell_ModulesPresent(t *testing.T) {
	resources := make([]parser.NormalizedResource, 0, 25)
	for i := 0; i < 20; i++ {
		resources = append(resources, parser.NormalizedResource{
			Address: fmt.Sprintf("module.net.aws_subnet.s%d", i),
			Type:    "aws_subnet",
			Name:    fmt.Sprintf("s%d", i),
			Action:  "create",
			Values:  map[string]interface{}{},
		})
	}
	for i := 0; i < 5; i++ {
		resources = append(resources, parser.NormalizedResource{
			Address: fmt.Sprintf("aws_instance.r%d", i),
			Type:    "aws_instance",
			Name:    fmt.Sprintf("r%d", i),
			Action:  "create",
			Values:  map[string]interface{}{"tags": map[string]interface{}{"Name": "r"}},
		})
	}
	result := smell.NewDetector().Detect(resources)
	for _, s := range result.Smells {
		if s.Type == "monolith-risk" || s.Type == "no-modules" {
			t.Errorf("unexpected %q with 80%% module ratio", s.Type)
		}
	}
}

func TestSmell_QualityScoreImpact(t *testing.T) {
	clean := []parser.NormalizedResource{
		{Address: "aws_instance.c", Type: "aws_instance", Name: "c", Action: "create",
			Values: map[string]interface{}{"tags": map[string]interface{}{"Name": "c"}}},
	}
	dirty := []parser.NormalizedResource{
		{Address: "aws_db_instance.d", Type: "aws_db_instance", Name: "d", Action: "create",
			Values: map[string]interface{}{"password": "bad", "engine": "mysql",
				"tags": map[string]interface{}{"Name": "d"}}},
	}
	d := smell.NewDetector()
	cr := d.Detect(clean)
	dr := d.Detect(dirty)
	if dr.QualityScore >= cr.QualityScore {
		t.Errorf("dirty should score lower: clean=%.1f dirty=%.1f", cr.QualityScore, dr.QualityScore)
	}
}

func TestSmell_NilValues(t *testing.T) {
	resources := []parser.NormalizedResource{
		{Address: "aws_db_instance.nil", Type: "aws_db_instance", Name: "nil", Action: "create",
			Values: nil},
	}
	result := smell.NewDetector().Detect(resources)
	if result == nil {
		t.Error("expected non-nil result with nil values")
	}
}

func TestSmell_AllNewTypes(t *testing.T) {
	resources := make([]parser.NormalizedResource, 0, 25)
	resources = append(resources, parser.NormalizedResource{
		Address: "aws_db_instance.main", Type: "aws_db_instance", Name: "main", Action: "create",
		Values: map[string]interface{}{"password": "hardcoded!", "engine": "pg",
			"tags": map[string]interface{}{"Name": "db"}},
	})
	for i := 0; i < 24; i++ {
		resources = append(resources, parser.NormalizedResource{
			Address: fmt.Sprintf("aws_instance.i%d", i),
			Type:    "aws_instance",
			Name:    fmt.Sprintf("i%d", i),
			Action:  "create",
			Values:  map[string]interface{}{"tags": map[string]interface{}{"Name": fmt.Sprintf("i%d", i)}},
		})
	}
	result := smell.NewDetector().Detect(resources)
	found := map[smell.SmellType]bool{}
	for _, s := range result.Smells {
		found[s.Type] = true
	}
	for _, e := range []smell.SmellType{"hardcoded-values", "no-backup", "monolith-risk", "no-modules"} {
		if !found[e] {
			t.Errorf("expected smell %q", e)
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

func TestScoring_ProfileWeightsDiffer(t *testing.T) {
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

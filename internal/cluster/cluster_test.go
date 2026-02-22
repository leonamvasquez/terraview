package cluster

import (
	"fmt"
	"strings"
	"testing"

	"github.com/leonamvasquez/terraview/internal/i18n"
	"github.com/leonamvasquez/terraview/internal/rules"
)

func TestBuildEmpty(t *testing.T) {
	b := NewBuilder()
	result := b.Build(nil)
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if len(result.Clusters) != 0 {
		t.Errorf("expected 0 clusters, got %d", len(result.Clusters))
	}
}

func TestBuildSingleResource(t *testing.T) {
	b := NewBuilder()
	findings := []rules.Finding{
		{RuleID: "R1", Severity: "HIGH", Resource: "aws_instance.web", Source: "checkov"},
		{RuleID: "R2", Severity: "MEDIUM", Resource: "aws_instance.web", Source: "tfsec"},
	}
	result := b.Build(findings)
	if len(result.Clusters) != 1 {
		t.Fatalf("expected 1 cluster, got %d", len(result.Clusters))
	}
	c := result.Clusters[0]
	if c.ID != "aws_instance.web" {
		t.Errorf("expected ID aws_instance.web, got %s", c.ID)
	}
	if len(c.Findings) != 2 {
		t.Errorf("expected 2 findings, got %d", len(c.Findings))
	}
	if c.SourceCount != 2 {
		t.Errorf("expected source count 2, got %d", c.SourceCount)
	}
	if c.Severity != "HIGH" {
		t.Errorf("expected HIGH, got %s", c.Severity)
	}
}

func TestBuildMultipleResources(t *testing.T) {
	b := NewBuilder()
	findings := []rules.Finding{
		{RuleID: "R1", Severity: "CRITICAL", Resource: "aws_s3_bucket.data", Source: "checkov"},
		{RuleID: "R2", Severity: "LOW", Resource: "aws_instance.web", Source: "tfsec"},
	}
	result := b.Build(findings)
	if len(result.Clusters) != 2 {
		t.Fatalf("expected 2 clusters, got %d", len(result.Clusters))
	}
	if result.Clusters[0].Severity != "CRITICAL" {
		t.Errorf("expected first CRITICAL, got %s", result.Clusters[0].Severity)
	}
}

func TestSortedByRiskDescending(t *testing.T) {
	b := NewBuilder()
	findings := []rules.Finding{
		{RuleID: "R1", Severity: "LOW", Resource: "aws_instance.dev", Source: "tfsec"},
		{RuleID: "R2", Severity: "CRITICAL", Resource: "aws_s3_bucket.p", Source: "checkov"},
		{RuleID: "R3", Severity: "CRITICAL", Resource: "aws_s3_bucket.p", Source: "tfsec"},
		{RuleID: "R4", Severity: "MEDIUM", Resource: "aws_vpc.main", Source: "checkov"},
	}
	result := b.Build(findings)
	for i := 1; i < len(result.Clusters); i++ {
		if result.Clusters[i].RiskScore > result.Clusters[i-1].RiskScore {
			t.Errorf("not sorted: %.0f before %.0f",
				result.Clusters[i-1].RiskScore, result.Clusters[i].RiskScore)
		}
	}
}

func TestSourceMultiplier(t *testing.T) {
	b := NewBuilder()
	r1 := b.Build([]rules.Finding{
		{RuleID: "R1", Severity: "HIGH", Resource: "aws_instance.x", Source: "checkov"},
	})
	r2 := b.Build([]rules.Finding{
		{RuleID: "R1", Severity: "HIGH", Resource: "aws_instance.y", Source: "checkov"},
		{RuleID: "R2", Severity: "HIGH", Resource: "aws_instance.y", Source: "tfsec"},
	})
	if r2.Clusters[0].RiskScore <= r1.Clusters[0].RiskScore {
		t.Errorf("dual %.0f should > single %.0f",
			r2.Clusters[0].RiskScore, r1.Clusters[0].RiskScore)
	}
}

func TestHighRiskCount(t *testing.T) {
	b := NewBuilder()
	findings := []rules.Finding{
		{RuleID: "R1", Severity: "CRITICAL", Resource: "aws_s3.a", Source: "checkov"},
		{RuleID: "R2", Severity: "CRITICAL", Resource: "aws_s3.a", Source: "tfsec"},
		{RuleID: "R3", Severity: "LOW", Resource: "aws_instance.b", Source: "checkov"},
	}
	result := b.Build(findings)
	if result.HighRiskClusters != 1 {
		t.Errorf("expected 1 high-risk, got %d", result.HighRiskClusters)
	}
}

func TestNormalizeResourceKey(t *testing.T) {
	tests := []struct{ in, want string }{
		{"aws_instance.web", "aws_instance.web"},
		{"module.vpc.aws_subnet.private", "aws_subnet.private"},
		{"module.a.module.b.aws_iam_role.role", "aws_iam_role.role"},
		{"", "(unknown)"},
	}
	for _, tc := range tests {
		got := normalizeResourceKey(tc.in)
		if got != tc.want {
			t.Errorf("normalizeResourceKey(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestHighestSeverity(t *testing.T) {
	tests := []struct {
		findings []rules.Finding
		want     string
	}{
		{nil, "INFO"},
		{[]rules.Finding{{Severity: "LOW"}, {Severity: "HIGH"}}, "HIGH"},
		{[]rules.Finding{{Severity: "CRITICAL"}}, "CRITICAL"},
	}
	for _, tc := range tests {
		got := highestSeverity(tc.findings)
		if got != tc.want {
			t.Errorf("highestSeverity = %s, want %s", got, tc.want)
		}
	}
}

func TestFormatClusters(t *testing.T) {
	b := NewBuilder()
	result := b.Build([]rules.Finding{
		{RuleID: "R1", Severity: "HIGH", Resource: "aws_instance.web", Source: "checkov"},
	})
	out := FormatClusters(result)
	if !strings.Contains(out, "Cluster #1") {
		t.Error("expected Cluster #1")
	}
}

func TestFormatClustersBR(t *testing.T) {
	i18n.SetLang("pt-BR")
	defer i18n.SetLang("")
	b := NewBuilder()
	result := b.Build([]rules.Finding{
		{RuleID: "R1", Severity: "HIGH", Resource: "aws_instance.web", Source: "checkov"},
	})
	out := FormatClusters(result)
	if !strings.Contains(out, "Clusters de Risco") {
		t.Error("expected pt-BR header")
	}
}

func TestFormatClustersNil(t *testing.T) {
	out := FormatClusters(nil)
	if out == "" {
		t.Error("expected non-empty")
	}
}

func TestRiskScoreCapped(t *testing.T) {
	b := NewBuilder()
	var findings []rules.Finding
	for i := 0; i < 20; i++ {
		findings = append(findings, rules.Finding{
			RuleID:   fmt.Sprintf("R%d", i),
			Severity: "CRITICAL",
			Resource: "aws_bad.thing",
			Source:   "checkov",
		})
	}
	result := b.Build(findings)
	if result.Clusters[0].RiskScore > 100.0 {
		t.Errorf("score %.0f exceeds 100", result.Clusters[0].RiskScore)
	}
}

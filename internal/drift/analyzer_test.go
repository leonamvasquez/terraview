package drift

import (
	"testing"

	"github.com/leonamvasquez/terraview/internal/parser"
	"github.com/leonamvasquez/terraview/internal/rules"
)

func TestAnalyze_NoDrift(t *testing.T) {
	analyzer := NewAnalyzer(nil)
	resources := []parser.NormalizedResource{
		{Address: "aws_instance.web", Type: "aws_instance", Action: "no-op"},
		{Address: "aws_s3_bucket.logs", Type: "aws_s3_bucket", Action: "read"},
	}

	result := analyzer.Analyze(resources)

	if result.TotalChanges != 0 {
		t.Errorf("expected 0 changes, got %d", result.TotalChanges)
	}
	if result.ExitCode != 0 {
		t.Errorf("expected exit code 0, got %d", result.ExitCode)
	}
	if result.MaxSeverity != "NONE" {
		t.Errorf("expected NONE severity, got %s", result.MaxSeverity)
	}
}

func TestAnalyze_CriticalDelete(t *testing.T) {
	analyzer := NewAnalyzer(nil)
	resources := []parser.NormalizedResource{
		{Address: "aws_db_instance.main", Type: "aws_db_instance", Action: "delete"},
	}

	result := analyzer.Analyze(resources)

	if result.TotalChanges != 1 {
		t.Errorf("expected 1 change, got %d", result.TotalChanges)
	}
	if result.Deletes != 1 {
		t.Errorf("expected 1 delete, got %d", result.Deletes)
	}
	if result.ExitCode != 2 {
		t.Errorf("expected exit code 2 for critical delete, got %d", result.ExitCode)
	}
	if result.MaxSeverity != rules.SeverityCritical {
		t.Errorf("expected CRITICAL, got %s", result.MaxSeverity)
	}
}

func TestAnalyze_NonCriticalDelete(t *testing.T) {
	analyzer := NewAnalyzer(nil)
	resources := []parser.NormalizedResource{
		{Address: "aws_cloudwatch_log_group.app", Type: "aws_cloudwatch_log_group", Action: "delete"},
	}

	result := analyzer.Analyze(resources)

	if result.ExitCode != 1 {
		t.Errorf("expected exit code 1 for non-critical delete, got %d", result.ExitCode)
	}
	if result.MaxSeverity != rules.SeverityHigh {
		t.Errorf("expected HIGH, got %s", result.MaxSeverity)
	}
}

func TestAnalyze_Replace(t *testing.T) {
	analyzer := NewAnalyzer(nil)
	resources := []parser.NormalizedResource{
		{Address: "aws_instance.web", Type: "aws_instance", Action: "replace"},
	}

	result := analyzer.Analyze(resources)

	if result.Replaces != 1 {
		t.Errorf("expected 1 replace, got %d", result.Replaces)
	}
	if result.ExitCode != 1 {
		t.Errorf("expected exit code 1, got %d", result.ExitCode)
	}
}

func TestAnalyze_SecurityResourceDrift(t *testing.T) {
	analyzer := NewAnalyzer(nil)
	resources := []parser.NormalizedResource{
		{Address: "aws_iam_role.admin", Type: "aws_iam_role", Action: "update"},
	}

	result := analyzer.Analyze(resources)

	hasSec := false
	for _, f := range result.Findings {
		if f.RuleID == "DRIFT-SEC" {
			hasSec = true
		}
	}
	if !hasSec {
		t.Error("expected DRIFT-SEC finding for IAM role drift")
	}
}

func TestAnalyze_MixedChanges(t *testing.T) {
	analyzer := NewAnalyzer(nil)
	resources := []parser.NormalizedResource{
		{Address: "aws_instance.web", Type: "aws_instance", Action: "create"},
		{Address: "aws_instance.api", Type: "aws_instance", Action: "update"},
		{Address: "aws_s3_bucket.old", Type: "aws_s3_bucket", Action: "delete"},
		{Address: "aws_instance.db", Type: "aws_instance", Action: "no-op"},
	}

	result := analyzer.Analyze(resources)

	if result.TotalChanges != 3 {
		t.Errorf("expected 3 changes (no-op excluded), got %d", result.TotalChanges)
	}
	if result.Creates != 1 {
		t.Errorf("expected 1 create, got %d", result.Creates)
	}
	if result.Updates != 1 {
		t.Errorf("expected 1 update, got %d", result.Updates)
	}
	if result.Deletes != 1 {
		t.Errorf("expected 1 delete, got %d", result.Deletes)
	}
}

func TestAnalyze_CustomCriticalTypes(t *testing.T) {
	analyzer := NewAnalyzer([]string{"aws_instance"})
	resources := []parser.NormalizedResource{
		{Address: "aws_instance.web", Type: "aws_instance", Action: "delete"},
	}

	result := analyzer.Analyze(resources)

	if result.MaxSeverity != rules.SeverityCritical {
		t.Errorf("expected CRITICAL for custom critical type, got %s", result.MaxSeverity)
	}
	if result.ExitCode != 2 {
		t.Errorf("expected exit code 2, got %d", result.ExitCode)
	}
}

func TestAnalyze_AffectedTypes(t *testing.T) {
	analyzer := NewAnalyzer(nil)
	resources := []parser.NormalizedResource{
		{Address: "aws_instance.a", Type: "aws_instance", Action: "create"},
		{Address: "aws_instance.b", Type: "aws_instance", Action: "update"},
		{Address: "aws_s3_bucket.c", Type: "aws_s3_bucket", Action: "create"},
	}

	result := analyzer.Analyze(resources)

	if len(result.AffectedTypes) != 2 {
		t.Errorf("expected 2 affected types, got %d", len(result.AffectedTypes))
	}
}

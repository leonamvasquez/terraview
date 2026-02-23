package scanner

import (
	"errors"
	"testing"

	"github.com/leonamvasquez/terraview/internal/rules"
)

// ---------------------------------------------------------------------------
// Aggregate
// ---------------------------------------------------------------------------

func TestAggregate_Empty(t *testing.T) {
	result := Aggregate(nil)

	if len(result.Findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(result.Findings))
	}
	if result.TotalRaw != 0 {
		t.Errorf("expected TotalRaw 0, got %d", result.TotalRaw)
	}
	if result.TotalDeduped != 0 {
		t.Errorf("expected TotalDeduped 0, got %d", result.TotalDeduped)
	}
}

func TestAggregate_SingleScanner(t *testing.T) {
	results := []ScanResult{
		{
			Scanner: "checkov",
			Version: "2.5.0",
			Findings: []rules.Finding{
				{RuleID: "CKV_AWS_1", Severity: "HIGH", Resource: "aws_instance.web", Message: "Public SSH", Source: "scanner:checkov"},
				{RuleID: "CKV_AWS_2", Severity: "MEDIUM", Resource: "aws_s3_bucket.data", Message: "No encryption", Source: "scanner:checkov"},
			},
		},
	}

	agg := Aggregate(results)

	if len(agg.Findings) != 2 {
		t.Errorf("expected 2 findings, got %d", len(agg.Findings))
	}
	if agg.TotalRaw != 2 {
		t.Errorf("expected TotalRaw 2, got %d", agg.TotalRaw)
	}
	if len(agg.ScannersUsed) != 1 || agg.ScannersUsed[0] != "checkov" {
		t.Errorf("expected ScannersUsed [checkov], got %v", agg.ScannersUsed)
	}
	if len(agg.ScannersError) != 0 {
		t.Errorf("expected no scanner errors, got %v", agg.ScannersError)
	}
	// Should be sorted by severity: HIGH before MEDIUM
	if agg.Findings[0].Severity != "HIGH" {
		t.Errorf("expected first finding HIGH, got %s", agg.Findings[0].Severity)
	}
}

func TestAggregate_MultiScanner_WithDedup(t *testing.T) {
	results := []ScanResult{
		{
			Scanner: "checkov",
			Version: "2.5.0",
			Findings: []rules.Finding{
				{RuleID: "CKV_AWS_1", Severity: "MEDIUM", Resource: "aws_instance.web", Message: "encryption at rest not enabled", Source: "scanner:checkov"},
			},
		},
		{
			Scanner: "tfsec",
			Version: "1.0.0",
			Findings: []rules.Finding{
				{RuleID: "AVD-AWS-001", Severity: "HIGH", Resource: "aws_instance.web", Message: "encryption at rest not enabled", Source: "scanner:tfsec"},
			},
		},
	}

	agg := Aggregate(results)

	if agg.TotalRaw != 2 {
		t.Errorf("expected TotalRaw 2, got %d", agg.TotalRaw)
	}
	// Should be deduped to 1
	if agg.TotalDeduped != 1 {
		t.Errorf("expected TotalDeduped 1, got %d", agg.TotalDeduped)
	}
	// Should keep the higher severity (HIGH)
	if agg.Findings[0].Severity != "HIGH" {
		t.Errorf("expected merged finding to have HIGH severity, got %s", agg.Findings[0].Severity)
	}
	if len(agg.ScannersUsed) != 2 {
		t.Errorf("expected 2 scanners used, got %d", len(agg.ScannersUsed))
	}
}

func TestAggregate_WithErrors(t *testing.T) {
	results := []ScanResult{
		{
			Scanner: "checkov",
			Version: "2.5.0",
			Error:   errors.New("checkov not installed"),
		},
		{
			Scanner: "tfsec",
			Version: "1.0.0",
			Findings: []rules.Finding{
				{RuleID: "AVD-001", Severity: "LOW", Resource: "aws_s3.b", Message: "test", Source: "scanner:tfsec"},
			},
		},
	}

	agg := Aggregate(results)

	if len(agg.ScannersError) != 1 || agg.ScannersError[0] != "checkov" {
		t.Errorf("expected ScannersError [checkov], got %v", agg.ScannersError)
	}
	if len(agg.ScannersUsed) != 1 || agg.ScannersUsed[0] != "tfsec" {
		t.Errorf("expected ScannersUsed [tfsec], got %v", agg.ScannersUsed)
	}
	// Findings from errored scanner should not be included
	if len(agg.Findings) != 1 {
		t.Errorf("expected 1 finding (from tfsec only), got %d", len(agg.Findings))
	}
	// Stats should reflect both scanners
	if len(agg.ScannerStats) != 2 {
		t.Errorf("expected 2 stats entries, got %d", len(agg.ScannerStats))
	}
	// Check error stat
	for _, s := range agg.ScannerStats {
		if s.Name == "checkov" && s.Error == "" {
			t.Error("expected error string in checkov stat")
		}
	}
}

// ---------------------------------------------------------------------------
// FormatScannerHeader / FormatScannerHeaderBR
// ---------------------------------------------------------------------------

func TestFormatScannerHeader(t *testing.T) {
	agg := AggregatedResult{
		ScannerStats: []ScannerStat{
			{Name: "checkov", Findings: 3},
			{Name: "tfsec", Findings: 5},
		},
		TotalRaw:     10,
		TotalDeduped: 8,
	}

	header := FormatScannerHeader(agg)

	if header == "" {
		t.Fatal("expected non-empty header")
	}
	if !contains(header, "checkov (3 findings)") {
		t.Errorf("expected 'checkov (3 findings)' in header, got: %s", header)
	}
	if !contains(header, "tfsec (5 findings)") {
		t.Errorf("expected 'tfsec (5 findings)' in header, got: %s", header)
	}
	if !contains(header, "10 → 8 findings") {
		t.Errorf("expected dedup line, got: %s", header)
	}
}

func TestFormatScannerHeader_NoDedup(t *testing.T) {
	agg := AggregatedResult{
		ScannerStats: []ScannerStat{
			{Name: "checkov", Findings: 3},
		},
		TotalRaw:     3,
		TotalDeduped: 3,
	}

	header := FormatScannerHeader(agg)
	if contains(header, "Dedup") {
		t.Error("should not show dedup line when counts are equal")
	}
}

func TestFormatScannerHeader_WithError(t *testing.T) {
	agg := AggregatedResult{
		ScannerStats: []ScannerStat{
			{Name: "checkov", Error: "not found"},
		},
	}

	header := FormatScannerHeader(agg)
	if !contains(header, "checkov (error)") {
		t.Errorf("expected error indicator, got: %s", header)
	}
}

func TestFormatScannerHeaderBR(t *testing.T) {
	agg := AggregatedResult{
		ScannerStats: []ScannerStat{
			{Name: "checkov", Findings: 3},
		},
		TotalRaw:     5,
		TotalDeduped: 3,
	}

	header := FormatScannerHeaderBR(agg)
	if !contains(header, "3 achados") {
		t.Errorf("expected Portuguese 'achados', got: %s", header)
	}
	if !contains(header, "duplicados") {
		t.Errorf("expected Portuguese 'duplicados', got: %s", header)
	}
}

func TestFormatScannerHeaderBR_WithError(t *testing.T) {
	agg := AggregatedResult{
		ScannerStats: []ScannerStat{
			{Name: "tfsec", Error: "fail"},
		},
	}

	header := FormatScannerHeaderBR(agg)
	if !contains(header, "tfsec (erro)") {
		t.Errorf("expected 'erro' in Portuguese header, got: %s", header)
	}
}

// ---------------------------------------------------------------------------
// deduplicateFindings
// ---------------------------------------------------------------------------

func TestDeduplicateFindings_NoDuplicates(t *testing.T) {
	findings := []rules.Finding{
		{RuleID: "R1", Severity: "HIGH", Resource: "aws_instance.a", Message: "msg1", Source: "scanner:checkov"},
		{RuleID: "R2", Severity: "LOW", Resource: "aws_s3_bucket.b", Message: "msg2", Source: "scanner:tfsec"},
	}
	result := deduplicateFindings(findings)
	if len(result) != 2 {
		t.Errorf("expected 2 findings (no dedup), got %d", len(result))
	}
}

func TestDeduplicateFindings_CrossScannerMerge(t *testing.T) {
	findings := []rules.Finding{
		{RuleID: "R1", Severity: "MEDIUM", Resource: "aws_instance.a", Message: "encryption at rest not enabled for s3", Source: "scanner:checkov"},
		{RuleID: "R2", Severity: "HIGH", Resource: "aws_instance.a", Message: "encryption at rest not enabled for s3", Source: "scanner:tfsec", Remediation: "Enable encryption"},
	}
	result := deduplicateFindings(findings)
	if len(result) != 1 {
		t.Errorf("expected 1 deduped finding, got %d", len(result))
	}
	// Should keep higher severity
	if result[0].Severity != "HIGH" {
		t.Errorf("expected HIGH (kept higher), got %s", result[0].Severity)
	}
	// Should merge sources
	if !contains(result[0].Source, "checkov") || !contains(result[0].Source, "tfsec") {
		t.Errorf("expected merged source, got %s", result[0].Source)
	}
	// Should keep remediation from second finding
	if result[0].Remediation != "Enable encryption" {
		t.Errorf("expected remediation merged, got %q", result[0].Remediation)
	}
}

func TestDeduplicateFindings_Empty(t *testing.T) {
	result := deduplicateFindings(nil)
	if len(result) != 0 {
		t.Errorf("expected 0, got %d", len(result))
	}
}

// ---------------------------------------------------------------------------
// normalizeResource
// ---------------------------------------------------------------------------

func TestNormalizeResource(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"aws_instance.web", "aws_instance.web"},
		{"  aws_instance.web  ", "aws_instance.web"},
		{"AWS_Instance.Web", "aws_instance.web"},
		{"aws_instance.web:42", "aws_instance.web"},    // strip line number
		{"module.vpc:resource", "module.vpc:resource"}, // non-digit after colon → keep
	}
	for _, tt := range tests {
		if got := normalizeResource(tt.input); got != tt.want {
			t.Errorf("normalizeResource(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

// ---------------------------------------------------------------------------
// normalizeRuleID
// ---------------------------------------------------------------------------

func TestNormalizeRuleID(t *testing.T) {
	tests := []struct {
		ruleID  string
		message string
		want    string
	}{
		{"CKV_AWS_1", "encryption at rest not enabled for s3", "ENCRYPT_REST:s3"},
		{"AVD-001", "encryption in transit not configured for rds", "ENCRYPT_TRANSIT:rds"},
		{"R1", "public access to s3 bucket", "PUBLIC_ACCESS:s3"},
		{"R2", "SSH open to 0.0.0.0/0", "SSH_OPEN"},
		{"R3", "wildcard actions in iam policy", "IAM_WILDCARD"},
		{"R4", "logging is not enabled for cloudtrail", "LOGGING:cloudtrail"},
		{"CUSTOM_RULE", "some random message", "CUSTOM_RULE"}, // no mapping → uppercase
	}
	for _, tt := range tests {
		if got := normalizeRuleID(tt.ruleID, tt.message); got != tt.want {
			t.Errorf("normalizeRuleID(%q, %q) = %q, want %q", tt.ruleID, tt.message, got, tt.want)
		}
	}
}

// ---------------------------------------------------------------------------
// extractResourceType
// ---------------------------------------------------------------------------

func TestExtractResourceType(t *testing.T) {
	tests := []struct {
		msg  string
		want string
	}{
		{"s3 bucket has no encryption", "s3"},
		{"rds instance not encrypted", "rds"},
		{"iam policy with wildcard", "iam"},
		{"some unknown resource", "unknown"},
		{"elasticache cluster open", "elasticache"},
		{"lambda function no logging", "lambda"},
	}
	for _, tt := range tests {
		if got := extractResourceType(tt.msg); got != tt.want {
			t.Errorf("extractResourceType(%q) = %q, want %q", tt.msg, got, tt.want)
		}
	}
}

// ---------------------------------------------------------------------------
// extractScannerName
// ---------------------------------------------------------------------------

func TestExtractScannerName(t *testing.T) {
	tests := []struct {
		source string
		want   string
	}{
		{"scanner:checkov", "checkov"},
		{"scanner:tfsec", "tfsec"},
		{"external:sarif", "sarif"},
		{"just-name", "just-name"},
		{"", ""},
	}
	for _, tt := range tests {
		if got := extractScannerName(tt.source); got != tt.want {
			t.Errorf("extractScannerName(%q) = %q, want %q", tt.source, got, tt.want)
		}
	}
}

// ---------------------------------------------------------------------------
// severityRank
// ---------------------------------------------------------------------------

func TestSeverityRank(t *testing.T) {
	tests := []struct {
		sev  string
		want int
	}{
		{rules.SeverityCritical, 5},
		{rules.SeverityHigh, 4},
		{rules.SeverityMedium, 3},
		{rules.SeverityLow, 2},
		{rules.SeverityInfo, 1},
		{"UNKNOWN", 0},
		{"", 0},
	}
	for _, tt := range tests {
		if got := severityRank(tt.sev); got != tt.want {
			t.Errorf("severityRank(%q) = %d, want %d", tt.sev, got, tt.want)
		}
	}
}

// ---------------------------------------------------------------------------
// sortBySeverity
// ---------------------------------------------------------------------------

func TestSortBySeverity(t *testing.T) {
	findings := []rules.Finding{
		{Severity: "LOW", RuleID: "R1"},
		{Severity: "CRITICAL", RuleID: "R2"},
		{Severity: "MEDIUM", RuleID: "R3"},
		{Severity: "HIGH", RuleID: "R4"},
		{Severity: "INFO", RuleID: "R5"},
	}
	sortBySeverity(findings)

	expected := []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
	for i, sev := range expected {
		if findings[i].Severity != sev {
			t.Errorf("position %d: expected %s, got %s", i, sev, findings[i].Severity)
		}
	}
}

func TestSortBySeverity_StableOrder(t *testing.T) {
	findings := []rules.Finding{
		{Severity: "HIGH", RuleID: "first"},
		{Severity: "HIGH", RuleID: "second"},
	}
	sortBySeverity(findings)

	// Stable sort should preserve order of equal elements
	if findings[0].RuleID != "first" || findings[1].RuleID != "second" {
		t.Errorf("expected stable order, got %s then %s", findings[0].RuleID, findings[1].RuleID)
	}
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func contains(s, substr string) bool {
	return len(s) >= len(substr) && containsFn(s, substr)
}

func containsFn(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

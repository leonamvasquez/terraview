package rules

import (
	"testing"

	"github.com/leonamvasquez/terraview/internal/parser"
)

func TestGenericRule_MatchesTarget(t *testing.T) {
	rule := &GenericRule{
		definition: RuleDefinition{
			ID:       "TEST001",
			Targets:  []string{"aws_s3_bucket"},
			Severity: SeverityHigh,
			Category: CategorySecurity,
		},
	}

	if !rule.matchesTarget("aws_s3_bucket") {
		t.Error("expected rule to match aws_s3_bucket")
	}

	if rule.matchesTarget("aws_instance") {
		t.Error("expected rule to not match aws_instance")
	}
}

func TestGenericRule_WildcardTarget(t *testing.T) {
	rule := &GenericRule{
		definition: RuleDefinition{
			ID:      "TEST002",
			Targets: []string{"*"},
		},
	}

	if !rule.matchesTarget("aws_anything") {
		t.Error("expected wildcard to match any resource type")
	}
}

func TestGenericRule_EmptyTargets(t *testing.T) {
	rule := &GenericRule{
		definition: RuleDefinition{
			ID:      "TEST003",
			Targets: []string{},
		},
	}

	if !rule.matchesTarget("aws_anything") {
		t.Error("expected empty targets to match any resource type")
	}
}

func TestEvaluateCondition_Equals(t *testing.T) {
	resource := parser.NormalizedResource{
		Values: map[string]interface{}{
			"publicly_accessible": "true",
		},
	}

	cond := Condition{Field: "publicly_accessible", Operator: "equals", Value: "true"}
	if !evaluateCondition(cond, resource) {
		t.Error("expected equals condition to match")
	}

	cond = Condition{Field: "publicly_accessible", Operator: "equals", Value: "false"}
	if evaluateCondition(cond, resource) {
		t.Error("expected equals condition to not match")
	}
}

func TestEvaluateCondition_Contains(t *testing.T) {
	resource := parser.NormalizedResource{
		Values: map[string]interface{}{
			"policy": `{"Action":"*","Resource":"*"}`,
		},
	}

	cond := Condition{Field: "policy", Operator: "contains", Value: `"Action":"*"`}
	if !evaluateCondition(cond, resource) {
		t.Error("expected contains condition to match")
	}
}

func TestEvaluateCondition_Exists(t *testing.T) {
	resource := parser.NormalizedResource{
		Values: map[string]interface{}{
			"encryption": map[string]interface{}{"enabled": true},
		},
	}

	cond := Condition{Field: "encryption", Operator: "exists"}
	if !evaluateCondition(cond, resource) {
		t.Error("expected exists condition to match for present field")
	}

	cond = Condition{Field: "missing_field", Operator: "exists"}
	if evaluateCondition(cond, resource) {
		t.Error("expected exists condition to not match for missing field")
	}
}

func TestEvaluateCondition_NotExists(t *testing.T) {
	resource := parser.NormalizedResource{
		Values: map[string]interface{}{},
	}

	cond := Condition{Field: "server_side_encryption_configuration", Operator: "not_exists"}
	if !evaluateCondition(cond, resource) {
		t.Error("expected not_exists to match for missing field")
	}
}

func TestEvaluateCondition_IsTrueAndIsFalse(t *testing.T) {
	resource := parser.NormalizedResource{
		Values: map[string]interface{}{
			"multi_az":            false,
			"publicly_accessible": true,
		},
	}

	cond := Condition{Field: "multi_az", Operator: "is_false"}
	if !evaluateCondition(cond, resource) {
		t.Error("expected is_false to match for false value")
	}

	cond = Condition{Field: "publicly_accessible", Operator: "is_true"}
	if !evaluateCondition(cond, resource) {
		t.Error("expected is_true to match for true value")
	}
}

func TestEvaluateCondition_IsAction(t *testing.T) {
	resource := parser.NormalizedResource{
		Action: "delete",
		Values: map[string]interface{}{},
	}

	cond := Condition{Field: "", Operator: "is_action", Value: "delete"}
	if !evaluateCondition(cond, resource) {
		t.Error("expected is_action to match delete")
	}
}

func TestGetNestedValue(t *testing.T) {
	values := map[string]interface{}{
		"level1": map[string]interface{}{
			"level2": map[string]interface{}{
				"value": "deep",
			},
		},
		"flat": "top",
	}

	if v := getNestedValue(values, "flat"); v != "top" {
		t.Errorf("expected 'top', got %v", v)
	}

	if v := getNestedValue(values, "level1.level2.value"); v != "deep" {
		t.Errorf("expected 'deep', got %v", v)
	}

	if v := getNestedValue(values, "nonexistent.path"); v != nil {
		t.Errorf("expected nil, got %v", v)
	}
}

func TestTagRule_MissingTags(t *testing.T) {
	rule := &TagRule{requiredTags: []string{"Environment", "Team", "Project", "ManagedBy"}}

	resource := parser.NormalizedResource{
		Address: "aws_instance.test",
		Action:  "create",
		Values: map[string]interface{}{
			"tags": map[string]interface{}{
				"Environment": "production",
				"Project":     "myapp",
			},
		},
	}

	findings := rule.Evaluate(resource, nil)
	if len(findings) != 2 {
		t.Errorf("expected 2 missing tag findings, got %d", len(findings))
	}

	// Check that Team and ManagedBy are the missing ones
	foundTeam := false
	foundManagedBy := false
	for _, f := range findings {
		if f.Message == "Resource is missing required tag: Team" {
			foundTeam = true
		}
		if f.Message == "Resource is missing required tag: ManagedBy" {
			foundManagedBy = true
		}
	}
	if !foundTeam {
		t.Error("expected finding for missing Team tag")
	}
	if !foundManagedBy {
		t.Error("expected finding for missing ManagedBy tag")
	}
}

func TestTagRule_AllTagsPresent(t *testing.T) {
	rule := &TagRule{requiredTags: []string{"Environment"}}

	resource := parser.NormalizedResource{
		Address: "aws_instance.test",
		Action:  "create",
		Values: map[string]interface{}{
			"tags": map[string]interface{}{
				"Environment": "production",
			},
		},
	}

	findings := rule.Evaluate(resource, nil)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(findings))
	}
}

func TestTagRule_SkipsDeleteAction(t *testing.T) {
	rule := &TagRule{requiredTags: []string{"Environment"}}

	resource := parser.NormalizedResource{
		Address: "aws_instance.test",
		Action:  "delete",
		Values:  map[string]interface{}{},
	}

	findings := rule.Evaluate(resource, nil)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for delete action, got %d", len(findings))
	}
}

func TestCriticalDeletionRule_DeleteCriticalResource(t *testing.T) {
	rule := &CriticalDeletionRule{
		criticalTypes: []string{"aws_db_instance", "aws_s3_bucket"},
	}

	resource := parser.NormalizedResource{
		Address: "aws_db_instance.main",
		Type:    "aws_db_instance",
		Action:  "delete",
		Values:  map[string]interface{}{},
	}

	findings := rule.Evaluate(resource, nil)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	if findings[0].Severity != SeverityHigh {
		t.Errorf("expected HIGH severity, got %s", findings[0].Severity)
	}
}

func TestCriticalDeletionRule_CreateNonCritical(t *testing.T) {
	rule := &CriticalDeletionRule{
		criticalTypes: []string{"aws_db_instance"},
	}

	resource := parser.NormalizedResource{
		Address: "aws_instance.web",
		Type:    "aws_instance",
		Action:  "create",
		Values:  map[string]interface{}{},
	}

	findings := rule.Evaluate(resource, nil)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(findings))
	}
}

func TestEngine_Evaluate_Integration(t *testing.T) {
	config := RulesConfig{
		Version:      "1.0",
		RequiredTags: []string{"Environment"},
		CriticalResourceTypes: []string{"aws_db_instance"},
		Rules: []RuleDefinition{
			{
				ID:          "SEC005",
				Name:        "RDS Publicly Accessible",
				Description: "RDS instance is publicly accessible",
				Severity:    SeverityHigh,
				Category:    CategorySecurity,
				Enabled:     true,
				Targets:     []string{"aws_db_instance"},
				Conditions: []Condition{
					{Field: "publicly_accessible", Operator: "is_true"},
				},
			},
		},
	}

	engine := NewEngineFromConfig(config)

	resources := []parser.NormalizedResource{
		{
			Address: "aws_db_instance.main",
			Type:    "aws_db_instance",
			Action:  "create",
			Values: map[string]interface{}{
				"publicly_accessible": true,
				"tags": map[string]interface{}{
					"Environment": "production",
				},
			},
		},
	}

	findings := engine.Evaluate(resources)

	// Should find: publicly_accessible = true
	foundPublicRDS := false
	for _, f := range findings {
		if f.RuleID == "SEC005" {
			foundPublicRDS = true
		}
	}

	if !foundPublicRDS {
		t.Error("expected finding for publicly accessible RDS")
	}
}

func TestEngine_Evaluate_S3NoEncryption(t *testing.T) {
	config := RulesConfig{
		Version: "1.0",
		Rules: []RuleDefinition{
			{
				ID:          "SEC002",
				Name:        "S3 Without Encryption",
				Description: "S3 bucket missing encryption",
				Severity:    SeverityHigh,
				Category:    CategorySecurity,
				Enabled:     true,
				Targets:     []string{"aws_s3_bucket"},
				Conditions: []Condition{
					{Field: "server_side_encryption_configuration", Operator: "not_exists"},
				},
			},
		},
	}

	engine := NewEngineFromConfig(config)

	resources := []parser.NormalizedResource{
		{
			Address: "aws_s3_bucket.data",
			Type:    "aws_s3_bucket",
			Action:  "create",
			Values: map[string]interface{}{
				"bucket": "test-bucket",
			},
		},
	}

	findings := engine.Evaluate(resources)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	if findings[0].RuleID != "SEC002" {
		t.Errorf("expected SEC002, got %s", findings[0].RuleID)
	}
}

func TestEngine_Evaluate_IAMWildcard(t *testing.T) {
	config := RulesConfig{
		Version: "1.0",
		Rules: []RuleDefinition{
			{
				ID:          "SEC003",
				Name:        "IAM Wildcard",
				Description: "IAM policy uses wildcard",
				Severity:    SeverityCritical,
				Category:    CategorySecurity,
				Enabled:     true,
				Targets:     []string{"aws_iam_role_policy"},
				Conditions: []Condition{
					{Field: "policy", Operator: "contains", Value: `"Action":"*"`},
				},
			},
		},
	}

	engine := NewEngineFromConfig(config)

	resources := []parser.NormalizedResource{
		{
			Address: "aws_iam_role_policy.admin",
			Type:    "aws_iam_role_policy",
			Action:  "create",
			Values: map[string]interface{}{
				"policy": `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`,
			},
		},
	}

	findings := engine.Evaluate(resources)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	if findings[0].Severity != SeverityCritical {
		t.Errorf("expected CRITICAL severity, got %s", findings[0].Severity)
	}
}

func TestEngine_DisabledRulesSkipped(t *testing.T) {
	config := RulesConfig{
		Version: "1.0",
		Rules: []RuleDefinition{
			{
				ID:          "DISABLED001",
				Description: "This rule is disabled",
				Severity:    SeverityHigh,
				Category:    CategorySecurity,
				Enabled:     false,
				Targets:     []string{"*"},
				Conditions: []Condition{
					{Field: "anything", Operator: "exists"},
				},
			},
		},
	}

	engine := NewEngineFromConfig(config)
	resources := []parser.NormalizedResource{
		{
			Address: "aws_instance.test",
			Type:    "aws_instance",
			Action:  "create",
			Values:  map[string]interface{}{"anything": true},
		},
	}

	findings := engine.Evaluate(resources)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for disabled rule, got %d", len(findings))
	}
}

// ============================================================
// Bug 1 Tests: contains_in_list with nested objects
// ============================================================

func TestListContainsValue_NestedIngress(t *testing.T) {
	// Simulates a Security Group with ingress rules containing cidr_blocks
	ingress := []interface{}{
		map[string]interface{}{
			"from_port": 22,
			"to_port":   22,
			"protocol":  "tcp",
			"cidr_blocks": []interface{}{
				"0.0.0.0/0",
			},
		},
	}

	if !listContainsValue(ingress, "0.0.0.0/0") {
		t.Error("expected listContainsValue to find 0.0.0.0/0 inside nested ingress objects")
	}
}

func TestListContainsValue_NestedIngress_NoMatch(t *testing.T) {
	ingress := []interface{}{
		map[string]interface{}{
			"from_port": 22,
			"to_port":   22,
			"protocol":  "tcp",
			"cidr_blocks": []interface{}{
				"10.0.0.0/8",
			},
		},
	}

	if listContainsValue(ingress, "0.0.0.0/0") {
		t.Error("expected listContainsValue to NOT find 0.0.0.0/0 when only 10.0.0.0/8 present")
	}
}

func TestListContainsValue_FlatArray(t *testing.T) {
	// Must still work for simple flat arrays
	flat := []interface{}{"0.0.0.0/0", "10.0.0.0/8"}

	if !listContainsValue(flat, "0.0.0.0/0") {
		t.Error("expected listContainsValue to find 0.0.0.0/0 in flat array")
	}
}

func TestListContainsValue_MultipleIngressRules(t *testing.T) {
	ingress := []interface{}{
		map[string]interface{}{
			"from_port": 443,
			"to_port":   443,
			"protocol":  "tcp",
			"cidr_blocks": []interface{}{
				"10.0.0.0/8",
			},
		},
		map[string]interface{}{
			"from_port": 22,
			"to_port":   22,
			"protocol":  "tcp",
			"cidr_blocks": []interface{}{
				"0.0.0.0/0",
			},
		},
	}

	if !listContainsValue(ingress, "0.0.0.0/0") {
		t.Error("expected listContainsValue to find 0.0.0.0/0 in second ingress rule")
	}
}

func TestEngine_SEC001_NestedIngress(t *testing.T) {
	config := RulesConfig{
		Version: "1.0",
		Rules: []RuleDefinition{
			{
				ID:          "SEC001",
				Name:        "SSH Open to Internet",
				Description: "Security group allows SSH from 0.0.0.0/0",
				Severity:    SeverityHigh,
				Category:    CategorySecurity,
				Enabled:     true,
				Targets:     []string{"aws_security_group"},
				Conditions: []Condition{
					{Field: "ingress", Operator: "contains_in_list", Value: "0.0.0.0/0"},
				},
			},
		},
	}

	engine := NewEngineFromConfig(config)

	resources := []parser.NormalizedResource{
		{
			Address: "aws_security_group.web",
			Type:    "aws_security_group",
			Action:  "create",
			Values: map[string]interface{}{
				"ingress": []interface{}{
					map[string]interface{}{
						"from_port": 22,
						"to_port":   22,
						"protocol":  "tcp",
						"cidr_blocks": []interface{}{
							"0.0.0.0/0",
						},
					},
				},
			},
		},
	}

	findings := engine.Evaluate(resources)
	if len(findings) != 1 {
		t.Fatalf("expected 1 SEC001 finding, got %d", len(findings))
	}
	if findings[0].RuleID != "SEC001" {
		t.Errorf("expected SEC001, got %s", findings[0].RuleID)
	}
}

// ============================================================
// Bug 2 Tests: Companion resource excludes
// ============================================================

func TestEngine_SEC002_SuppressedByCompanion(t *testing.T) {
	config := RulesConfig{
		Version: "1.0",
		Rules: []RuleDefinition{
			{
				ID:          "SEC002",
				Name:        "S3 Without Encryption",
				Description: "S3 bucket missing encryption",
				Severity:    SeverityHigh,
				Category:    CategorySecurity,
				Enabled:     true,
				Targets:     []string{"aws_s3_bucket"},
				Conditions: []Condition{
					{Field: "server_side_encryption_configuration", Operator: "not_exists"},
				},
				CompanionExcludes: []CompanionExclude{
					{ResourceType: "aws_s3_bucket_server_side_encryption_configuration", NameField: "bucket"},
				},
			},
		},
	}

	engine := NewEngineFromConfig(config)

	resources := []parser.NormalizedResource{
		{
			Address: "aws_s3_bucket.data",
			Type:    "aws_s3_bucket",
			Name:    "data",
			Action:  "create",
			Values: map[string]interface{}{
				"bucket": "my-data-bucket",
			},
		},
		{
			Address: "aws_s3_bucket_server_side_encryption_configuration.data",
			Type:    "aws_s3_bucket_server_side_encryption_configuration",
			Name:    "data",
			Action:  "create",
			Values: map[string]interface{}{
				"bucket": "my-data-bucket",
			},
		},
	}

	findings := engine.Evaluate(resources)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings when companion encryption resource exists, got %d", len(findings))
		for _, f := range findings {
			t.Logf("  finding: %s - %s", f.RuleID, f.Message)
		}
	}
}

func TestEngine_SEC002_NotSuppressedWithoutCompanion(t *testing.T) {
	config := RulesConfig{
		Version: "1.0",
		Rules: []RuleDefinition{
			{
				ID:          "SEC002",
				Name:        "S3 Without Encryption",
				Description: "S3 bucket missing encryption",
				Severity:    SeverityHigh,
				Category:    CategorySecurity,
				Enabled:     true,
				Targets:     []string{"aws_s3_bucket"},
				Conditions: []Condition{
					{Field: "server_side_encryption_configuration", Operator: "not_exists"},
				},
				CompanionExcludes: []CompanionExclude{
					{ResourceType: "aws_s3_bucket_server_side_encryption_configuration", NameField: "bucket"},
				},
			},
		},
	}

	engine := NewEngineFromConfig(config)

	resources := []parser.NormalizedResource{
		{
			Address: "aws_s3_bucket.data",
			Type:    "aws_s3_bucket",
			Name:    "data",
			Action:  "create",
			Values: map[string]interface{}{
				"bucket": "my-data-bucket",
			},
		},
	}

	findings := engine.Evaluate(resources)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding when no companion resource, got %d", len(findings))
	}
	if findings[0].RuleID != "SEC002" {
		t.Errorf("expected SEC002, got %s", findings[0].RuleID)
	}
}

func TestEngine_BP001_SuppressedByCompanion(t *testing.T) {
	config := RulesConfig{
		Version: "1.0",
		Rules: []RuleDefinition{
			{
				ID:          "BP001",
				Name:        "S3 Without Versioning",
				Description: "S3 bucket without versioning",
				Severity:    SeverityMedium,
				Category:    CategoryBestPractice,
				Enabled:     true,
				Targets:     []string{"aws_s3_bucket"},
				Conditions: []Condition{
					{Field: "versioning", Operator: "not_exists"},
				},
				CompanionExcludes: []CompanionExclude{
					{ResourceType: "aws_s3_bucket_versioning", NameField: "bucket"},
				},
			},
		},
	}

	engine := NewEngineFromConfig(config)

	resources := []parser.NormalizedResource{
		{
			Address: "aws_s3_bucket.logs",
			Type:    "aws_s3_bucket",
			Name:    "logs",
			Action:  "create",
			Values: map[string]interface{}{
				"bucket": "my-logs-bucket",
			},
		},
		{
			Address: "aws_s3_bucket_versioning.logs",
			Type:    "aws_s3_bucket_versioning",
			Name:    "logs",
			Action:  "create",
			Values: map[string]interface{}{
				"bucket": "my-logs-bucket",
			},
		},
	}

	findings := engine.Evaluate(resources)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings when companion versioning resource exists, got %d", len(findings))
	}
}

// ============================================================
// Bug 3 Tests: TAG001 for resources without tags field
// ============================================================

func TestTagRule_NoTagsField_TaggableResource(t *testing.T) {
	rule := &TagRule{
		requiredTags:  []string{"Environment", "Team"},
		taggableTypes: map[string]bool{"aws_instance": true, "aws_s3_bucket": true},
	}

	resource := parser.NormalizedResource{
		Address: "aws_instance.web",
		Type:    "aws_instance",
		Action:  "create",
		Values:  map[string]interface{}{
			"ami": "ami-12345",
		},
	}

	findings := rule.Evaluate(resource, nil)
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings for taggable resource without tags, got %d", len(findings))
	}
}

func TestTagRule_NoTagsField_NonTaggableResource(t *testing.T) {
	rule := &TagRule{
		requiredTags:  []string{"Environment"},
		taggableTypes: map[string]bool{"aws_instance": true},
	}

	resource := parser.NormalizedResource{
		Address: "aws_iam_role_policy.admin",
		Type:    "aws_iam_role_policy",
		Action:  "create",
		Values:  map[string]interface{}{
			"policy": "{}",
		},
	}

	findings := rule.Evaluate(resource, nil)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for non-taggable resource without tags, got %d", len(findings))
	}
}

func TestTagRule_FallbackHeuristic_NoTaggableTypesConfigured(t *testing.T) {
	// When no taggable types are configured, fallback to aws_ prefix heuristic
	rule := &TagRule{
		requiredTags:  []string{"Environment"},
		taggableTypes: map[string]bool{},
	}

	resource := parser.NormalizedResource{
		Address: "aws_instance.web",
		Type:    "aws_instance",
		Action:  "create",
		Values:  map[string]interface{}{},
	}

	findings := rule.Evaluate(resource, nil)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for aws_ resource with fallback heuristic, got %d", len(findings))
	}
}

func TestEngine_SEC002_SuppressedByCompanion_BucketFieldUnknown(t *testing.T) {
	// Simulates real plan.json where companion resource has bucket in after_unknown (nil in after)
	config := RulesConfig{
		Version: "1.0",
		Rules: []RuleDefinition{
			{
				ID:          "SEC002",
				Name:        "S3 Without Encryption",
				Description: "S3 bucket missing encryption",
				Severity:    SeverityHigh,
				Category:    CategorySecurity,
				Enabled:     true,
				Targets:     []string{"aws_s3_bucket"},
				Conditions: []Condition{
					{Field: "server_side_encryption_configuration", Operator: "not_exists"},
				},
				CompanionExcludes: []CompanionExclude{
					{ResourceType: "aws_s3_bucket_server_side_encryption_configuration", NameField: "bucket"},
				},
			},
		},
	}

	engine := NewEngineFromConfig(config)

	// Companion resource has no "bucket" field in Values (it's after_unknown in real plans)
	resources := []parser.NormalizedResource{
		{
			Address: "aws_s3_bucket.compliant",
			Type:    "aws_s3_bucket",
			Name:    "compliant",
			Action:  "create",
			Values: map[string]interface{}{
				"force_destroy": false,
				"tags":          map[string]interface{}{"Environment": "production"},
			},
		},
		{
			Address: "aws_s3_bucket_server_side_encryption_configuration.compliant",
			Type:    "aws_s3_bucket_server_side_encryption_configuration",
			Name:    "compliant",
			Action:  "create",
			Values: map[string]interface{}{
				// "bucket" is absent — it's in after_unknown in real plans
				"expected_bucket_owner": nil,
			},
		},
	}

	findings := engine.Evaluate(resources)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings when companion has same name (bucket field unknown), got %d", len(findings))
		for _, f := range findings {
			t.Logf("  finding: %s - %s", f.RuleID, f.Message)
		}
	}
}

func TestEngine_TAG001_Integration_NoTagsField(t *testing.T) {
	config := RulesConfig{
		Version:               "1.0",
		RequiredTags:          []string{"Environment", "Team"},
		TaggableResourceTypes: []string{"aws_instance", "aws_s3_bucket"},
		Rules:                 []RuleDefinition{},
	}

	engine := NewEngineFromConfig(config)

	resources := []parser.NormalizedResource{
		{
			Address: "aws_instance.web",
			Type:    "aws_instance",
			Action:  "create",
			Values:  map[string]interface{}{
				"ami": "ami-12345",
			},
		},
	}

	findings := engine.Evaluate(resources)
	if len(findings) != 2 {
		t.Fatalf("expected 2 TAG001 findings, got %d", len(findings))
	}
	for _, f := range findings {
		if f.RuleID != "TAG001" {
			t.Errorf("expected TAG001, got %s", f.RuleID)
		}
	}
}

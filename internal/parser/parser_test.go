package parser

import (
	"encoding/json"
	"testing"
)

func TestParse_ValidPlan(t *testing.T) {
	plan := buildTestPlan()
	data, err := json.Marshal(plan)
	if err != nil {
		t.Fatalf("failed to marshal test plan: %v", err)
	}

	p := NewParser()
	result, err := p.Parse(data)
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}

	if result.FormatVersion != "1.2" {
		t.Errorf("expected format_version 1.2, got %s", result.FormatVersion)
	}

	if len(result.ResourceChanges) != 3 {
		t.Errorf("expected 3 resource changes, got %d", len(result.ResourceChanges))
	}
}

func TestParse_EmptyPlan(t *testing.T) {
	p := NewParser()
	_, err := p.Parse([]byte(`{"format_version": "1.2", "resource_changes": []}`))
	if err == nil {
		t.Error("expected error for empty resource_changes, got nil")
	}
}

func TestParse_InvalidJSON(t *testing.T) {
	p := NewParser()
	_, err := p.Parse([]byte(`{invalid json`))
	if err == nil {
		t.Error("expected error for invalid JSON, got nil")
	}
}

func TestNormalizeResources(t *testing.T) {
	plan := buildTestPlan()
	p := NewParser()

	resources := p.NormalizeResources(plan)

	if len(resources) != 3 {
		t.Fatalf("expected 3 normalized resources, got %d", len(resources))
	}

	// First resource: create action
	if resources[0].Action != "create" {
		t.Errorf("expected action 'create', got '%s'", resources[0].Action)
	}
	if resources[0].Type != "aws_s3_bucket" {
		t.Errorf("expected type 'aws_s3_bucket', got '%s'", resources[0].Type)
	}
	if resources[0].Provider != "aws" {
		t.Errorf("expected provider 'aws', got '%s'", resources[0].Provider)
	}
	if resources[0].Address != "aws_s3_bucket.data" {
		t.Errorf("expected address 'aws_s3_bucket.data', got '%s'", resources[0].Address)
	}

	// Second resource: delete action
	if resources[1].Action != "delete" {
		t.Errorf("expected action 'delete', got '%s'", resources[1].Action)
	}

	// Third resource: replace action
	if resources[2].Action != "replace" {
		t.Errorf("expected action 'replace', got '%s'", resources[2].Action)
	}
}

func TestNormalizeAction(t *testing.T) {
	tests := []struct {
		name     string
		actions  []string
		expected string
	}{
		{"create", []string{"create"}, "create"},
		{"delete", []string{"delete"}, "delete"},
		{"read", []string{"read"}, "read"},
		{"no-op", []string{"no-op"}, "no-op"},
		{"replace create-delete", []string{"create", "delete"}, "replace"},
		{"replace delete-create", []string{"delete", "create"}, "replace"},
		{"update", []string{"update"}, "update"},
		{"empty", []string{}, "no-op"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := normalizeAction(tt.actions)
			if result != tt.expected {
				t.Errorf("normalizeAction(%v) = %s, want %s", tt.actions, result, tt.expected)
			}
		})
	}
}

func TestExtractProvider(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"registry.terraform.io/hashicorp/aws", "aws"},
		{"registry.terraform.io/hashicorp/google", "google"},
		{"aws", "aws"},
		{"", ""},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := extractProvider(tt.input)
			if result != tt.expected {
				t.Errorf("extractProvider(%s) = %s, want %s", tt.input, result, tt.expected)
			}
		})
	}
}

func TestExtractResourceSummary(t *testing.T) {
	plan := buildTestPlan()
	p := NewParser()
	resources := p.NormalizeResources(plan)
	summary := p.ExtractResourceSummary(resources)

	total, ok := summary["total_resources"].(int)
	if !ok || total != 3 {
		t.Errorf("expected total_resources=3, got %v", summary["total_resources"])
	}

	actions, ok := summary["actions"].(map[string]int)
	if !ok {
		t.Fatal("actions not found in summary")
	}
	if actions["create"] != 1 {
		t.Errorf("expected 1 create action, got %d", actions["create"])
	}
	if actions["delete"] != 1 {
		t.Errorf("expected 1 delete action, got %d", actions["delete"])
	}
}

func buildTestPlan() *TerraformPlan {
	return &TerraformPlan{
		FormatVersion:    "1.2",
		TerraformVersion: "1.7.0",
		ResourceChanges: []ResourceChange{
			{
				Address:      "aws_s3_bucket.data",
				Mode:         "managed",
				Type:         "aws_s3_bucket",
				Name:         "data",
				ProviderName: "registry.terraform.io/hashicorp/aws",
				Change: Change{
					Actions: []string{"create"},
					Before:  nil,
					After: map[string]interface{}{
						"bucket": "test-bucket",
						"tags": map[string]interface{}{
							"Environment": "test",
						},
					},
				},
			},
			{
				Address:      "aws_instance.old",
				Mode:         "managed",
				Type:         "aws_instance",
				Name:         "old",
				ProviderName: "registry.terraform.io/hashicorp/aws",
				Change: Change{
					Actions: []string{"delete"},
					Before: map[string]interface{}{
						"instance_type": "t3.micro",
					},
					After: nil,
				},
			},
			{
				Address:      "aws_security_group.web",
				Mode:         "managed",
				Type:         "aws_security_group",
				Name:         "web",
				ProviderName: "registry.terraform.io/hashicorp/aws",
				Change: Change{
					Actions: []string{"delete", "create"},
					Before: map[string]interface{}{
						"name": "old-sg",
					},
					After: map[string]interface{}{
						"name": "new-sg",
						"ingress": []interface{}{
							map[string]interface{}{
								"from_port":   float64(22),
								"to_port":     float64(22),
								"protocol":    "tcp",
								"cidr_blocks": []interface{}{"0.0.0.0/0"},
							},
						},
					},
				},
			},
		},
	}
}

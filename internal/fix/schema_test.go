package fix

import (
	"strings"
	"testing"
)

func TestExtractTopLevelAttrs(t *testing.T) {
	hcl := `resource "aws_lb" "x" {
  name               = "my-lb"
  internal           = false
  load_balancer_type = "application"
  subnets            = ["subnet-1", "subnet-2"]
  access_logs {
    bucket  = "logs"
    enabled = true
  }
  # comment_attr = "ignored"
  tags = {
    Name = "my-lb"
  }
}`
	got := extractTopLevelAttrs(hcl)
	want := map[string]bool{
		"name": true, "internal": true, "load_balancer_type": true,
		"subnets": true, "access_logs": true, "tags": true,
	}
	if len(got) != len(want) {
		t.Fatalf("got %d attrs (%v), want %d (%v)", len(got), got, len(want), want)
	}
	for _, a := range got {
		if !want[a] {
			t.Errorf("unexpected attr %q", a)
		}
	}
}

func TestValidateAttributes(t *testing.T) {
	tests := []struct {
		name         string
		hcl          string
		resourceType string
		wantErr      bool
		errContains  string
	}{
		{
			"unknown type — permissive",
			`resource "aws_some_new_thing" "x" {
  whatever = true
}`,
			"aws_some_new_thing",
			false,
			"",
		},
		{
			"valid aws_lb",
			`resource "aws_lb" "x" {
  name = "lb"
  internal = false
  subnets = ["a"]
}`,
			"aws_lb",
			false,
			"",
		},
		{
			"hallucinated web_acl_arn on aws_lb",
			`resource "aws_lb" "x" {
  name = "lb"
  web_acl_arn = "arn:aws:wafv2:..."
}`,
			"aws_lb",
			true,
			"web_acl_arn",
		},
		{
			"hallucinated invalid attribute on aws_s3_bucket",
			`resource "aws_s3_bucket" "x" {
  bucket = "b"
  some_invented_attr = "foo"
}`,
			"aws_s3_bucket",
			true,
			"some_invented_attr",
		},
		{
			"valid aws_kms_key with rotation",
			`resource "aws_kms_key" "k" {
  description         = "logs"
  enable_key_rotation = true
  deletion_window_in_days = 30
}`,
			"aws_kms_key",
			false,
			"",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateAttributes(tc.hcl, tc.resourceType)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil\nHCL:\n%s", tc.hcl)
				}
				if !strings.Contains(err.Error(), tc.errContains) {
					t.Errorf("error %q should mention %q", err, tc.errContains)
				}
			} else if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestExtractResourceTypeFromHCL(t *testing.T) {
	tests := []struct {
		hcl, want string
	}{
		{`resource "aws_lb" "x" {`, "aws_lb"},
		{`  resource "aws_kms_key" "k" {` + "\n  enable_key_rotation = true\n}", "aws_kms_key"},
		{`# comment only`, ""},
		{`resource only`, ""},
	}
	for _, tc := range tests {
		got := extractResourceTypeFromHCL(tc.hcl)
		if got != tc.want {
			t.Errorf("extractResourceTypeFromHCL(%q) = %q, want %q", tc.hcl, got, tc.want)
		}
	}
}

func TestKnownAttributes(t *testing.T) {
	if attrs := KnownAttributes("aws_lb"); len(attrs) == 0 {
		t.Error("aws_lb should be in schema")
	}
	if attrs := KnownAttributes("aws_unknown_resource_xyz"); attrs != nil {
		t.Errorf("unknown type should return nil, got %v", attrs)
	}
}

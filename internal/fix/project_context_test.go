package fix

import (
	"os"
	"path/filepath"
	"testing"
)

func TestBuildProjectContext_AggregatesAllDeclarations(t *testing.T) {
	dir := t.TempDir()

	files := map[string]string{
		"versions.tf": `terraform {
  required_providers {
    aws    = { source = "hashicorp/aws", version = "~> 5.0" }
    random = { source = "hashicorp/random", version = "~> 3.0" }
  }
}

provider "aws" {
  region = "us-east-1"
}

data "aws_caller_identity" "current" {}
`,
		"variables.tf": `variable "environment" {
  type    = string
  default = "prod"
}

variable "region" {
  type = string
}
`,
		"main.tf": `locals {
  project_name = "demo"
  team         = "platform"
}

resource "aws_kms_key" "main" {
  description = "main"
}

resource "aws_kms_key" "logs" {
  description = "logs"
}

resource "aws_s3_bucket" "data" {
  bucket = "demo"
}
`,
		// Should be ignored — sub-directories are not recursed.
		"modules/vpc/main.tf": `resource "aws_vpc" "should_be_ignored" { cidr_block = "10.0.0.0/16" }`,
		// Should be ignored — non-.tf file.
		"README.md": "ignore me",
	}
	for name, content := range files {
		full := filepath.Join(dir, name)
		_ = os.MkdirAll(filepath.Dir(full), 0o755)
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	pc := BuildProjectContext(dir)

	wantContains := func(slice []string, want string, label string) {
		t.Helper()
		for _, v := range slice {
			if v == want {
				return
			}
		}
		t.Errorf("%s: missing %q (got %v)", label, want, slice)
	}
	wantNotContains := func(slice []string, unwanted string, label string) {
		t.Helper()
		for _, v := range slice {
			if v == unwanted {
				t.Errorf("%s: unexpectedly contains %q", label, unwanted)
			}
		}
	}

	wantContains(pc.Providers, "aws", "providers")
	wantContains(pc.Providers, "random", "providers")

	wantContains(pc.Variables, "environment", "variables")
	wantContains(pc.Variables, "region", "variables")

	wantContains(pc.DataSources, "data.aws_caller_identity.current", "data_sources")

	wantContains(pc.Locals, "project_name", "locals")
	wantContains(pc.Locals, "team", "locals")

	if got := pc.ResourcesByType["aws_kms_key"]; len(got) != 2 {
		t.Errorf("aws_kms_key: want 2 entries, got %v", got)
	}
	wantContains(pc.ResourcesByType["aws_s3_bucket"], "aws_s3_bucket.data", "resources_by_type[aws_s3_bucket]")

	// Sub-directory file must NOT bleed in.
	if _, ok := pc.ResourcesByType["aws_vpc"]; ok {
		t.Error("expected sub-directory aws_vpc to be ignored, but it was indexed")
	}
	wantNotContains(pc.ResourcesByType["aws_vpc"], "aws_vpc.should_be_ignored", "resources_by_type[aws_vpc]")

	if !pc.HasProvider("AWS") {
		t.Error("HasProvider should be case-insensitive")
	}
	if pc.HasProvider("nonexistent") {
		t.Error("HasProvider must return false for unknown providers")
	}
}

func TestBuildProjectContext_EmptyDir(t *testing.T) {
	pc := BuildProjectContext(t.TempDir())
	if len(pc.Providers) != 0 || len(pc.Variables) != 0 || len(pc.DataSources) != 0 ||
		len(pc.Locals) != 0 || len(pc.ResourcesByType) != 0 {
		t.Errorf("expected empty context, got %+v", pc)
	}
}

func TestBuildProjectContext_MissingDir(t *testing.T) {
	pc := BuildProjectContext("/nonexistent/path/that/does/not/exist")
	if pc == nil {
		t.Fatal("BuildProjectContext must never return nil")
	}
}

func TestProjectContextDTO_NilAndEmptyAreOmitted(t *testing.T) {
	if dto := projectContextDTOFrom(nil); dto != nil {
		t.Errorf("nil ProjectContext must yield nil DTO, got %+v", dto)
	}
	empty := &ProjectContext{ResourcesByType: map[string][]string{}}
	if dto := projectContextDTOFrom(empty); dto != nil {
		t.Errorf("empty ProjectContext must yield nil DTO, got %+v", dto)
	}
}

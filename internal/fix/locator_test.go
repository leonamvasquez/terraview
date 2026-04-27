package fix

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCountBraces_StringAware(t *testing.T) {
	tests := []struct {
		name string
		line string
		want int
	}{
		{"plain open", "resource \"aws_kms_key\" \"k\" {", 1},
		{"plain close", "}", -1},
		{"balanced", "foo = bar { baz = {} }", 0},
		{"string with braces ignored", `value = "text { with } braces"`, 0},
		{"jsonencode open", `policy = jsonencode({`, 1},
		{"hash comment ignored", `# this { has } braces`, 0},
		{"slash comment ignored", `// open { close }`, 0},
		{"escaped quote in string", `v = "he said \"hello\" { ok }"`, 0},
		{"open before comment", `key = { # comment {{{`, 1},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := countBraces(tc.line)
			if got != tc.want {
				t.Errorf("countBraces(%q) = %d, want %d", tc.line, got, tc.want)
			}
		})
	}
}

func TestIsBraceBalanced(t *testing.T) {
	tests := []struct {
		name string
		hcl  string
		want bool
	}{
		{
			"valid block",
			`resource "aws_kms_key" "k" {
  enable_key_rotation = true
}`,
			true,
		},
		{
			"missing closing brace",
			`resource "aws_kms_key" "k" {
  enable_key_rotation = true`,
			false,
		},
		{
			"jsonencode balanced",
			`resource "aws_iam_role_policy" "p" {
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = []
  })
}`,
			true,
		},
		{
			"string with braces — still balanced",
			`resource "aws_s3_bucket" "b" {
  tags = { Name = "my { bucket }" }
}`,
			true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := isBraceBalanced(tc.hcl)
			if got != tc.want {
				t.Errorf("isBraceBalanced() = %v, want %v\nHCL:\n%s", got, tc.want, tc.hcl)
			}
		})
	}
}

func TestFindResource_HeredocPolicy(t *testing.T) {
	// A .tf file where the resource contains a heredoc JSON policy.
	// The brace inside the heredoc must not confuse the block finder.
	content := `resource "aws_iam_role_policy" "bad_policy" {
  name = "bad"
  role = aws_iam_role.node.id
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Resource": "*"
  }]
}
POLICY
}

resource "aws_kms_key" "other" {
  enable_key_rotation = true
}
`
	dir := t.TempDir()
	path := filepath.Join(dir, "iam.tf")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	loc, err := FindResource(dir, "aws_iam_role_policy.bad_policy")
	if err != nil {
		t.Fatalf("FindResource error: %v", err)
	}
	if loc == nil {
		t.Fatal("expected location, got nil")
	}
	if loc.StartLine != 1 {
		t.Errorf("StartLine = %d, want 1", loc.StartLine)
	}
	// EndLine should be the closing } of bad_policy, not one inside the heredoc.
	if loc.EndLine != 13 {
		t.Errorf("EndLine = %d, want 13", loc.EndLine)
	}

	// aws_kms_key.other must also be findable (proves heredoc didn't consume rest of file)
	loc2, err := FindResource(dir, "aws_kms_key.other")
	if err != nil {
		t.Fatalf("FindResource error: %v", err)
	}
	if loc2 == nil {
		t.Fatal("expected location for aws_kms_key.other, got nil")
	}
}

func TestLineStartsResourceBlock(t *testing.T) {
	needle := `resource "aws_lb" "main"`
	tests := []struct {
		name string
		line string
		want bool
	}{
		{"plain header", `resource "aws_lb" "main" {`, true},
		{"indented header", `  resource "aws_lb" "main" {`, true},
		{"header without brace", `resource "aws_lb" "main"`, true},
		{"comment hash", `# resource "aws_lb" "main" {`, false},
		{"comment slash", `// resource "aws_lb" "main" {`, false},
		{"description string", `description = "see resource \"aws_lb\" \"main\""`, false},
		{"different name prefix", `resource "aws_lb" "main_other" {`, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := lineStartsResourceBlock(tc.line, needle); got != tc.want {
				t.Errorf("got %v, want %v for %q", got, tc.want, tc.line)
			}
		})
	}
}

func TestFindResource_IgnoresCommentedHeader(t *testing.T) {
	content := `# old version: resource "aws_lb" "main" { ... }
resource "aws_lb" "main" {
  name = "real"
}
`
	dir := t.TempDir()
	path := filepath.Join(dir, "lb.tf")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	loc, err := FindResource(dir, "aws_lb.main")
	if err != nil || loc == nil {
		t.Fatalf("FindResource: loc=%v err=%v", loc, err)
	}
	if loc.StartLine != 2 {
		t.Errorf("StartLine = %d, want 2 (must skip commented header on line 1)", loc.StartLine)
	}
}

func TestFindResource_IgnoresNamePrefix(t *testing.T) {
	// Two resources with similar names: the locator must not match the
	// "main_other" header when asked for "main".
	content := `resource "aws_lb" "main_other" {
  name = "other"
}

resource "aws_lb" "main" {
  name = "real"
}
`
	dir := t.TempDir()
	path := filepath.Join(dir, "lb.tf")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	loc, err := FindResource(dir, "aws_lb.main")
	if err != nil || loc == nil {
		t.Fatalf("FindResource: loc=%v err=%v", loc, err)
	}
	if loc.StartLine != 5 {
		t.Errorf("StartLine = %d, want 5 (must not match main_other on line 1)", loc.StartLine)
	}
}

func TestSplitAddr_ForEach(t *testing.T) {
	tests := []struct {
		addr     string
		wantType string
		wantName string
	}{
		{"aws_lambda_function.functions[\"handler\"]", "aws_lambda_function", "functions"},
		{"aws_instance.web[0]", "aws_instance", "web"},
		{"module.vpc.aws_vpc.main", "aws_vpc", "main"},
		{"aws_iam_role.eks_node", "aws_iam_role", "eks_node"},
	}
	for _, tc := range tests {
		t.Run(tc.addr, func(t *testing.T) {
			gotType, gotName := splitAddr(tc.addr)
			if gotType != tc.wantType || gotName != tc.wantName {
				t.Errorf("splitAddr(%q) = (%q, %q), want (%q, %q)",
					tc.addr, gotType, gotName, tc.wantType, tc.wantName)
			}
		})
	}
}

func TestDeduplicatePrereqs(t *testing.T) {
	dir := t.TempDir()
	// Write an existing resource
	existing := `resource "aws_kms_key" "existing" {
  enable_key_rotation = true
}
`
	if err := os.WriteFile(filepath.Join(dir, "kms.tf"), []byte(existing), 0o644); err != nil {
		t.Fatal(err)
	}

	prereqs := []string{
		// This one already exists — should be filtered out
		`resource "aws_kms_key" "existing" {
  enable_key_rotation = true
}`,
		// This one is new — should be kept
		`resource "aws_kms_alias" "new_alias" {
  name = "alias/new"
}`,
	}

	got := deduplicatePrereqs(prereqs, dir)
	if len(got) != 1 {
		t.Fatalf("expected 1 prereq after dedup, got %d", len(got))
	}
	rType, rName := parsePrereqHeader(got[0])
	if rType != "aws_kms_alias" || rName != "new_alias" {
		t.Errorf("unexpected surviving prereq: %s.%s", rType, rName)
	}
}

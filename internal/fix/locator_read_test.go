package fix

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestReadLines_OK(t *testing.T) {
	file := copyFixture(t)
	loc, err := FindResource(filepath.Dir(file), "aws_s3_bucket.logs")
	if err != nil || loc == nil {
		t.Fatalf("FindResource: loc=%v err=%v", loc, err)
	}

	lines, err := ReadLines(loc)
	if err != nil {
		t.Fatalf("ReadLines: %v", err)
	}
	if len(lines) == 0 {
		t.Fatal("expected at least one line")
	}
	if !strings.Contains(lines[0], `"aws_s3_bucket" "logs"`) {
		t.Errorf("first line should be the resource header, got %q", lines[0])
	}
}

func TestReadLines_OutOfBounds(t *testing.T) {
	file := copyFixture(t)
	loc := &Location{File: file, StartLine: 1, EndLine: 9999}
	if _, err := ReadLines(loc); err == nil {
		t.Fatal("expected out-of-bounds error")
	}
}

func TestReadLines_MissingFile(t *testing.T) {
	loc := &Location{File: "/nonexistent.tf", StartLine: 1, EndLine: 2}
	if _, err := ReadLines(loc); err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestReadFileContext_ListsSiblingResources(t *testing.T) {
	file := copyFixture(t)
	dir := filepath.Dir(file)
	loc, err := FindResource(dir, "aws_s3_bucket.logs")
	if err != nil || loc == nil {
		t.Fatalf("FindResource: loc=%v err=%v", loc, err)
	}

	ctx := ReadFileContext(loc, dir)
	if ctx == "" {
		t.Fatal("expected non-empty context")
	}
	// Should include sibling resources (data bucket, iam role) but not the
	// target "logs" bucket.
	if !strings.Contains(ctx, `"aws_s3_bucket" "data"`) {
		t.Errorf("expected sibling data bucket in context, got:\n%s", ctx)
	}
	if !strings.Contains(ctx, `"aws_iam_role" "app"`) {
		t.Errorf("expected sibling iam role in context, got:\n%s", ctx)
	}
	if strings.Contains(ctx, `"aws_s3_bucket" "logs"`) {
		t.Errorf("context should exclude the target resource, got:\n%s", ctx)
	}
}

func TestReadFileContext_MissingFile(t *testing.T) {
	loc := &Location{File: "/nonexistent.tf", StartLine: 1}
	if ctx := ReadFileContext(loc, "/"); ctx != "" {
		t.Errorf("expected empty context on read error, got %q", ctx)
	}
}

package smell

import (
	"testing"

	"github.com/leonamvasquez/terraview/internal/parser"
)

func TestDetect_NoTags(t *testing.T) {
	res := []parser.NormalizedResource{
		{Address: "aws_instance.web", Type: "aws_instance", Name: "web",
			Values: map[string]interface{}{"ami": "ami-123"}},
	}
	r := NewDetector().Detect(res)
	for _, s := range r.Smells {
		if s.Type == SmellNoTags {
			return
		}
	}
	t.Error("expected missing-tags smell")
}

func TestDetect_WithTags(t *testing.T) {
	res := []parser.NormalizedResource{
		{Address: "aws_instance.web", Type: "aws_instance", Name: "web",
			Values: map[string]interface{}{"tags": map[string]interface{}{"Name": "web"}}},
	}
	r := NewDetector().Detect(res)
	for _, s := range r.Smells {
		if s.Type == SmellNoTags && s.Resource == "aws_instance.web" {
			t.Error("should not flag tags when present")
		}
	}
}

func TestDetect_NoEncryption(t *testing.T) {
	res := []parser.NormalizedResource{
		{Address: "aws_s3_bucket.data", Type: "aws_s3_bucket", Name: "data",
			Values: map[string]interface{}{"bucket": "b"}},
	}
	r := NewDetector().Detect(res)
	for _, s := range r.Smells {
		if s.Type == SmellNoEncryption {
			return
		}
	}
	t.Error("expected no-encryption smell")
}

func TestDetect_NoSmells(t *testing.T) {
	res := []parser.NormalizedResource{
		{Address: "null_resource.x", Type: "null_resource", Name: "x"},
	}
	r := NewDetector().Detect(res)
	if r.QualityScore != 10.0 {
		t.Errorf("want 10.0, got %.1f", r.QualityScore)
	}
}

func TestDetect_PermissiveSG(t *testing.T) {
	res := []parser.NormalizedResource{
		{Address: "aws_security_group.open", Type: "aws_security_group", Name: "open",
			Values: map[string]interface{}{"cidr_blocks": []interface{}{"0.0.0.0/0"}}},
	}
	r := NewDetector().Detect(res)
	for _, s := range r.Smells {
		if s.Type == SmellOverlyPermissive {
			return
		}
	}
	t.Error("expected overly-permissive smell")
}

func TestFormatSmells(t *testing.T) {
	r := &DetectorResult{QualityScore: 10.0, QualityLevel: "EXCELLENT"}
	if FormatSmells(r) == "" {
		t.Error("expected non-empty")
	}
}

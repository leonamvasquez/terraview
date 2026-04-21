package scoring

import (
	"math"
	"testing"

	"github.com/leonamvasquez/terraview/internal/rules"
)

// Tests below cover scenarios not present in scorer_test.go:
// custom-weights comparison and NaN/Inf range guard across multiple inputs.
// Previously lived in the dead internal/regression package.

func TestScoring_MediumOnlyFloor(t *testing.T) {
	s := NewScorerWithWeights(5, 3, 1, 0.5)
	f := []rules.Finding{
		{Severity: rules.SeverityMedium, Category: rules.CategorySecurity},
		{Severity: rules.SeverityMedium, Category: rules.CategorySecurity},
		{Severity: rules.SeverityMedium, Category: rules.CategorySecurity},
	}
	sc := s.Calculate(f, 3)
	if sc.SecurityScore < 5.0 {
		t.Errorf("MEDIUM-only security should be >= 5.0, got %.1f", sc.SecurityScore)
	}
}

func TestScoring_CustomWeightsDiffer(t *testing.T) {
	def := NewScorerWithWeights(5, 3, 1, 0.5)
	fin := NewScorerWithWeights(10, 5, 2, 1)
	f := []rules.Finding{
		{Severity: rules.SeverityMedium, Category: rules.CategorySecurity},
	}
	ds := def.Calculate(f, 5)
	fs := fin.Calculate(f, 5)
	if fs.OverallScore >= ds.OverallScore {
		t.Errorf("fintech weights should produce lower score: default=%.1f fintech=%.1f", ds.OverallScore, fs.OverallScore)
	}
}

func TestScoring_Range(t *testing.T) {
	s := NewScorerWithWeights(5, 3, 1, 0.5)
	cases := []struct {
		name string
		f    []rules.Finding
		n    int
	}{
		{"empty", nil, 0},
		{"clean", nil, 10},
		{"1crit", []rules.Finding{
			{Severity: rules.SeverityCritical, Category: rules.CategorySecurity},
		}, 1},
		{"50crit", func() []rules.Finding {
			r := make([]rules.Finding, 50)
			for i := range r {
				r[i] = rules.Finding{Severity: rules.SeverityCritical, Category: rules.CategorySecurity}
			}
			return r
		}(), 2},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			sc := s.Calculate(c.f, c.n)
			for _, v := range []float64{sc.SecurityScore, sc.MaintainabilityScore, sc.ComplianceScore, sc.OverallScore} {
				if v < 0 || v > 10 {
					t.Errorf("score out of [0,10]: %.1f", v)
				}
				if math.IsNaN(v) || math.IsInf(v, 0) {
					t.Errorf("score is NaN/Inf: %f", v)
				}
			}
		})
	}
}

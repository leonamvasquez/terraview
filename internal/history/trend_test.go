package history

import (
	"testing"
)

func TestComputeTrend_Ascending(t *testing.T) {
	td := ComputeTrend("Overall", []float64{5.0, 6.0, 7.0, 8.0, 9.0})
	if td.Direction != "↑" {
		t.Errorf("Direction = %q, want ↑", td.Direction)
	}
	if td.First != 5.0 {
		t.Errorf("First = %.1f, want 5.0", td.First)
	}
	if td.Last != 9.0 {
		t.Errorf("Last = %.1f, want 9.0", td.Last)
	}
	if td.DeltaAbs != 4.0 {
		t.Errorf("DeltaAbs = %.1f, want 4.0", td.DeltaAbs)
	}
	if td.Sparkline == "" {
		t.Error("Sparkline should not be empty")
	}
}

func TestComputeTrend_Descending(t *testing.T) {
	td := ComputeTrend("Security", []float64{9.0, 7.0, 5.0, 3.0})
	if td.Direction != "↓" {
		t.Errorf("Direction = %q, want ↓", td.Direction)
	}
	if td.DeltaAbs != -6.0 {
		t.Errorf("DeltaAbs = %.1f, want -6.0", td.DeltaAbs)
	}
}

func TestComputeTrend_Constant(t *testing.T) {
	td := ComputeTrend("Stable", []float64{5.0, 5.0, 5.0})
	if td.Direction != "→" {
		t.Errorf("Direction = %q, want →", td.Direction)
	}
	if td.DeltaPct != 0 {
		t.Errorf("DeltaPct = %.2f, want 0", td.DeltaPct)
	}
	// Sparkline should be all the same block character
	runes := []rune(td.Sparkline)
	if len(runes) != 3 {
		t.Fatalf("Sparkline length = %d, want 3", len(runes))
	}
	if runes[0] != runes[1] || runes[1] != runes[2] {
		t.Error("Constant sparkline should have identical blocks")
	}
}

func TestComputeTrend_SingleDatapoint(t *testing.T) {
	td := ComputeTrend("Solo", []float64{7.5})
	if td.Direction != "→" {
		t.Errorf("Direction = %q, want →", td.Direction)
	}
	if td.First != 7.5 || td.Last != 7.5 {
		t.Errorf("First/Last = %.1f/%.1f, want 7.5/7.5", td.First, td.Last)
	}
	if len([]rune(td.Sparkline)) != 1 {
		t.Errorf("Sparkline = %q, expected single block", td.Sparkline)
	}
}

func TestComputeTrend_NoDatapoints(t *testing.T) {
	td := ComputeTrend("Empty", nil)
	if td.Direction != "→" {
		t.Errorf("Direction = %q, want →", td.Direction)
	}
	if td.Sparkline != "(sem dados)" {
		t.Errorf("Sparkline = %q, want (sem dados)", td.Sparkline)
	}
}

func TestComputeTrend_DeltaPct(t *testing.T) {
	td := ComputeTrend("Score", []float64{4.0, 6.0})
	expectedPct := 50.0 // (6-4)/4 * 100 = 50%
	if td.DeltaPct != expectedPct {
		t.Errorf("DeltaPct = %.1f, want %.1f", td.DeltaPct, expectedPct)
	}
}

func TestComputeTrend_DivByZero_InitialZero(t *testing.T) {
	td := ComputeTrend("FromZero", []float64{0, 5.0})
	if td.DeltaPct != 100 {
		t.Errorf("DeltaPct = %.1f, want 100", td.DeltaPct)
	}
	if td.Direction != "↑" {
		t.Errorf("Direction = %q, want ↑", td.Direction)
	}
}

func TestComputeTrend_DivByZero_BothZero(t *testing.T) {
	td := ComputeTrend("ZeroToZero", []float64{0, 0})
	if td.DeltaPct != 0 {
		t.Errorf("DeltaPct = %.1f, want 0", td.DeltaPct)
	}
	if td.Direction != "→" {
		t.Errorf("Direction = %q, want →", td.Direction)
	}
}

func TestBuildSparkline_Length(t *testing.T) {
	for _, n := range []int{1, 5, 10, 50} {
		vals := make([]float64, n)
		for i := range vals {
			vals[i] = float64(i)
		}
		s := buildSparkline(vals)
		runes := []rune(s)
		if len(runes) != n {
			t.Errorf("buildSparkline(%d values) = %d runes, want %d", n, len(runes), n)
		}
	}
}

func TestBuildSparkline_Empty(t *testing.T) {
	s := buildSparkline(nil)
	if s != "" {
		t.Errorf("buildSparkline(nil) = %q, want empty", s)
	}
}

func TestComputeTrendsFromRecords(t *testing.T) {
	// Provide records in newest-first order (as returned by List)
	records := []ScanRecord{
		{ScoreOverall: 9.0, ScoreSecurity: 8.0, CountCritical: 0, CountHigh: 1},
		{ScoreOverall: 7.0, ScoreSecurity: 6.0, CountCritical: 2, CountHigh: 5},
		{ScoreOverall: 5.0, ScoreSecurity: 4.0, CountCritical: 3, CountHigh: 8},
	}

	trends := ComputeTrendsFromRecords(records)
	if len(trends) != 4 {
		t.Fatalf("expected 4 trends, got %d", len(trends))
	}

	// After reversal: [5, 7, 9] → ascending
	overall := trends[0]
	if overall.Metric != "Overall" {
		t.Errorf("trends[0].Metric = %q, want Overall", overall.Metric)
	}
	if overall.Direction != "↑" {
		t.Errorf("Overall direction = %q, want ↑", overall.Direction)
	}

	// CRITICAL: [3, 2, 0] → descending
	crit := trends[2]
	if crit.Metric != "CRITICAL" {
		t.Errorf("trends[2].Metric = %q, want CRITICAL", crit.Metric)
	}
	if crit.Direction != "↓" {
		t.Errorf("CRITICAL direction = %q, want ↓", crit.Direction)
	}
}

func TestComputeTrendsFromRecords_Empty(t *testing.T) {
	trends := ComputeTrendsFromRecords(nil)
	if trends != nil {
		t.Errorf("expected nil for empty records, got %d trends", len(trends))
	}
}

func TestFormatTrend_Score(t *testing.T) {
	td := ComputeTrend("Overall", []float64{5.0, 7.0, 9.0})
	out := FormatTrend(td)
	if out == "" {
		t.Error("FormatTrend returned empty string")
	}
	// Should contain metric name
	if !containsStr(out, "Overall") {
		t.Errorf("output missing metric name: %s", out)
	}
}

func TestFormatTrend_Count(t *testing.T) {
	td := ComputeTrend("CRITICAL", []float64{5, 3, 1})
	out := FormatTrend(td)
	// Count format: integer values
	if !containsStr(out, "5") || !containsStr(out, "1") {
		t.Errorf("output missing integer values: %s", out)
	}
}

func TestFormatTrend_NoData(t *testing.T) {
	td := ComputeTrend("Empty", nil)
	out := FormatTrend(td)
	if !containsStr(out, "sem dados") {
		t.Errorf("expected (sem dados) in output: %s", out)
	}
}

// containsStr is defined in record_test.go

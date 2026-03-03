package scoring

import (
	"math"
	"strings"

	"github.com/leonamvasquez/terraview/internal/rules"
)

// ScoreDecomposition contém a decomposição completa do cálculo de score,
// permitindo auditoria de como cada finding contribuiu para o resultado final.
type ScoreDecomposition struct {
	Security        CategoryDecomposition `json:"security"`
	Compliance      CategoryDecomposition `json:"compliance"`
	Maintainability CategoryDecomposition `json:"maintainability"`
	Reliability     CategoryDecomposition `json:"reliability"`
	Overall         OverallDecomposition  `json:"overall"`
}

// CategoryDecomposition detalha o cálculo de uma categoria.
type CategoryDecomposition struct {
	RawScore       float64         `json:"raw_score"`
	FinalScore     float64         `json:"final_score"`
	WeightedSum    float64         `json:"weighted_sum"`
	PenaltyRatio   float64         `json:"penalty_ratio"`
	TotalResources int             `json:"total_resources"`
	FloorApplied   string          `json:"floor_applied,omitempty"`
	BlendingNote   string          `json:"blending_note,omitempty"`
	FindingsImpact []FindingImpact `json:"findings_impact"`
}

// FindingImpact detalha a contribuição de um finding individual.
type FindingImpact struct {
	RuleID        string   `json:"rule_id"`
	Resource      string   `json:"resource"`
	Severity      string   `json:"severity"`
	Weight        float64  `json:"weight"`
	Source        string   `json:"source"`
	Category      string   `json:"category"`
	RiskVectors   []string `json:"risk_vectors"`
	ImpactOnScore float64  `json:"impact_on_score"`
}

// OverallDecomposition detalha o cálculo do Score Geral.
type OverallDecomposition struct {
	Formula    string             `json:"formula"`
	Components []OverallComponent `json:"components"`
	FinalScore float64            `json:"final_score"`
}

// OverallComponent é um peso × score usado no cálculo do Overall.
type OverallComponent struct {
	Category string  `json:"category"`
	Score    float64 `json:"score"`
	Weight   float64 `json:"weight"`
	Weighted float64 `json:"weighted"`
}

// Decompose calcula a decomposição completa do scoring para auditoria.
// Deve ser chamado com os mesmos parâmetros usados em Calculate() para
// garantir que os números sejam idênticos.
func (s *Scorer) Decompose(findings []rules.Finding, totalResources int) ScoreDecomposition {
	if len(findings) == 0 || totalResources == 0 {
		return s.emptyDecomposition(totalResources)
	}

	secFindings := filterByCategories(findings, rules.CategorySecurity)
	maintFindings := filterByCategories(findings, rules.CategoryMaintainability, rules.CategoryBestPractice)
	compFindings := filterByCategories(findings, rules.CategoryCompliance)
	relFindings := filterByCategories(findings, rules.CategoryReliability)

	secDecomp := s.decomposeCategory(secFindings, totalResources, "security")
	compDecomp := s.decomposeCategory(compFindings, totalResources, "compliance")
	maintDecomp := s.decomposeCategory(maintFindings, totalResources, "maintainability")
	relDecomp := s.decomposeCategory(relFindings, totalResources, "reliability")

	// Aplicar blending de confiabilidade
	if len(relFindings) > 0 {
		blendedSec := (secDecomp.RawScore*2 + relDecomp.RawScore) / 3
		secDecomp.FinalScore = clampScore(blendedSec)
		secDecomp.BlendingNote = "Blended com reliability: (sec×2 + rel) / 3"

		blendedComp := (compDecomp.RawScore*2 + relDecomp.RawScore) / 3
		compDecomp.FinalScore = clampScore(blendedComp)
		compDecomp.BlendingNote = "Blended com reliability: (comp×2 + rel) / 3"
	}

	// Calcular Overall
	secScore := secDecomp.FinalScore
	compScore := compDecomp.FinalScore
	maintScore := maintDecomp.FinalScore
	relScore := relDecomp.FinalScore

	overallRaw := (secScore*3 + compScore*2 + maintScore*1.5 + relScore*1) / 7.5
	overallFinal := clampScore(overallRaw)

	overall := OverallDecomposition{
		Formula: "(sec×3.0 + comp×2.0 + maint×1.5 + rel×1.0) / 7.5",
		Components: []OverallComponent{
			{Category: "security", Score: secScore, Weight: 3.0, Weighted: roundDec(secScore * 3.0)},
			{Category: "compliance", Score: compScore, Weight: 2.0, Weighted: roundDec(compScore * 2.0)},
			{Category: "maintainability", Score: maintScore, Weight: 1.5, Weighted: roundDec(maintScore * 1.5)},
			{Category: "reliability", Score: relScore, Weight: 1.0, Weighted: roundDec(relScore * 1.0)},
		},
		FinalScore: overallFinal,
	}

	return ScoreDecomposition{
		Security:        secDecomp,
		Compliance:      compDecomp,
		Maintainability: maintDecomp,
		Reliability:     relDecomp,
		Overall:         overall,
	}
}

// decomposeCategory calcula a decomposição de uma categoria individual.
func (s *Scorer) decomposeCategory(findings []rules.Finding, totalResources int, categoryName string) CategoryDecomposition {
	impacts := make([]FindingImpact, 0, len(findings))
	weightedSum := 0.0
	hasCritical := false
	hasHigh := false
	onlyMediumOrBelow := true

	for _, f := range findings {
		w := s.severityWeights[f.Severity]
		weightedSum += w

		switch f.Severity {
		case rules.SeverityCritical:
			hasCritical = true
			onlyMediumOrBelow = false
		case rules.SeverityHigh:
			hasHigh = true
			onlyMediumOrBelow = false
		}

		// Impacto individual: quanto este finding contribui para a penalização
		individualPenalty := w / math.Max(float64(totalResources), 1.0) * 2.0
		impact := FindingImpact{
			RuleID:        f.RuleID,
			Resource:      f.Resource,
			Severity:      f.Severity,
			Weight:        w,
			Source:        f.Source,
			Category:      f.Category,
			RiskVectors:   inferRiskVectors(f),
			ImpactOnScore: -roundDec(individualPenalty),
		}
		impacts = append(impacts, impact)
	}

	penaltyRatio := weightedSum / math.Max(float64(totalResources), 1.0)
	rawScore := 10.0 - math.Min(penaltyRatio*2.0, 10.0)

	floorApplied := ""
	if onlyMediumOrBelow && rawScore < 5.0 {
		rawScore = 5.0
		floorApplied = "Piso 5.0: apenas findings MEDIUM ou inferior"
	}
	if hasHigh && !hasCritical && rawScore < 2.0 {
		rawScore = 2.0
		floorApplied = "Piso 2.0: HIGH sem CRITICAL"
	}

	finalScore := clampScore(rawScore)

	return CategoryDecomposition{
		RawScore:       roundDec(rawScore),
		FinalScore:     finalScore,
		WeightedSum:    roundDec(weightedSum),
		PenaltyRatio:   roundDec(penaltyRatio),
		TotalResources: totalResources,
		FloorApplied:   floorApplied,
		FindingsImpact: impacts,
	}
}

// emptyDecomposition retorna uma decomposição com todos os scores em 10.0.
func (s *Scorer) emptyDecomposition(totalResources int) ScoreDecomposition {
	empty := CategoryDecomposition{
		RawScore:       10.0,
		FinalScore:     10.0,
		TotalResources: totalResources,
		FindingsImpact: []FindingImpact{},
	}

	return ScoreDecomposition{
		Security:        empty,
		Compliance:      empty,
		Maintainability: empty,
		Reliability:     empty,
		Overall: OverallDecomposition{
			Formula: "(sec×3.0 + comp×2.0 + maint×1.5 + rel×1.0) / 7.5",
			Components: []OverallComponent{
				{Category: "security", Score: 10.0, Weight: 3.0, Weighted: 30.0},
				{Category: "compliance", Score: 10.0, Weight: 2.0, Weighted: 20.0},
				{Category: "maintainability", Score: 10.0, Weight: 1.5, Weighted: 15.0},
				{Category: "reliability", Score: 10.0, Weight: 1.0, Weighted: 10.0},
			},
			FinalScore: 10.0,
		},
	}
}

// inferRiskVectors infere os vetores de risco a partir da categoria e mensagem.
// Como findings não carregam features diretamente, usamos heurística.
func inferRiskVectors(f rules.Finding) []string {
	cat := strings.ToLower(f.Category)
	msg := strings.ToLower(f.Message)
	ruleID := strings.ToLower(f.RuleID)

	var vectors []string

	switch {
	case strings.Contains(cat, "security"):
		// Inferir vetor específico pela mensagem/rule
		if containsAny(msg, "encrypt", "kms", "ssl", "tls", "at-rest", "in-transit") ||
			containsAny(ruleID, "encrypt") {
			vectors = append(vectors, "encryption")
		}
		if containsAny(msg, "public", "0.0.0.0", "ingress", "egress", "port", "cidr", "sg", "security group", "firewall") {
			vectors = append(vectors, "network")
		}
		if containsAny(msg, "iam", "policy", "role", "permission", "wildcard", "admin", "root", "access", "privilege") ||
			containsAny(ruleID, "iam") {
			vectors = append(vectors, "identity")
		}
		// Se nenhum vetor específico, default para criptografia (mais comum em security)
		if len(vectors) == 0 {
			vectors = append(vectors, "encryption")
		}
	case strings.Contains(cat, "compliance"):
		vectors = append(vectors, "governance")
	case strings.Contains(cat, "reliab"):
		vectors = append(vectors, "observability")
	case strings.Contains(cat, "maint") || strings.Contains(cat, "best"):
		vectors = append(vectors, "governance")
	default:
		vectors = append(vectors, "governance")
	}

	return vectors
}

func containsAny(s string, terms ...string) bool {
	for _, t := range terms {
		if strings.Contains(s, t) {
			return true
		}
	}
	return false
}

func roundDec(v float64) float64 {
	return math.Round(v*100) / 100
}

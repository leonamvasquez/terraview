// Package riskvec creates deterministic multi-cloud risk vectors from extracted features.
package riskvec

import (
	"github.com/leonamvasquez/terraview/internal/feature"
)

// RiskVector is a normalized multi-axis risk representation.
type RiskVector struct {
	Network       int `json:"network"`
	Encryption    int `json:"encryption"`
	Identity      int `json:"identity"`
	Governance    int `json:"governance"`
	Observability int `json:"observability"`
	Total         int `json:"total"`
}

// ScoredResource combines resource features with its computed risk vector.
type ScoredResource struct {
	Features   feature.ResourceFeatures `json:"features"`
	RiskVector RiskVector               `json:"risk_vector"`
}

// Scorer computes risk vectors from resource features.
type Scorer struct{}

// NewScorer creates a new risk vector scorer.
func NewScorer() *Scorer {
	return &Scorer{}
}

// Score computes risk vectors for a slice of resource features. O(n).
func (s *Scorer) Score(features []feature.ResourceFeatures) []ScoredResource {
	result := make([]ScoredResource, 0, len(features))
	for i := range features {
		result = append(result, s.scoreOne(&features[i]))
	}
	return result
}

func (s *Scorer) scoreOne(f *feature.ResourceFeatures) ScoredResource {
	rv := RiskVector{
		Network:       clamp(f.NetworkExposure, 0, 3),
		Encryption:    clamp(f.EncryptionRisk, 0, 3),
		Identity:      clamp(f.IdentityRisk, 0, 3),
		Governance:    clamp(f.GovernanceRisk, 0, 3),
		Observability: clamp(f.ObservabilityRisk, 0, 3),
	}
	rv.Total = rv.Network + rv.Encryption + rv.Identity + rv.Governance + rv.Observability

	return ScoredResource{
		Features:   *f,
		RiskVector: rv,
	}
}

// HighestAxis returns the highest single axis value in the vector.
func (rv *RiskVector) HighestAxis() int {
	m := rv.Network
	if rv.Encryption > m {
		m = rv.Encryption
	}
	if rv.Identity > m {
		m = rv.Identity
	}
	if rv.Governance > m {
		m = rv.Governance
	}
	if rv.Observability > m {
		m = rv.Observability
	}
	return m
}

// DominantCategory returns the risk category name with the highest score.
func (rv *RiskVector) DominantCategory() string {
	m := rv.HighestAxis()
	if m == 0 {
		return "best-practice"
	}
	switch m {
	case rv.Network:
		return "security"
	case rv.Encryption:
		return "security"
	case rv.Identity:
		return "security"
	case rv.Governance:
		return "compliance"
	case rv.Observability:
		return "reliability"
	default:
		return "best-practice"
	}
}

func clamp(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

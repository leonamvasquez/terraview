// Package validator validates AI-generated findings against the topology graph,
// discarding hallucinated or invalid findings before the merge stage.
//
// Validation rules:
//   - Resource existence in the graph
//   - Resource type matching
//   - Valid severity (CRITICAL|HIGH|MEDIUM|LOW|INFO)
//   - Duplicate detection (same resource + same category/description)
//   - Required fields populated (ResourceID, Description)
package validator

import (
	"fmt"
	"strings"

	"github.com/leonamvasquez/terraview/internal/rules"
	"github.com/leonamvasquez/terraview/internal/topology"
)

// DiscardReason descreve o motivo pelo qual um finding foi descartado.
type DiscardReason string

const (
	// ReasonResourceNotFound indica que o recurso não existe no grafo de topologia.
	ReasonResourceNotFound DiscardReason = "recurso_nao_encontrado"
	// ReasonResourceTypeMismatch indica divergência de tipo entre finding e grafo.
	ReasonResourceTypeMismatch DiscardReason = "tipo_recurso_divergente"
	// ReasonInvalidSeverity indica severidade fora do conjunto permitido.
	ReasonInvalidSeverity DiscardReason = "severidade_invalida"
	// ReasonDuplicate indica finding duplicado (mesmo recurso + categoria/descrição).
	ReasonDuplicate DiscardReason = "duplicado"
	// ReasonEmptyFields indica campos obrigatórios ausentes.
	ReasonEmptyFields DiscardReason = "campos_obrigatorios_vazios"
)

// DiscardedFinding agrupa um finding descartado com o motivo.
type DiscardedFinding struct {
	Finding rules.Finding `json:"finding"`
	Reason  DiscardReason `json:"reason"`
	Detail  string        `json:"detail"`
}

// ValidationReport contém as estatísticas da validação de findings da IA.
type ValidationReport struct {
	TotalReceived int                `json:"total_received"`
	TotalValid    int                `json:"total_valid"`
	TotalDiscard  int                `json:"total_discarded"`
	Discarded     []DiscardedFinding `json:"discarded,omitempty"`
}

// validSeverities contém as severidades aceitas.
var validSeverities = map[string]bool{
	rules.SeverityCritical: true,
	rules.SeverityHigh:     true,
	rules.SeverityMedium:   true,
	rules.SeverityLow:      true,
	rules.SeverityInfo:     true,
}

// ValidateAIFindings filtra findings gerados por IA, descartando os que não
// correspondem a recursos reais no grafo de topologia ou que são inválidos.
//
// Retorna os findings válidos, os descartados e um relatório de validação.
func ValidateAIFindings(findings []rules.Finding, graph *topology.Graph) (valid []rules.Finding, discarded []DiscardedFinding, report *ValidationReport) {
	report = &ValidationReport{
		TotalReceived: len(findings),
	}

	if len(findings) == 0 {
		return nil, nil, report
	}

	// Construir índice de nós do grafo: address → Node
	nodeIndex := buildNodeIndex(graph)

	// Track duplicates: key = resource|category|descNorm
	seen := make(map[string]bool)

	for _, f := range findings {
		// Regra 5: campos obrigatórios
		if reason, detail := checkEmptyFields(f); reason != "" {
			discarded = append(discarded, DiscardedFinding{
				Finding: f,
				Reason:  reason,
				Detail:  detail,
			})
			continue
		}

		// Regra 3: severidade válida
		if reason, detail := checkSeverity(f); reason != "" {
			discarded = append(discarded, DiscardedFinding{
				Finding: f,
				Reason:  reason,
				Detail:  detail,
			})
			continue
		}

		// Regra 1 + 2: existência e tipo do recurso
		if reason, detail := checkResource(f, nodeIndex); reason != "" {
			discarded = append(discarded, DiscardedFinding{
				Finding: f,
				Reason:  reason,
				Detail:  detail,
			})
			continue
		}

		// Regra 4: detecção de duplicatas
		if reason, detail := checkDuplicate(f, seen); reason != "" {
			discarded = append(discarded, DiscardedFinding{
				Finding: f,
				Reason:  reason,
				Detail:  detail,
			})
			continue
		}

		valid = append(valid, f)
	}

	report.TotalValid = len(valid)
	report.TotalDiscard = len(discarded)
	report.Discarded = discarded

	return valid, discarded, report
}

// buildNodeIndex cria um mapa address→Node a partir do grafo de topologia.
func buildNodeIndex(graph *topology.Graph) map[string]topology.Node {
	index := make(map[string]topology.Node, len(graph.Nodes))
	for _, n := range graph.Nodes {
		index[n.Address] = n
	}
	return index
}

// checkEmptyFields verifica se os campos obrigatórios estão preenchidos.
func checkEmptyFields(f rules.Finding) (DiscardReason, string) {
	resource := strings.TrimSpace(f.Resource)
	message := strings.TrimSpace(f.Message)

	if resource == "" && message == "" {
		return ReasonEmptyFields, "resource e message estão vazios"
	}
	if resource == "" {
		return ReasonEmptyFields, "resource está vazio"
	}
	if message == "" {
		return ReasonEmptyFields, "message está vazio"
	}
	return "", ""
}

// checkSeverity verifica se a severidade é válida.
func checkSeverity(f rules.Finding) (DiscardReason, string) {
	sev := strings.ToUpper(strings.TrimSpace(f.Severity))
	if !validSeverities[sev] {
		return ReasonInvalidSeverity, fmt.Sprintf("severidade '%s' não é válida (esperado: CRITICAL|HIGH|MEDIUM|LOW|INFO)", f.Severity)
	}
	return "", ""
}

// checkResource verifica se o recurso existe no grafo e se o tipo corresponde.
func checkResource(f rules.Finding, nodeIndex map[string]topology.Node) (DiscardReason, string) {
	resource := strings.TrimSpace(f.Resource)

	node, exists := nodeIndex[resource]
	if !exists {
		return ReasonResourceNotFound, fmt.Sprintf("recurso '%s' não existe no plano Terraform", resource)
	}

	// Extrair tipo do endereço do finding (ex: "aws_s3_bucket" de "aws_s3_bucket.my_bucket")
	findingType := extractResourceType(resource)
	if findingType != "" && node.Type != "" && findingType != node.Type {
		return ReasonResourceTypeMismatch, fmt.Sprintf(
			"tipo do finding '%s' diverge do grafo '%s' para recurso '%s'",
			findingType, node.Type, resource,
		)
	}

	return "", ""
}

// checkDuplicate verifica se um finding já foi visto (mesmo recurso + mesma categoria/descrição).
func checkDuplicate(f rules.Finding, seen map[string]bool) (DiscardReason, string) {
	key := deduplicationKey(f)
	if seen[key] {
		return ReasonDuplicate, fmt.Sprintf("finding duplicado para recurso '%s' com categoria '%s'", f.Resource, f.Category)
	}
	seen[key] = true
	return "", ""
}

// deduplicationKey gera uma chave única para detecção de duplicatas.
// Usa recurso + categoria + primeiros 80 caracteres da mensagem normalizada.
func deduplicationKey(f rules.Finding) string {
	msg := strings.ToLower(strings.TrimSpace(f.Message))
	if len(msg) > 80 {
		msg = msg[:80]
	}
	return fmt.Sprintf("%s|%s|%s",
		strings.ToLower(strings.TrimSpace(f.Resource)),
		strings.ToLower(strings.TrimSpace(f.Category)),
		msg,
	)
}

// extractResourceType extrai o tipo do recurso a partir do endereço Terraform.
// Ex: "aws_s3_bucket.my_bucket" → "aws_s3_bucket"
//
//	"module.vpc.aws_subnet.private" → "aws_subnet"
func extractResourceType(address string) string {
	// Lidar com endereços de módulo: module.vpc.aws_subnet.private[0]
	parts := strings.Split(address, ".")
	if len(parts) < 2 {
		return ""
	}

	// Percorrer de trás para frente para encontrar tipo.nome
	// O tipo é o penúltimo segmento que não começa com "module"
	for i := len(parts) - 2; i >= 0; i-- {
		if parts[i] == "module" || (i > 0 && parts[i-1] == "module") {
			continue
		}
		// Remover índice se presente: "aws_subnet" de "aws_subnet[0]"
		candidate := parts[i]
		if idx := strings.Index(candidate, "["); idx != -1 {
			candidate = candidate[:idx]
		}
		// Tipo de recurso Terraform sempre contém underscore e não é "module"
		if strings.Contains(candidate, "_") && candidate != "module" {
			return candidate
		}
	}

	return ""
}

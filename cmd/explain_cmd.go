package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/leonamvasquez/terraview/internal/ai"
	_ "github.com/leonamvasquez/terraview/internal/ai/providers"
	"github.com/leonamvasquez/terraview/internal/config"
	"github.com/leonamvasquez/terraview/internal/parser"
	"github.com/leonamvasquez/terraview/internal/terraformexec"
	"github.com/leonamvasquez/terraview/internal/topology"
	"github.com/leonamvasquez/terraview/internal/workspace"
	"github.com/spf13/cobra"
)

var explainCmd = &cobra.Command{
	Use:   "explain",
	Short: "AI-powered natural language explanation of your infrastructure",
	Long: `Generates a comprehensive natural-language explanation of your Terraform
infrastructure using AI. Explains what each resource does, how they connect,
and the overall architecture pattern.

Requires an AI provider (--provider or configured in .terraview.yaml).

Examples:
  terraview explain
  terraview explain --plan plan.json
  terraview explain --provider gemini
  terraview explain --format json`,
	RunE: runExplainCmd,
}

func init() {
	explainCmd.Flags().StringVarP(&planFile, "plan", "p", "", "Path to terraform plan JSON (auto-generates if omitted)")
	explainCmd.Flags().StringVar(&aiProvider, "provider", "", "AI provider (ollama, gemini, claude, deepseek)")
	explainCmd.Flags().StringVar(&ollamaModel, "model", "", "AI model to use")
	explainCmd.Flags().IntVar(&timeout, "timeout", 0, "AI request timeout in seconds")
	explainCmd.Flags().StringVarP(&outputDir, "output", "o", "", "Output directory")
	explainCmd.Flags().StringVar(&outputFormat, "format", "", "Output format: pretty, json (default pretty)")
}

// InfraExplanation is the structured explanation of the full infrastructure.
type InfraExplanation struct {
	Overview     string          `json:"overview"`
	Architecture string          `json:"architecture"`
	Components   []ComponentExpl `json:"components"`
	Connections  []string        `json:"connections"`
	Patterns     []string        `json:"patterns"`
	Concerns     []string        `json:"concerns,omitempty"`
}

// ComponentExpl describes a single infrastructure component.
type ComponentExpl struct {
	Resource string `json:"resource"`
	Purpose  string `json:"purpose"`
	Role     string `json:"role"`
}

func runExplainCmd(cmd *cobra.Command, args []string) error {
	// Load config
	cfg, err := config.Load(workDir)
	if err != nil {
		return fmt.Errorf("config error: %w", err)
	}

	resolvedPlan := planFile
	if resolvedPlan == "" {
		if err := workspace.Validate(workDir); err != nil {
			return err
		}
		executor, err := terraformexec.NewExecutor(workDir)
		if err != nil {
			return err
		}
		if executor.NeedsInit() {
			if err := executor.Init(); err != nil {
				return err
			}
		}
		generated, err := executor.Plan()
		if err != nil {
			return err
		}
		resolvedPlan = generated
	}

	// Parse plan
	p := parser.NewParser()
	plan, err := p.ParseFile(resolvedPlan)
	if err != nil {
		return fmt.Errorf("parse error: %w", err)
	}
	resources := p.NormalizeResources(plan)
	logVerbose("Found %d resources", len(resources))

	if len(resources) == 0 {
		fmt.Println("No resources found in plan. Nothing to explain.")
		return nil
	}

	// Build topology
	topoGraph := topology.BuildGraph(resources)

	// Resolve AI provider
	effectiveProvider := cfg.LLM.Provider
	if aiProvider != "" {
		effectiveProvider = aiProvider
	}
	if effectiveProvider == "" {
		return fmt.Errorf("AI provider required. Use --provider or configure in .terraview.yaml")
	}

	effectiveModel := cfg.LLM.Model
	if ollamaModel != "" {
		effectiveModel = ollamaModel
	}

	effectiveTimeout := cfg.LLM.TimeoutSeconds
	if timeout > 0 {
		effectiveTimeout = timeout
	}
	if effectiveTimeout == 0 {
		effectiveTimeout = 120
	}

	// Create AI provider
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(effectiveTimeout+30)*time.Second)
	defer cancel()

	// When the provider is not ollama and no explicit URL was set, clear the
	// default Ollama URL so each provider falls back to its own base URL.
	explainURL := cfg.LLM.URL
	if effectiveProvider != "ollama" && explainURL == "http://localhost:11434" {
		explainURL = ""
	}

	providerCfg := ai.ProviderConfig{
		Model:       effectiveModel,
		APIKey:      cfg.LLM.APIKey,
		BaseURL:     explainURL,
		Temperature: 0.3,
		TimeoutSecs: effectiveTimeout,
		MaxTokens:   8192,
		MaxRetries:  2,
	}

	provider, err := ai.NewProvider(ctx, effectiveProvider, providerCfg)
	if err != nil {
		return fmt.Errorf("AI provider error: %w", err)
	}

	// Build explain prompt
	prompt := buildInfraExplainPrompt(resources, topoGraph)
	if brFlag {
		prompt += "\n\nIMPORTANT: You MUST respond entirely in Brazilian Portuguese (pt-BR). All text, descriptions, and explanations must be in Portuguese.\n"
	}

	req := ai.Request{
		Resources: resources,
		Summary: map[string]interface{}{
			"total_resources":  len(resources),
			"topology_context": topoGraph.FormatContext(),
			"topology_layers":  topoGraph.Layers(),
			"mode":             "explain-infra",
		},
		Prompts: ai.Prompts{
			System: prompt,
		},
	}

	fmt.Println("Analyzing infrastructure with AI...")
	completion, err := provider.Analyze(ctx, req)
	if err != nil {
		return fmt.Errorf("AI analysis failed: %w", err)
	}

	// Parse response
	explanation := parseInfraExplanation(completion.Summary)

	// Output
	resolvedOutput := outputDir
	if resolvedOutput == "" {
		resolvedOutput = workDir
	}

	resolvedFormat := "pretty"
	if outputFormat != "" {
		resolvedFormat = outputFormat
	}

	if resolvedFormat == "json" {
		data, _ := json.MarshalIndent(explanation, "", "  ")
		jsonPath := filepath.Join(resolvedOutput, "explain.json")
		if err := os.WriteFile(jsonPath, data, 0644); err != nil {
			return fmt.Errorf("failed to write %s: %w", jsonPath, err)
		}
		fmt.Printf("Written: %s\n", jsonPath)
	} else {
		printInfraExplanation(explanation)
	}

	return nil
}

func buildInfraExplainPrompt(resources []parser.NormalizedResource, topoGraph *topology.Graph) string {
	var sb strings.Builder

	sb.WriteString("You are a senior cloud architect explaining infrastructure to a team.\n\n")
	sb.WriteString("Analyze the following Terraform infrastructure and provide a comprehensive explanation.\n\n")
	sb.WriteString("You MUST respond ONLY with valid JSON in this exact format:\n")
	sb.WriteString(`{
  "findings": [],
  "summary": "{\"overview\":\"...\",\"architecture\":\"...\",\"components\":[{\"resource\":\"...\",\"purpose\":\"...\",\"role\":\"...\"}],\"connections\":[\"...\"],\"patterns\":[\"...\"],\"concerns\":[\"...\"]}"
}`)
	sb.WriteString("\n\nThe summary field MUST be a JSON string containing:\n")
	sb.WriteString("- overview: 2-3 sentence high-level overview of the infrastructure\n")
	sb.WriteString("- architecture: describe the architecture pattern (monolith, microservices, serverless, etc.)\n")
	sb.WriteString("- components: array of {resource, purpose, role} for each significant resource\n")
	sb.WriteString("- connections: array of strings describing how resources connect to each other\n")
	sb.WriteString("- patterns: array of infrastructure patterns identified (HA, DR, auto-scaling, etc.)\n")
	sb.WriteString("- concerns: array of potential architecture concerns or improvements\n\n")

	sb.WriteString("TOPOLOGY:\n")
	sb.WriteString(topoGraph.FormatContext())
	sb.WriteString("\n\nRESOURCES:\n")
	for _, r := range resources {
		sb.WriteString(fmt.Sprintf("- %s (%s) [%s]\n", r.Address, r.Type, r.Action))
	}

	return sb.String()
}

func parseInfraExplanation(raw string) *InfraExplanation {
	raw = strings.TrimSpace(raw)

	// Try direct unmarshal first
	var expl InfraExplanation
	if err := json.Unmarshal([]byte(raw), &expl); err == nil && expl.Overview != "" {
		return &expl
	}

	// Try generic map to handle overview-as-object
	var m map[string]interface{}
	if err := json.Unmarshal([]byte(raw), &m); err == nil {
		return infraExplFromMap(m)
	}

	// Try extracting JSON from code fences
	cleaned := raw
	if idx := strings.Index(raw, "```json"); idx != -1 {
		endIdx := strings.Index(raw[idx+7:], "```")
		if endIdx != -1 {
			cleaned = strings.TrimSpace(raw[idx+7 : idx+7+endIdx])
		}
	} else if idx := strings.Index(raw, "```"); idx != -1 {
		endIdx := strings.Index(raw[idx+3:], "```")
		if endIdx != -1 {
			cleaned = strings.TrimSpace(raw[idx+3 : idx+3+endIdx])
		}
	}

	if cleaned != raw {
		if err := json.Unmarshal([]byte(cleaned), &expl); err == nil && expl.Overview != "" {
			return &expl
		}
		if err := json.Unmarshal([]byte(cleaned), &m); err == nil {
			return infraExplFromMap(m)
		}
	}

	// Fallback: use raw text as overview
	return &InfraExplanation{
		Overview:     raw,
		Architecture: "Unable to parse structured response",
	}
}

// infraExplFromMap builds an InfraExplanation from a generic map, handling
// overview/architecture as either string or nested object.
func infraExplFromMap(m map[string]interface{}) *InfraExplanation {
	expl := &InfraExplanation{}

	switch v := m["overview"].(type) {
	case string:
		expl.Overview = v
	case map[string]interface{}:
		if s, ok := v["overview"].(string); ok {
			expl.Overview = s
		} else if s, ok := v["summary"].(string); ok {
			expl.Overview = s
		} else {
			b, _ := json.Marshal(v)
			expl.Overview = string(b)
		}
	default:
		if v != nil {
			expl.Overview = fmt.Sprintf("%v", v)
		}
	}

	if s, ok := m["architecture"].(string); ok {
		expl.Architecture = s
	}

	// Parse components array
	if arr, ok := m["components"].([]interface{}); ok {
		for _, item := range arr {
			if obj, ok := item.(map[string]interface{}); ok {
				c := ComponentExpl{}
				if s, ok := obj["resource"].(string); ok {
					c.Resource = s
				}
				if s, ok := obj["purpose"].(string); ok {
					c.Purpose = s
				}
				if s, ok := obj["role"].(string); ok {
					c.Role = s
				}
				expl.Components = append(expl.Components, c)
			}
		}
	}

	expl.Connections = infraToStringSlice(m["connections"])
	expl.Patterns = infraToStringSlice(m["patterns"])
	expl.Concerns = infraToStringSlice(m["concerns"])

	if expl.Overview == "" {
		expl.Overview = "Unable to parse structured response"
	}

	return expl
}

// infraToStringSlice converts an interface{} ([]interface{}) to []string.
func infraToStringSlice(v interface{}) []string {
	arr, ok := v.([]interface{})
	if !ok {
		return nil
	}
	result := make([]string, 0, len(arr))
	for _, item := range arr {
		if s, ok := item.(string); ok {
			result = append(result, s)
		}
	}
	return result
}

func printInfraExplanation(expl *InfraExplanation) {
	fmt.Println()
	fmt.Println("===============================================")
	if brFlag {
		fmt.Println("  Explicação da Infraestrutura")
	} else {
		fmt.Println("  Explain My Infrastructure")
	}
	fmt.Println("===============================================")
	fmt.Println()

	lblOverview := "OVERVIEW:"
	lblArch := "ARCHITECTURE:"
	lblComponents := "COMPONENTS:"
	lblPurpose := "Purpose"
	lblRole := "Role"
	lblConnections := "CONNECTIONS:"
	lblPatterns := "PATTERNS:"
	lblConcerns := "CONCERNS:"
	if brFlag {
		lblOverview = "VISÃO GERAL:"
		lblArch = "ARQUITETURA:"
		lblComponents = "COMPONENTES:"
		lblPurpose = "Finalidade"
		lblRole = "Papel"
		lblConnections = "CONEXÕES:"
		lblPatterns = "PADRÕES:"
		lblConcerns = "OBSERVAÇÕES:"
	}

	fmt.Println(lblOverview)
	fmt.Printf("  %s\n", expl.Overview)
	fmt.Println()

	if expl.Architecture != "" {
		fmt.Println(lblArch)
		fmt.Printf("  %s\n", expl.Architecture)
		fmt.Println()
	}

	if len(expl.Components) > 0 {
		fmt.Println(lblComponents)
		for _, c := range expl.Components {
			fmt.Printf("  - %s\n", c.Resource)
			fmt.Printf("    %s: %s\n", lblPurpose, c.Purpose)
			if c.Role != "" {
				fmt.Printf("    %s: %s\n", lblRole, c.Role)
			}
		}
		fmt.Println()
	}

	if len(expl.Connections) > 0 {
		fmt.Println(lblConnections)
		for _, c := range expl.Connections {
			fmt.Printf("  - %s\n", c)
		}
		fmt.Println()
	}

	if len(expl.Patterns) > 0 {
		fmt.Println(lblPatterns)
		for _, p := range expl.Patterns {
			fmt.Printf("  - %s\n", p)
		}
		fmt.Println()
	}

	if len(expl.Concerns) > 0 {
		fmt.Println(lblConcerns)
		for _, c := range expl.Concerns {
			fmt.Printf("  - %s\n", c)
		}
		fmt.Println()
	}

	fmt.Println("===============================================")
}

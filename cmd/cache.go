package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"github.com/leonamvasquez/terraview/internal/aicache"
	"github.com/leonamvasquez/terraview/internal/output"
)

var cacheCmd = &cobra.Command{
	Use:   "cache",
	Short: pick("Manage the AI response cache", "Gerenciar o cache de respostas IA"),
	Long:  pick("Manage the persistent AI response cache stored at ~/.terraview/cache/", "Gerencia o cache persistente de respostas IA armazenado em ~/.terraview/cache/"),
}

var cacheClearCmd = &cobra.Command{
	Use:   "clear",
	Short: pick("Delete the AI response cache", "Limpar o cache de respostas IA"),
	RunE:  runCacheClear,
}

var cacheStatusCmd = &cobra.Command{
	Use:   "status",
	Short: pick("Show cache statistics", "Exibir estatísticas do cache"),
	RunE:  runCacheStatus,
}

func init() {
	cacheCmd.AddCommand(cacheClearCmd)
	cacheCmd.AddCommand(cacheStatusCmd)
}

func runCacheClear(_ *cobra.Command, _ []string) error {
	dir := aicache.DiskCacheDir()
	if err := aicache.ClearDisk(dir); err != nil {
		return fmt.Errorf(pick("failed to clear cache: %w", "falha ao limpar cache: %w"), err)
	}
	fmt.Fprintf(os.Stdout, "%s %s\n", output.Prefix(),
		pick("AI cache cleared.", "Cache de IA limpo."))
	return nil
}

func runCacheStatus(_ *cobra.Command, _ []string) error {
	dir := aicache.DiskCacheDir()
	entries, totalSize, oldest, newest, err := aicache.DiskStats(dir)
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Fprintf(os.Stdout, "%s %s\n", output.Prefix(),
				pick("No cache found. Enable with 'cache: true' in .terraview.yaml.",
					"Nenhum cache encontrado. Habilite com 'cache: true' em .terraview.yaml."))
			return nil
		}
		return fmt.Errorf(pick("failed to read cache: %w", "falha ao ler cache: %w"), err)
	}

	fmt.Fprintf(os.Stdout, "%s %s\n", output.Prefix(),
		pick("AI Cache Status", "Status do Cache IA"))
	fmt.Fprintf(os.Stdout, "  %s %d\n",
		pick("Entries:", "Entradas:"), entries)
	fmt.Fprintf(os.Stdout, "  %s %s\n",
		pick("Total size:", "Tamanho total:"), formatBytes(totalSize))
	if entries > 0 {
		fmt.Fprintf(os.Stdout, "  %s %s\n",
			pick("Oldest:", "Mais antigo:"), oldest.Format(time.RFC3339))
		fmt.Fprintf(os.Stdout, "  %s %s\n",
			pick("Newest:", "Mais recente:"), newest.Format(time.RFC3339))
	}
	fmt.Fprintf(os.Stdout, "  %s %s\n",
		pick("Path:", "Caminho:"), dir)

	// Verificar se estamos em um diretório Terraform e mostrar hash do plano atual
	currentPlanHash := detectCurrentPlanHash()
	if currentPlanHash != "" {
		fmt.Fprintf(os.Stdout, "\n  %s %s\n",
			pick("Current plan hash:", "Hash do plano atual:"), currentPlanHash[:16]+"...")

		meta, lookupErr := aicache.LookupPlanHash(dir, currentPlanHash)
		if lookupErr != nil {
			fmt.Fprintf(os.Stdout, "  %s %s\n",
				pick("Cache hit:", "Cache hit:"),
				pick("no", "não"))
		} else {
			fmt.Fprintf(os.Stdout, "  %s %s\n",
				pick("Cache hit:", "Cache hit:"),
				pick("yes", "sim"))
			fmt.Fprintf(os.Stdout, "  %s %s/%s\n",
				pick("Cached with:", "Cacheado com:"), meta.Provider, meta.Model)
			fmt.Fprintf(os.Stdout, "  %s %s\n",
				pick("Cached at:", "Cacheado em:"), meta.CreatedAt.Format(time.RFC3339))
		}
	}

	return nil
}

// detectCurrentPlanHash procura plan.json ou tfplan no diretório atual
// e calcula o hash SHA-256 do conteúdo para comparação com o cache.
func detectCurrentPlanHash() string {
	cwd, err := os.Getwd()
	if err != nil {
		return ""
	}

	// Procurar arquivos de plano em ordem de preferência
	for _, name := range []string{"plan.json", "tfplan"} {
		planPath := filepath.Join(cwd, name)
		data, err := os.ReadFile(planPath)
		if err == nil && len(data) > 0 {
			return aicache.PlanHash(data)
		}
	}
	return ""
}

func formatBytes(b int64) string {
	switch {
	case b >= 1024*1024:
		return fmt.Sprintf("%.1f MB", float64(b)/(1024*1024))
	case b >= 1024:
		return fmt.Sprintf("%.1f KB", float64(b)/1024)
	default:
		return fmt.Sprintf("%d B", b)
	}
}

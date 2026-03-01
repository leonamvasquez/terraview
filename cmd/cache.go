package cmd

import (
	"fmt"
	"os"
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
	path := aicache.DiskCachePath()
	if err := aicache.ClearDisk(path); err != nil {
		return fmt.Errorf(pick("failed to clear cache: %w", "falha ao limpar cache: %w"), err)
	}
	fmt.Fprintf(os.Stdout, "%s %s\n", output.Prefix(),
		pick("AI cache cleared.", "Cache de IA limpo."))
	return nil
}

func runCacheStatus(_ *cobra.Command, _ []string) error {
	path := aicache.DiskCachePath()
	entries, fileSize, oldest, newest, err := aicache.DiskStats(path)
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Fprintf(os.Stdout, "%s %s\n", output.Prefix(),
				pick("No cache file found. Enable with 'cache: true' in .terraview.yaml.",
					"Nenhum arquivo de cache encontrado. Habilite com 'cache: true' em .terraview.yaml."))
			return nil
		}
		return fmt.Errorf(pick("failed to read cache: %w", "falha ao ler cache: %w"), err)
	}

	fmt.Fprintf(os.Stdout, "%s %s\n", output.Prefix(),
		pick("AI Cache Status", "Status do Cache IA"))
	fmt.Fprintf(os.Stdout, "  %s %d\n",
		pick("Entries:", "Entradas:"), entries)
	fmt.Fprintf(os.Stdout, "  %s %s\n",
		pick("File size:", "Tamanho:"), formatBytes(fileSize))
	if entries > 0 {
		fmt.Fprintf(os.Stdout, "  %s %s\n",
			pick("Oldest:", "Mais antigo:"), oldest.Format(time.RFC3339))
		fmt.Fprintf(os.Stdout, "  %s %s\n",
			pick("Newest:", "Mais recente:"), newest.Format(time.RFC3339))
	}
	fmt.Fprintf(os.Stdout, "  %s %s\n",
		pick("Path:", "Caminho:"), path)

	return nil
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

package cmd

import (
	"fmt"

	"github.com/leonamvasquez/terraview/internal/bininstaller"
	"github.com/leonamvasquez/terraview/internal/platform"
	"github.com/leonamvasquez/terraview/internal/scanner"
	"github.com/spf13/cobra"
)

var scannersCmd = &cobra.Command{
	Use:   "scanners",
	Short: "Manage security scanners",
	Long:  "List, install, and manage security scanner binaries.",
}

var scannersListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all scanners with status",
	RunE: func(cmd *cobra.Command, args []string) error {
		cache := bininstaller.LoadCache()
		p, _ := platform.Detect()

		if brFlag {
			fmt.Printf("Plataforma: %s\n", p.String())
			fmt.Printf("Diretório de instalação: %s\n\n", p.InstallDir())
		} else {
			fmt.Printf("Platform: %s\n", p.String())
			fmt.Printf("Install directory: %s\n\n", p.InstallDir())
		}

		all := scanner.DefaultManager.All()
		for _, name := range sortedScannerNames(all) {
			s := all[name]
			status := "✗ not installed"
			version := ""

			if s.Available() {
				status = "✓ available"
				version = s.Version()
			}

			entry, cached := cache.Get(name)
			cacheInfo := ""
			if cached {
				cacheInfo = fmt.Sprintf(" (cached v%s)", entry.Version)
			}

			inst := bininstaller.InstallerFor(name)
			autoInstall := "no"
			if inst != nil && inst.SupportsDirectBinary() {
				autoInstall = "yes"
			}

			fmt.Printf("  [%s] %-12s %-16s auto-install: %s%s\n",
				status, name, version, autoInstall, cacheInfo)
		}
		return nil
	},
}

var scannersInstallCmd = &cobra.Command{
	Use:   "install [scanner...]",
	Short: "Install scanner binaries",
	Long:  "Download and install scanner binaries for the current platform.",
	RunE: func(cmd *cobra.Command, args []string) error {
		p, _ := platform.Detect()
		forceReinstall, _ := cmd.Flags().GetBool("force")
		cache := bininstaller.LoadCache()

		if brFlag {
			fmt.Printf("Plataforma detectada: %s\n", p.String())
		} else {
			fmt.Printf("Detected platform: %s\n", p.String())
		}

		var installers []bininstaller.BinaryInstaller
		if len(args) == 0 || (len(args) == 1 && args[0] == "all") {
			installers = bininstaller.AllInstallers()
		} else {
			for _, name := range args {
				inst := bininstaller.InstallerFor(name)
				if inst == nil {
					fmt.Printf("  [!] Unknown scanner: %s\n", name)
					continue
				}
				installers = append(installers, inst)
			}
		}

		for _, inst := range installers {
			name := inst.Name()

			// Skip if already installed and not forcing
			if !forceReinstall && cache.IsInstalled(name) {
				entry, _ := cache.Get(name)
				fmt.Printf("  [skip] %s v%s already installed at %s\n",
					name, entry.Version, entry.Path)
				continue
			}

			if !inst.SupportsDirectBinary() {
				fb := inst.FallbackCommand(p)
				fmt.Printf("  [info] %s: no binary download available. %s\n", name, fb)
				continue
			}

			if brFlag {
				fmt.Printf("  [↓] Instalando %s...\n", name)
			} else {
				fmt.Printf("  [↓] Installing %s...\n", name)
			}

			result := bininstaller.Install(inst, p, "")
			if result.Installed {
				cache.Set(result)
				fmt.Printf("  [✓] %s v%s → %s\n", name, result.Version, result.Path)
			} else {
				fmt.Printf("  [✗] %s: %s\n", name, result.Error)
				if result.Fallback != "" {
					fmt.Printf("      Fallback: %s\n", result.Fallback)
				}
			}
		}

		if err := cache.Save(); err != nil {
			fmt.Printf("  [warn] Failed to save cache: %v\n", err)
		}

		return nil
	},
}

func init() {
	scannersInstallCmd.Flags().BoolP("force", "f", false, "Force reinstall even if already cached")
	scannersCmd.AddCommand(scannersListCmd)
	scannersCmd.AddCommand(scannersInstallCmd)
}

func sortedScannerNames(m map[string]scanner.Scanner) []string {
	names := make([]string, 0, len(m))
	for k := range m {
		names = append(names, k)
	}
	// Simple sort
	for i := 0; i < len(names); i++ {
		for j := i + 1; j < len(names); j++ {
			if names[i] > names[j] {
				names[i], names[j] = names[j], names[i]
			}
		}
	}
	return names
}

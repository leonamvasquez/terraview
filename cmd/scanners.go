package cmd

import (
	"fmt"
	"strings"

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

// ─────────────────────────────────────────────────────────────
// scanners list
// ─────────────────────────────────────────────────────────────

var scannersListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all scanners with installation status",
	RunE: func(cmd *cobra.Command, args []string) error {
		p, _ := platform.Detect()
		cache := bininstaller.LoadCache()

		if brFlag {
			fmt.Printf("  Plataforma: %s\n\n", p.String())
		} else {
			fmt.Printf("  Platform: %s\n\n", p.String())
		}

		all := scanner.DefaultManager.All()
		for _, name := range sortedScannerNames(all) {
			s := all[name]
			spec := bininstaller.SpecFor(name)

			var statusIcon, version, details string

			if s.Available() {
				statusIcon = ansiGreen + "[✓]" + ansiReset
				version = s.Version()
				// Where is it installed?
				if entry, ok := cache.Get(name); ok {
					details = fmt.Sprintf("binary (%s)", entry.Path)
				} else {
					details = "system PATH"
				}
			} else {
				statusIcon = ansiRed + "[✗]" + ansiReset
				version = ansiDim + "not installed" + ansiReset
				if spec != nil {
					fb := bininstaller.FallbackFor(spec, p)
					if fb != "" {
						details = ansiDim + fb + ansiReset
					}
				}
			}

			// Deprecation warning inline
			deprNote := ""
			if spec != nil && spec.Deprecated != "" {
				deprNote = "  " + ansiYellow + spec.Deprecated + ansiReset
			}

			fmt.Printf("  %s %-12s %-20s %s%s\n",
				statusIcon, name, version, ansiDim+details+ansiReset, deprNote)
		}

		// Summary
		available := scanner.DefaultManager.Available()
		missing := scanner.DefaultManager.Missing()
		fmt.Printf("\n  %d/%d scanners installed", len(available), len(all))
		if len(missing) > 0 {
			names := make([]string, 0, len(missing))
			for _, m := range missing {
				names = append(names, m.Name)
			}
			if brFlag {
				fmt.Printf(" — execute 'tv scanners install' para instalar: %s", strings.Join(names, ", "))
			} else {
				fmt.Printf(" — run 'tv scanners install' to install: %s", strings.Join(names, ", "))
			}
		}
		fmt.Println()
		return nil
	},
}

// ─────────────────────────────────────────────────────────────
// scanners install
// ─────────────────────────────────────────────────────────────

var scannersInstallCmd = &cobra.Command{
	Use:   "install [scanner...]",
	Short: "Install one or more scanner binaries",
	Long: `Install security scanners using the best available method:
  1. OS package manager (brew, pip3, choco, scoop, ...)
  2. Direct binary download from official releases
  3. Manual instructions when automatic install is not possible

Examples:
  tv scanners install              # install all missing scanners
  tv scanners install tfsec        # install tfsec only
  tv scanners install checkov kics # install specific scanners`,
	RunE: func(cmd *cobra.Command, args []string) error {
		p, _ := platform.Detect()
		forceReinstall, _ := cmd.Flags().GetBool("force")
		cache := bininstaller.LoadCache()

		if brFlag {
			fmt.Printf("  Plataforma detectada: %s\n\n", p.String())
		} else {
			fmt.Printf("  Detected platform: %s\n\n", p.String())
		}

		// Determine which specs to process
		var specs []*bininstaller.ScannerSpec
		if len(args) == 0 || (len(args) == 1 && args[0] == "all") {
			specs = bininstaller.AllSpecs()
		} else {
			for _, name := range args {
				spec := bininstaller.SpecFor(name)
				if spec == nil {
					fmt.Printf("  [!] Unrecognized scanner: %s\n", name)
					continue
				}
				specs = append(specs, spec)
			}
		}

		for _, spec := range specs {
			name := spec.Name
			s, exists := scanner.DefaultManager.All()[name]

			// Show archived/deprecated notice before attempting install
			if spec.Deprecated != "" {
				fmt.Printf("  %s%s%s\n", ansiYellow, spec.Deprecated, ansiReset)
			}

			// Skip if already available and not forced
			if !forceReinstall {
				if exists && s.Available() {
					ver := s.Version()
					fmt.Printf("  [skip] %-12s already installed %s\n", name, ansiDim+ver+ansiReset)
					continue
				}
				if entry, ok := cache.Get(name); ok {
					fmt.Printf("  [skip] %-12s already in cache v%s → %s\n",
						name, entry.Version, ansiDim+entry.Path+ansiReset)
					continue
				}
			}

			if brFlag {
				fmt.Printf("  [↓]   %-12s instalando...\n", name)
			} else {
				fmt.Printf("  [↓]   %-12s installing...\n", name)
			}

			result := bininstaller.SmartInstall(spec, p, "")

			switch {
			case result.Installed:
				cache.Set(result)
				loc := result.Path
				if loc == "" {
					loc = "system"
				}
				what := result.Method
				if what == "" {
					what = "package manager"
				}
				fmt.Printf("  [✓]   %-12s installed via %s → %s\n",
					name, ansiGreen+what+ansiReset, ansiDim+loc+ansiReset)

			case result.Fallback != "":
				// Auto-install not possible — show manual command
				if brFlag {
					fmt.Printf("  [info] %-12s instalação manual necessária:\n", name)
				} else {
					fmt.Printf("  [info] %-12s manual installation required:\n", name)
				}
				fmt.Printf("           $ %s%s%s\n", ansiBold, result.Fallback, ansiReset)
				if name == "kics" && p.OS == "windows" {
					fmt.Printf("           (Windows: Docker is the only supported method for kics)\n")
				}

			default:
				// Failed with error
				fmt.Printf("  [✗]   %-12s %s\n", name, ansiRed+result.Error+ansiReset)
			}
		}

		if err := cache.Save(); err != nil {
			fmt.Printf("  [warn] Failed to save cache: %v\n", err)
		}

		return nil
	},
}

func init() {
	scannersInstallCmd.Flags().BoolP("force", "f", false, "Force reinstall even if already installed")
	scannersCmd.AddCommand(scannersListCmd)
	scannersCmd.AddCommand(scannersInstallCmd)
}

func sortedScannerNames(m map[string]scanner.Scanner) []string {
	names := make([]string, 0, len(m))
	for k := range m {
		names = append(names, k)
	}
	for i := 0; i < len(names); i++ {
		for j := i + 1; j < len(names); j++ {
			if names[i] > names[j] {
				names[i], names[j] = names[j], names[i]
			}
		}
	}
	return names
}

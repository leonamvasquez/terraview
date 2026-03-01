package cmd

import (
	"fmt"
	"sort"
	"strings"

	"github.com/leonamvasquez/terraview/internal/bininstaller"
	"github.com/leonamvasquez/terraview/internal/config"
	"github.com/leonamvasquez/terraview/internal/output"
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
		cfg, err := config.Load(workDir)
		if err != nil {
			return fmt.Errorf("config error: %w", err)
		}

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
				if brFlag {
					version = ansiDim + "não instalado" + ansiReset
				} else {
					version = ansiDim + "not installed" + ansiReset
				}
				if spec != nil {
					fb := bininstaller.FallbackFor(spec, p)
					if fb != "" {
						details = ansiDim + fb + ansiReset
					}
				}
			}

			// Default indicator
			defaultTag := ""
			if cfg.Scanner.Default == name {
				defaultTag = " " + ansiCyan + "(default)" + ansiReset
			}

			// Deprecation warning inline
			deprNote := ""
			if spec != nil && spec.Deprecated != "" {
				deprNote = "\n    " + ansiYellow + spec.Deprecated + ansiReset
			}

			fmt.Printf("  %s %-12s %-20s %s%s%s\n",
				statusIcon, name, version, ansiDim+details+ansiReset, defaultTag, deprNote)
		}

		// Summary
		available := scanner.DefaultManager.Available()
		missing := scanner.DefaultManager.Missing()
		fmt.Printf("\n  %d/%d scanners installed", len(available), len(all))
		if len(missing) > 0 {
			if brFlag {
				fmt.Printf(" — instale com 'tv scanners install <nome>' ou '--all'")
			} else {
				fmt.Printf(" — install with 'tv scanners install <name>' or '--all'")
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
  tv scanners install checkov        # install checkov only
  tv scanners install tfsec          # install tfsec only
  tv scanners install terrascan      # install terrascan only
  tv scanners install checkov tfsec  # install specific scanners
  tv scanners install --all          # install all missing scanners`,
	RunE: func(cmd *cobra.Command, args []string) error {
		p, _ := platform.Detect()
		forceReinstall, _ := cmd.Flags().GetBool("force")
		installAll, _ := cmd.Flags().GetBool("all")
		cache := bininstaller.LoadCache()

		// Require either scanner names or --all
		if len(args) == 0 && !installAll {
			if brFlag {
				return fmt.Errorf("especifique um scanner ou use --all\n\nExemplos:\n  terraview scanners install checkov\n  terraview scanners install tfsec\n  terraview scanners install terrascan\n  terraview scanners install --all")
			}
			return fmt.Errorf("specify a scanner or use --all\n\nExamples:\n  terraview scanners install checkov\n  terraview scanners install tfsec\n  terraview scanners install terrascan\n  terraview scanners install --all")
		}

		if brFlag {
			fmt.Printf("  Plataforma detectada: %s\n\n", p.String())
		} else {
			fmt.Printf("  Detected platform: %s\n\n", p.String())
		}

		// Determine which specs to process
		var specs []*bininstaller.ScannerSpec
		if installAll {
			specs = bininstaller.AllSpecs()
		} else {
			for _, name := range args {
				spec := bininstaller.SpecFor(name)
				if spec == nil {
					fmt.Printf("  [!] Unknown scanner: %s. Valid: %s\n", name, strings.Join(scanner.ValidScanners, ", "))
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

			installingMsg := fmt.Sprintf("Installing %s...", name)
			if brFlag {
				installingMsg = fmt.Sprintf("Instalando %s...", name)
			}

			installSpinner := output.NewSpinner(installingMsg)
			installSpinner.Start()
			result := bininstaller.SmartInstall(spec, p, "")
			installSpinner.Stop(result.Installed)

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
	scannersInstallCmd.Flags().Bool("force", false, "Force reinstall even if already installed")
	scannersInstallCmd.Flags().Bool("all", false, "Install all missing scanners")
	scannersCmd.AddCommand(scannersListCmd)
	scannersCmd.AddCommand(scannersInstallCmd)
	scannersCmd.AddCommand(scannersDefaultCmd)
}

// ─────────────────────────────────────────────────────────────
// scanners default
// ─────────────────────────────────────────────────────────────

var scannersDefaultCmd = &cobra.Command{
	Use:   "default [scanner]",
	Short: "Set or show the default scanner",
	Long: `Set a default scanner so 'terraview scan' runs without specifying a name.

Examples:
  tv scanners default              # show current default
  tv scanners default checkov      # set checkov as default
  tv scanners default tfsec        # set tfsec as default`,
	Args: cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := config.Load(workDir)
		if err != nil {
			return fmt.Errorf("config error: %w", err)
		}

		// Show current default
		if len(args) == 0 {
			if cfg.Scanner.Default == "" {
				if brFlag {
					fmt.Println("  Nenhum scanner padrão configurado.")
					fmt.Println("  O scanner será selecionado automaticamente por prioridade: checkov > tfsec > terrascan")
					fmt.Println()
					fmt.Printf("  %sDefina com: terraview scanners default <nome>%s\n", ansiDim, ansiReset)
				} else {
					fmt.Println("  No default scanner configured.")
					fmt.Println("  Scanner will be auto-selected by priority: checkov > tfsec > terrascan")
					fmt.Println()
					fmt.Printf("  %sSet with: terraview scanners default <name>%s\n", ansiDim, ansiReset)
				}
			} else {
				if brFlag {
					fmt.Printf("  Scanner padrão: %s%s%s\n", ansiBold, cfg.Scanner.Default, ansiReset)
				} else {
					fmt.Printf("  Default scanner: %s%s%s\n", ansiBold, cfg.Scanner.Default, ansiReset)
				}
			}
			return nil
		}

		name := strings.ToLower(args[0])

		// Validate scanner name
		valid := false
		for _, v := range scanner.ValidScanners {
			if v == name {
				valid = true
				break
			}
		}
		if !valid {
			avail := scanner.DefaultManager.Available()
			if len(avail) == 0 {
				return fmt.Errorf("unknown scanner %q. Valid scanners: %s",
					name, strings.Join(scanner.ValidScanners, ", "))
			}
			names := make([]string, 0, len(avail))
			for _, a := range avail {
				names = append(names, a.Name())
			}
			sort.Strings(names)
			if brFlag {
				return fmt.Errorf("scanner %q não reconhecido. Scanners instalados:\n  %s",
					name, strings.Join(names, "\n  "))
			}
			return fmt.Errorf("unknown scanner %q. Installed scanners:\n  %s",
				name, strings.Join(names, "\n  "))
		}

		// Check if installed
		s, ok := scanner.DefaultManager.Get(name)
		if !ok || !s.Available() {
			if brFlag {
				return fmt.Errorf("scanner %q não está instalado. Instale com:\n  terraview scanners install %s", name, name)
			}
			return fmt.Errorf("scanner %q is not installed. Install with:\n  terraview scanners install %s", name, name)
		}

		// Save to global config
		if err := config.SaveDefaultScanner(name); err != nil {
			return fmt.Errorf("failed to save default: %w", err)
		}

		if brFlag {
			fmt.Printf("  %s✔%s Scanner padrão definido: %s%s%s\n",
				ansiGreen, ansiReset, ansiBold, name, ansiReset)
			fmt.Printf("  %sAgora 'terraview scan' usará %s automaticamente.%s\n",
				ansiDim, name, ansiReset)
		} else {
			fmt.Printf("  %s✔%s Default scanner set: %s%s%s\n",
				ansiGreen, ansiReset, ansiBold, name, ansiReset)
			fmt.Printf("  %sNow 'terraview scan' will use %s automatically.%s\n",
				ansiDim, name, ansiReset)
		}

		return nil
	},
}

func sortedScannerNames(m map[string]scanner.Scanner) []string {
	names := make([]string, 0, len(m))
	for k := range m {
		names = append(names, k)
	}
	sort.Strings(names)
	return names
}

package scanner

import (
	"github.com/leonamvasquez/terraview/internal/builtin"
	"github.com/leonamvasquez/terraview/internal/rules"
)

func init() {
	Register(&BuiltinScanner{})
}

// BuiltinScanner implements the Scanner interface using the built-in Go rule
// engine. It requires no external binaries and runs entirely in-process.
type BuiltinScanner struct{}

func (s *BuiltinScanner) Name() string               { return "builtin" }
func (s *BuiltinScanner) Available() bool            { return true }
func (s *BuiltinScanner) Version() string            { return "builtin" }
func (s *BuiltinScanner) Priority() int              { return 10 }
func (s *BuiltinScanner) SupportedModes() []ScanMode { return []ScanMode{ScanModePlan} }

func (s *BuiltinScanner) EnsureInstalled() (bool, InstallHint) {
	return true, InstallHint{}
}

func (s *BuiltinScanner) Scan(ctx ScanContext) ([]rules.Finding, error) {
	return builtin.Scan(ctx.PlanPath)
}

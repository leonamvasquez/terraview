package ai

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type mockProvider struct {
	name string
}

func (m *mockProvider) Name() string                       { return m.name }
func (m *mockProvider) Validate(ctx context.Context) error { return nil }
func (m *mockProvider) Analyze(ctx context.Context, req Request) (Completion, error) {
	return Completion{Provider: m.name, Summary: "mock"}, nil
}

func TestRegistry_RegisterAndCreate(t *testing.T) {
	r := NewRegistry()

	r.Register("mock", func(cfg ProviderConfig) (Provider, error) {
		return &mockProvider{name: "mock"}, nil
	}, ProviderInfo{DisplayName: "Mock Provider"})

	if !r.Has("mock") {
		t.Fatal("expected mock provider to be registered")
	}

	provider, err := r.Create("mock", ProviderConfig{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if provider.Name() != "mock" {
		t.Errorf("expected name 'mock', got %q", provider.Name())
	}
}

func TestRegistry_CreateNotFound(t *testing.T) {
	r := NewRegistry()

	_, err := r.Create("nonexistent", ProviderConfig{})
	if err == nil {
		t.Fatal("expected error for nonexistent provider")
	}
}

func TestRegistry_Names(t *testing.T) {
	r := NewRegistry()

	r.Register("beta", func(cfg ProviderConfig) (Provider, error) {
		return &mockProvider{name: "beta"}, nil
	}, ProviderInfo{DisplayName: "Beta"})

	r.Register("alpha", func(cfg ProviderConfig) (Provider, error) {
		return &mockProvider{name: "alpha"}, nil
	}, ProviderInfo{DisplayName: "Alpha"})

	names := r.Names()
	if len(names) != 2 {
		t.Fatalf("expected 2 names, got %d", len(names))
	}
	if names[0] != "alpha" || names[1] != "beta" {
		t.Errorf("expected sorted names [alpha, beta], got %v", names)
	}
}

func TestRegistry_List(t *testing.T) {
	r := NewRegistry()

	r.Register("test", func(cfg ProviderConfig) (Provider, error) {
		return &mockProvider{name: "test"}, nil
	}, ProviderInfo{DisplayName: "Test Provider", RequiresKey: true, EnvVarKey: "TEST_KEY"})

	infos := r.List()
	if len(infos) != 1 {
		t.Fatalf("expected 1 info, got %d", len(infos))
	}

	if infos[0].DisplayName != "Test Provider" {
		t.Errorf("expected 'Test Provider', got %q", infos[0].DisplayName)
	}
	if !infos[0].RequiresKey {
		t.Error("expected RequiresKey to be true")
	}
}

func TestRegistry_DuplicatePanics(t *testing.T) {
	r := NewRegistry()

	factory := func(cfg ProviderConfig) (Provider, error) {
		return &mockProvider{name: "dup"}, nil
	}

	r.Register("dup", factory, ProviderInfo{DisplayName: "Dup"})

	defer func() {
		if recover() == nil {
			t.Fatal("expected panic on duplicate registration")
		}
	}()

	r.Register("dup", factory, ProviderInfo{DisplayName: "Dup2"})
}

// ---------------------------------------------------------------------------
// ProviderError tests (errors.go)
// ---------------------------------------------------------------------------

func TestProviderError_Error(t *testing.T) {
	e := &ProviderError{
		Provider: "claude",
		Op:       "analyze",
		Err:      errors.New("rate limit"),
	}
	got := e.Error()
	if got != "ai/claude: analyze: rate limit" {
		t.Errorf("Error() = %q", got)
	}
}

func TestProviderError_Unwrap(t *testing.T) {
	inner := errors.New("timeout")
	e := &ProviderError{Provider: "gemini", Op: "connect", Err: inner}
	if !errors.Is(e, inner) {
		t.Error("Unwrap should return inner error")
	}
}

func TestProviderError_UnwrapSentinel(t *testing.T) {
	e := NewProviderError("openai", "validate", ErrProviderValidation)
	if !errors.Is(e, ErrProviderValidation) {
		t.Error("should unwrap to ErrProviderValidation")
	}
}

func TestNewProviderError(t *testing.T) {
	err := errors.New("oops")
	pe := NewProviderError("ollama", "pull", err)
	if pe.Provider != "ollama" {
		t.Errorf("Provider = %q", pe.Provider)
	}
	if pe.Op != "pull" {
		t.Errorf("Op = %q", pe.Op)
	}
	if pe.Err != err {
		t.Error("Err should be the original error")
	}
}

func TestProviderError_ErrorsAs(t *testing.T) {
	pe := NewProviderError("claude", "analyze", errors.New("fail"))
	var target *ProviderError
	if !errors.As(pe, &target) {
		t.Fatal("errors.As should match *ProviderError")
	}
	if target.Provider != "claude" {
		t.Errorf("Provider = %q", target.Provider)
	}
}

// ---------------------------------------------------------------------------
// PromptLoader tests (prompts.go)
// ---------------------------------------------------------------------------

func TestNewPromptLoader(t *testing.T) {
	pl := NewPromptLoader("/some/dir")
	if pl == nil {
		t.Fatal("expected non-nil PromptLoader")
	}
}

func TestPromptLoader_Load_AllFiles(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "system.md"), []byte("sys prompt"), 0644)
	os.WriteFile(filepath.Join(dir, "security.md"), []byte("sec rules"), 0644)
	os.WriteFile(filepath.Join(dir, "architecture.md"), []byte("arch rules"), 0644)
	os.WriteFile(filepath.Join(dir, "standards.md"), []byte("std rules"), 0644)
	os.WriteFile(filepath.Join(dir, "cost.md"), []byte("cost rules"), 0644)
	os.WriteFile(filepath.Join(dir, "compliance.md"), []byte("compliance rules"), 0644)
	os.WriteFile(filepath.Join(dir, "context-analysis.md"), []byte("context rules"), 0644)

	pl := NewPromptLoader(dir)
	ps, err := pl.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if ps.System != "sys prompt" {
		t.Errorf("System = %q", ps.System)
	}
	if ps.Security != "sec rules" {
		t.Errorf("Security = %q", ps.Security)
	}
	if ps.Architecture != "arch rules" {
		t.Errorf("Architecture = %q", ps.Architecture)
	}
	if ps.Standards != "std rules" {
		t.Errorf("Standards = %q", ps.Standards)
	}
	if ps.Cost != "cost rules" {
		t.Errorf("Cost = %q", ps.Cost)
	}
	if ps.Compliance != "compliance rules" {
		t.Errorf("Compliance = %q", ps.Compliance)
	}
	if ps.ContextAnalysis != "context rules" {
		t.Errorf("ContextAnalysis = %q", ps.ContextAnalysis)
	}
}

func TestPromptLoader_Load_OnlySystem(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "system.md"), []byte("base"), 0644)

	pl := NewPromptLoader(dir)
	ps, err := pl.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if ps.System != "base" {
		t.Errorf("System = %q", ps.System)
	}
	// Optional files should be empty, not error
	if ps.Security != "" || ps.Architecture != "" || ps.Standards != "" || ps.Cost != "" || ps.Compliance != "" || ps.ContextAnalysis != "" {
		t.Error("optional prompts should be empty when files missing")
	}
}

func TestPromptLoader_Load_MissingSystem(t *testing.T) {
	dir := t.TempDir()
	// No system.md

	pl := NewPromptLoader(dir)
	_, err := pl.Load()
	if err == nil {
		t.Fatal("expected error when system.md missing")
	}
	if !strings.Contains(err.Error(), "system prompt") {
		t.Errorf("error = %q, want 'system prompt'", err)
	}
}

func TestPromptLoader_ReadPrompt_Success(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "test.md"), []byte("content"), 0644)

	pl := NewPromptLoader(dir)
	got, err := pl.readPrompt("test.md")
	if err != nil {
		t.Fatalf("readPrompt: %v", err)
	}
	if got != "content" {
		t.Errorf("got %q", got)
	}
}

func TestPromptLoader_ReadPrompt_NotFound(t *testing.T) {
	pl := NewPromptLoader(t.TempDir())
	_, err := pl.readPrompt("missing.md")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

// ---------------------------------------------------------------------------
// NewProvider (factory.go) — mock-based test
// ---------------------------------------------------------------------------

type failValidateProvider struct {
	mockProvider
}

func (f *failValidateProvider) Validate(ctx context.Context) error {
	return errors.New("missing API key")
}

func TestNewProvider_Success(t *testing.T) {
	oldDefault := globalRegistry
	defer func() { globalRegistry = oldDefault }()

	globalRegistry = NewRegistry()
	Register("testprov", func(cfg ProviderConfig) (Provider, error) {
		return &mockProvider{name: "testprov"}, nil
	}, ProviderInfo{DisplayName: "Test"})

	p, err := NewProvider(context.Background(), "testprov", ProviderConfig{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.Name() != "testprov" {
		t.Errorf("Name() = %q", p.Name())
	}
}

func TestNewProvider_ValidationFails(t *testing.T) {
	oldDefault := globalRegistry
	defer func() { globalRegistry = oldDefault }()

	globalRegistry = NewRegistry()
	Register("failprov", func(cfg ProviderConfig) (Provider, error) {
		return &failValidateProvider{mockProvider{name: "failprov"}}, nil
	}, ProviderInfo{DisplayName: "Fail"})

	_, err := NewProvider(context.Background(), "failprov", ProviderConfig{})
	if err == nil {
		t.Fatal("expected validation error")
	}
	var pe *ProviderError
	if !errors.As(err, &pe) {
		t.Fatal("expected ProviderError")
	}
	if pe.Op != "validate" {
		t.Errorf("Op = %q, want validate", pe.Op)
	}
}

func TestNewProvider_NotFound(t *testing.T) {
	oldDefault := globalRegistry
	defer func() { globalRegistry = oldDefault }()

	globalRegistry = NewRegistry()
	_, err := NewProvider(context.Background(), "nonexist", ProviderConfig{})
	if err == nil {
		t.Fatal("expected error for nonexistent provider")
	}
}

// ---------------------------------------------------------------------------
// Package-level wrappers (globalRegistry delegates)
// ---------------------------------------------------------------------------

func TestGlobalNames(t *testing.T) {
	oldDefault := globalRegistry
	defer func() { globalRegistry = oldDefault }()

	globalRegistry = NewRegistry()
	globalRegistry.Register("zz", func(cfg ProviderConfig) (Provider, error) {
		return &mockProvider{name: "zz"}, nil
	}, ProviderInfo{DisplayName: "ZZ"})
	globalRegistry.Register("aa", func(cfg ProviderConfig) (Provider, error) {
		return &mockProvider{name: "aa"}, nil
	}, ProviderInfo{DisplayName: "AA"})

	names := Names()
	if len(names) != 2 {
		t.Fatalf("expected 2 names, got %d", len(names))
	}
	if names[0] != "aa" || names[1] != "zz" {
		t.Errorf("expected sorted [aa, zz], got %v", names)
	}
}

func TestGlobalList(t *testing.T) {
	oldDefault := globalRegistry
	defer func() { globalRegistry = oldDefault }()

	globalRegistry = NewRegistry()
	globalRegistry.Register("test", func(cfg ProviderConfig) (Provider, error) {
		return &mockProvider{name: "test"}, nil
	}, ProviderInfo{DisplayName: "Test"})

	infos := List()
	if len(infos) != 1 {
		t.Fatalf("expected 1 info, got %d", len(infos))
	}
	if infos[0].Name != "test" {
		t.Errorf("expected name 'test', got %q", infos[0].Name)
	}
}

func TestGlobalHas(t *testing.T) {
	oldDefault := globalRegistry
	defer func() { globalRegistry = oldDefault }()

	globalRegistry = NewRegistry()
	globalRegistry.Register("found", func(cfg ProviderConfig) (Provider, error) {
		return &mockProvider{name: "found"}, nil
	}, ProviderInfo{DisplayName: "Found"})

	if !Has("found") {
		t.Error("expected Has to return true for registered provider")
	}
	if Has("missing") {
		t.Error("expected Has to return false for missing provider")
	}
}

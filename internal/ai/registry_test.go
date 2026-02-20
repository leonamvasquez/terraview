package ai

import (
	"context"
	"testing"
)

type mockProvider struct {
	name string
}

func (m *mockProvider) Name() string                                        { return m.name }
func (m *mockProvider) Validate(ctx context.Context) error                  { return nil }
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

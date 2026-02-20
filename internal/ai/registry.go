package ai

import (
	"fmt"
	"sort"
	"sync"
)

// Registry holds all registered AI provider factories.
// Thread-safe via sync.RWMutex.
type Registry struct {
	mu        sync.RWMutex
	factories map[string]ProviderFactory
	info      map[string]ProviderInfo
}

// globalRegistry is the default registry used by package-level functions.
var globalRegistry = NewRegistry()

// NewRegistry creates an empty Registry.
func NewRegistry() *Registry {
	return &Registry{
		factories: make(map[string]ProviderFactory),
		info:      make(map[string]ProviderInfo),
	}
}

// Register adds a provider factory to the registry.
// Panics if a provider with the same name is already registered (programming error).
func Register(name string, factory ProviderFactory, info ProviderInfo) {
	globalRegistry.Register(name, factory, info)
}

// Register adds a provider factory to this registry.
func (r *Registry) Register(name string, factory ProviderFactory, info ProviderInfo) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.factories[name]; exists {
		panic(fmt.Sprintf("ai: provider %q already registered", name))
	}

	r.factories[name] = factory
	info.Name = name
	r.info[name] = info
}

// Create instantiates a provider by name from the global registry.
func Create(name string, cfg ProviderConfig) (Provider, error) {
	return globalRegistry.Create(name, cfg)
}

// Create instantiates a provider by name.
func (r *Registry) Create(name string, cfg ProviderConfig) (Provider, error) {
	r.mu.RLock()
	factory, exists := r.factories[name]
	r.mu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("%w: %q (available: %v)", ErrProviderNotFound, name, r.Names())
	}

	return factory(cfg)
}

// Names returns all registered provider names, sorted.
func Names() []string {
	return globalRegistry.Names()
}

// Names returns all registered provider names in this registry, sorted.
func (r *Registry) Names() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	names := make([]string, 0, len(r.factories))
	for name := range r.factories {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// List returns info for all registered providers.
func List() []ProviderInfo {
	return globalRegistry.List()
}

// List returns info for all registered providers in this registry.
func (r *Registry) List() []ProviderInfo {
	r.mu.RLock()
	defer r.mu.RUnlock()

	infos := make([]ProviderInfo, 0, len(r.info))
	for _, info := range r.info {
		infos = append(infos, info)
	}
	sort.Slice(infos, func(i, j int) bool {
		return infos[i].Name < infos[j].Name
	})
	return infos
}

// Has checks if a provider is registered.
func Has(name string) bool {
	return globalRegistry.Has(name)
}

// Has checks if a provider is registered in this registry.
func (r *Registry) Has(name string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, exists := r.factories[name]
	return exists
}

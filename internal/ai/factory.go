package ai

import "context"

// NewProvider creates and validates a provider from the global registry.
func NewProvider(ctx context.Context, name string, cfg ProviderConfig) (Provider, error) {
	provider, err := Create(name, cfg)
	if err != nil {
		return nil, err
	}

	if err := provider.Validate(ctx); err != nil {
		return nil, &ProviderError{
			Provider: name,
			Op:       "validate",
			Err:      err,
		}
	}

	return provider, nil
}

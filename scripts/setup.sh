#!/usr/bin/env bash
set -euo pipefail

echo "=== terraview setup ==="

# Check Go
if ! command -v go &> /dev/null; then
    echo "ERROR: Go is not installed."
    echo "Install Go 1.22+: https://go.dev/dl/"
    echo "  macOS: brew install go"
    echo "  Linux: sudo snap install go --classic"
    exit 1
fi

echo "Go version: $(go version)"

# Download dependencies
echo "Downloading Go dependencies..."
go mod tidy

# Build
echo "Building..."
make build

echo ""
echo "Setup complete!"
echo "Run: ./build/terraview --plan examples/plan.json --skip-llm -v"

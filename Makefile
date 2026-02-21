BINARY_NAME := terraview
VERSION := $(shell git describe --tags --always 2>/dev/null || echo "v0.1.0")
BUILD_DIR := ./build
DIST_DIR := ./dist
LDFLAGS := -ldflags "-s -w -X main.version=$(VERSION)"

PLATFORMS := linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64

.PHONY: all build clean test lint run dist docker-build install help

all: clean lint test build

build:
	@echo "Building $(BINARY_NAME) $(VERSION)..."
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME) .

clean:
	@echo "Cleaning..."
	@rm -rf $(BUILD_DIR) $(DIST_DIR)
	@rm -f review.json review.md coverage.out coverage.html

test:
	@echo "Running tests..."
	go test ./... -v -race -coverprofile=coverage.out

test-short:
	@echo "Running short tests..."
	go test ./... -short

coverage: test
	@echo "Generating coverage report..."
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report: coverage.html"

lint:
	@echo "Linting..."
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run ./...; \
	else \
		echo "golangci-lint not installed, running go vet..."; \
		go vet ./...; \
	fi

run: build
	$(BUILD_DIR)/$(BINARY_NAME) review --plan examples/plan.json --skip-llm -v

run-with-llm: build
	$(BUILD_DIR)/$(BINARY_NAME) review --plan examples/plan.json -v

# Build for all platforms
dist: clean
	@echo "Building releases for $(VERSION)..."
	@mkdir -p $(DIST_DIR)
	@for platform in $(PLATFORMS); do \
		os=$${platform%/*}; \
		arch=$${platform#*/}; \
		ext=""; \
		if [ "$${os}" = "windows" ]; then ext=".exe"; fi; \
		output="$(DIST_DIR)/$(BINARY_NAME)-$${os}-$${arch}$${ext}"; \
		echo "  Building $${os}/$${arch}..."; \
		GOOS=$${os} GOARCH=$${arch} CGO_ENABLED=0 go build $(LDFLAGS) -o $${output} . ; \
		tar -czf "$(DIST_DIR)/$(BINARY_NAME)-$${os}-$${arch}.tar.gz" -C $(DIST_DIR) "$(BINARY_NAME)-$${os}-$${arch}$${ext}" ; \
		cp prompts/* $(DIST_DIR)/ 2>/dev/null || true; \
		cp rules/* $(DIST_DIR)/ 2>/dev/null || true; \
	done
	@echo "Packaging bundled assets..."
	@tar -czf $(DIST_DIR)/terraview-assets.tar.gz prompts/ rules/
	@echo "Done. Artifacts in $(DIST_DIR)/"

# Create a GitHub release (requires gh CLI)
release: dist
	@echo "Creating GitHub release $(VERSION)..."
	gh release create $(VERSION) $(DIST_DIR)/*.tar.gz \
		--title "$(BINARY_NAME) $(VERSION)" \
		--notes "Release $(VERSION)" \
		--draft

docker-build:
	docker build -t $(BINARY_NAME):$(VERSION) -t $(BINARY_NAME):latest .

docker-run: docker-build
	docker run --rm --network host \
		-v $(PWD)/examples:/workspace \
		$(BINARY_NAME):latest \
		review --plan /workspace/plan.json --output /workspace -v

install: build
	@echo "Installing $(BINARY_NAME) $(VERSION)..."
	@mkdir -p $(HOME)/.local/bin
	@mkdir -p $(HOME)/.terraview/prompts $(HOME)/.terraview/rules
	@cp prompts/* $(HOME)/.terraview/prompts/
	@cp rules/* $(HOME)/.terraview/rules/
	@cp $(BUILD_DIR)/$(BINARY_NAME) $(HOME)/.local/bin/$(BINARY_NAME)
	@chmod +x $(HOME)/.local/bin/$(BINARY_NAME)
	@ln -sf $(HOME)/.local/bin/$(BINARY_NAME) $(HOME)/.local/bin/tv
	@echo ""
	@echo "Installed $(BINARY_NAME) $(VERSION) to ~/.local/bin/"
	@echo "Alias 'tv' -> $(HOME)/.local/bin/tv"
	@echo "Assets installed to ~/.terraview/"
	@if ! echo "$$PATH" | grep -q "$(HOME)/.local/bin"; then \
		echo ""; \
		echo "  Add to your shell profile (~/.zshrc):"; \
		echo ""; \
		echo '    export PATH="$$HOME/.local/bin:$$PATH"'; \
		echo ""; \
		echo "  Then reload:"; \
		echo "    source ~/.zshrc"; \
	fi

install-global: build
	@echo "Installing $(BINARY_NAME) $(VERSION) to /usr/local/bin (requires sudo)..."
	@mkdir -p $(HOME)/.terraview/prompts $(HOME)/.terraview/rules
	@cp prompts/* $(HOME)/.terraview/prompts/
	@cp rules/* $(HOME)/.terraview/rules/
	sudo cp $(BUILD_DIR)/$(BINARY_NAME) /usr/local/bin/$(BINARY_NAME)
	sudo chmod +x /usr/local/bin/$(BINARY_NAME)
	sudo ln -sf /usr/local/bin/$(BINARY_NAME) /usr/local/bin/tv
	@echo "Installed $(BINARY_NAME) $(VERSION) to /usr/local/bin/"
	@echo "Alias 'tv' -> /usr/local/bin/tv"

uninstall:
	@echo "Removing $(BINARY_NAME)..."
	@rm -f $(HOME)/.local/bin/$(BINARY_NAME) $(HOME)/.local/bin/tv
	@rm -f /usr/local/bin/$(BINARY_NAME) /usr/local/bin/tv 2>/dev/null || true
	@rm -rf $(HOME)/.terraview
	@echo "Uninstalled."

help:
	@echo "$(BINARY_NAME) $(VERSION)"
	@echo ""
	@echo "Development:"
	@echo "  build        Build the binary for current platform"
	@echo "  test         Run all tests with race detection"
	@echo "  test-short   Run short tests only"
	@echo "  coverage     Generate test coverage report"
	@echo "  lint         Run linter"
	@echo "  clean        Remove build artifacts"
	@echo ""
	@echo "Run:"
	@echo "  run          Build and review example plan (no LLM)"
	@echo "  run-with-llm Build and review example plan (with LLM)"
	@echo ""
	@echo "Distribution:"
	@echo "  dist         Build for all platforms (linux/darwin/windows, amd64/arm64)"
	@echo "  release      Create a draft GitHub release"
	@echo "  docker-build Build Docker image"
	@echo "  docker-run   Run in Docker with example plan"
	@echo ""
	@echo "Install:"
	@echo "  install      Install binary + assets locally"
	@echo "  uninstall    Remove binary + assets"

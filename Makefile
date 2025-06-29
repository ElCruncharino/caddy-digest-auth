.PHONY: build test clean install-xcaddy build-caddy help

# Default target
help:
	@echo "Available targets:"
	@echo "  build        - Build the module"
	@echo "  test         - Run tests"
	@echo "  clean        - Clean build artifacts"
	@echo "  install-xcaddy - Install xcaddy"
	@echo "  build-caddy  - Build Caddy with this module"
	@echo "  fmt          - Format code"
	@echo "  lint         - Run linter"
	@echo "  vet          - Run go vet"

# Install xcaddy
install-xcaddy:
	@echo "Installing xcaddy..."
	go install github.com/caddyserver/xcaddy/cmd/xcaddy@latest

# Build Caddy with this module
build-caddy: install-xcaddy
	@echo "Building Caddy with digest auth module..."
	xcaddy build --with ./

# Run tests
test:
	@echo "Running tests..."
	go test -v ./...

# Run tests with race detection
test-race:
	@echo "Running tests with race detection..."
	go test -race -v ./...

# Format code
fmt:
	@echo "Formatting code..."
	go fmt ./...

# Run linter
lint:
	@echo "Running linter..."
	golangci-lint run

# Run go vet
vet:
	@echo "Running go vet..."
	go vet ./...

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	rm -f caddy caddy.exe
	rm -rf dist/
	rm -f *.log
	rm -f test_users.htdigest

# Build the module (placeholder for module-specific builds)
build:
	@echo "Building module..."
	go build ./...

# Install dependencies
deps:
	@echo "Installing dependencies..."
	go mod download
	go mod verify

# Update dependencies
deps-update:
	@echo "Updating dependencies..."
	go get -u ./...
	go mod tidy

# Show module info
info:
	@echo "Module information:"
	@echo "  Name: github.com/ElCruncharino/caddy-digest-auth"
	@echo "  Go version: $(shell go version)"
	@echo "  Go modules: $(shell go list -m all | head -5)" 
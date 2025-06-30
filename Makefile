# Makefile para sslscan-go

# Variáveis
BINARY_NAME=sslscan-go
MAIN_PATH=cmd/main.go
BUILD_DIR=build
VERSION=$(shell git describe --tags --always --dirty 2>/dev/null || echo "1.0.0")
LDFLAGS=-ldflags "-X main.version=$(VERSION)"

# Detecta o sistema operacional
OS := $(shell uname -s | tr '[:upper:]' '[:lower:]')
ARCH := $(shell uname -m)

# Configurações específicas por plataforma
ifeq ($(OS),darwin)
	BINARY_NAME := $(BINARY_NAME)-darwin-$(ARCH)
else ifeq ($(OS),linux)
	BINARY_NAME := $(BINARY_NAME)-linux-$(ARCH)
else ifeq ($(OS),windows)
	BINARY_NAME := $(BINARY_NAME)-windows-$(ARCH).exe
endif

# Comandos
.PHONY: all build clean test lint fmt help install

# Alvo padrão
all: clean build

# Compilar o projeto
build:
	@echo "Building $(BINARY_NAME)..."
	@mkdir -p $(BUILD_DIR)
	go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME) $(MAIN_PATH)
	@echo "Build complete: $(BUILD_DIR)/$(BINARY_NAME)"

# Compilar para múltiplas plataformas
build-all: clean
	@echo "Building for multiple platforms..."
	@mkdir -p $(BUILD_DIR)

	# Linux AMD64
	GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o $(BUILD_DIR)/sslscan-go-linux-amd64 $(MAIN_PATH)

	# Linux ARM64
	GOOS=linux GOARCH=arm64 go build $(LDFLAGS) -o $(BUILD_DIR)/sslscan-go-linux-arm64 $(MAIN_PATH)

	# macOS AMD64
	GOOS=darwin GOARCH=amd64 go build $(LDFLAGS) -o $(BUILD_DIR)/sslscan-go-darwin-amd64 $(MAIN_PATH)

	# macOS ARM64
	GOOS=darwin GOARCH=arm64 go build $(LDFLAGS) -o $(BUILD_DIR)/sslscan-go-darwin-arm64 $(MAIN_PATH)

	# Windows AMD64
	GOOS=windows GOARCH=amd64 go build $(LDFLAGS) -o $(BUILD_DIR)/sslscan-go-windows-amd64.exe $(MAIN_PATH)

	@echo "Multi-platform build complete!"

# Compilar com otimizações
build-release: clean
	@echo "Building optimized release version..."
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -a -installsuffix cgo -ldflags '-extldflags "-static"' -o $(BUILD_DIR)/$(BINARY_NAME)-static $(MAIN_PATH)
	@echo "Static build complete: $(BUILD_DIR)/$(BINARY_NAME)-static"

# Limpar arquivos de build
clean:
	@echo "Cleaning build directory..."
	@rm -rf $(BUILD_DIR)
	@go clean

# Executar testes
test:
	@echo "Running tests..."
	go test -v ./...

# Executar testes com cobertura
test-coverage:
	@echo "Running tests with coverage..."
	go test -v -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report generated: coverage.html"

# Executar linting
lint:
	@echo "Running linter..."
	golangci-lint run

# Formatar código
fmt:
	@echo "Formatting code..."
	go fmt ./...

# Verificar dependências
deps:
	@echo "Checking dependencies..."
	go mod tidy
	go mod verify

# Instalar dependências de desenvolvimento
install-dev-deps:
	@echo "Installing development dependencies..."
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest

# Instalar o binário
install: build
	@echo "Installing $(BINARY_NAME)..."
	@cp $(BUILD_DIR)/$(BINARY_NAME) /usr/local/bin/$(BINARY_NAME)
	@echo "Installation complete!"

# Desinstalar o binário
uninstall:
	@echo "Uninstalling $(BINARY_NAME)..."
	@rm -f /usr/local/bin/$(BINARY_NAME)
	@echo "Uninstallation complete!"

# Executar o programa
run: build
	@echo "Running $(BINARY_NAME)..."
	@./$(BUILD_DIR)/$(BINARY_NAME) --help

# Executar com exemplo
run-example: build
	@echo "Running example scan..."
	@./$(BUILD_DIR)/$(BINARY_NAME) --verbose --xml example.xml --junit example-junit.xml google.com

# Gerar documentação
docs:
	@echo "Generating documentation..."
	@mkdir -p docs
	@./$(BUILD_DIR)/$(BINARY_NAME) --help > docs/help.txt
	@echo "Documentation generated in docs/"

# Criar release
release: clean build-all
	@echo "Creating release..."
	@mkdir -p release
	@cp $(BUILD_DIR)/* release/
	@echo "Release files created in release/"

# Verificar se o Go está instalado
check-go:
	@which go > /dev/null || (echo "Go is not installed. Please install Go 1.21 or later." && exit 1)
	@go version

# Verificar versão
version:
	@echo "Version: $(VERSION)"

# Mostrar ajuda
help:
	@echo "Available targets:"
	@echo "  build          - Build the binary"
	@echo "  build-all      - Build for multiple platforms"
	@echo "  build-release  - Build optimized static binary"
	@echo "  clean          - Clean build files"
	@echo "  test           - Run tests"
	@echo "  test-coverage  - Run tests with coverage"
	@echo "  lint           - Run linter"
	@echo "  fmt            - Format code"
	@echo "  deps           - Check dependencies"
	@echo "  install-dev-deps - Install development dependencies"
	@echo "  install        - Install binary to /usr/local/bin"
	@echo "  uninstall      - Remove binary from /usr/local/bin"
	@echo "  run            - Run the program"
	@echo "  run-example    - Run example scan"
	@echo "  docs           - Generate documentation"
	@echo "  release        - Create release files"
	@echo "  check-go       - Check if Go is installed"
	@echo "  version        - Show version"
	@echo "  help           - Show this help"

# Docker targets
docker-build:
	@echo "Building Docker image..."
	docker build -t sslscan-go .

docker-run:
	@echo "Running Docker container..."
	docker run --rm sslscan-go --help

docker-example:
	@echo "Running example in Docker..."
	docker run --rm sslscan-go --verbose google.com

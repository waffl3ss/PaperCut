BINARY_NAME := papercut
SRC         := ./cmd/papercut

GOFLAGS := -trimpath
LDFLAGS := -s -w

.PHONY: all clean linux windows darwin darwin-arm build help

## Default: build for current OS
build:
	go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(BINARY_NAME) $(SRC)

## Build for Linux (amd64)
linux:
	GOOS=linux GOARCH=amd64 go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(BINARY_NAME)_linux $(SRC)

## Build for Windows (amd64)
windows:
	GOOS=windows GOARCH=amd64 go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(BINARY_NAME)_windows.exe $(SRC)

## Build for macOS (amd64)
darwin:
	GOOS=darwin GOARCH=amd64 go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(BINARY_NAME)_darwin $(SRC)

## Build for macOS (arm64 / Apple Silicon)
darwin-arm:
	GOOS=darwin GOARCH=arm64 go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(BINARY_NAME)_darwin_arm64 $(SRC)

## Build all platforms
all: linux windows darwin darwin-arm

## Clean build artifacts
clean:
	rm -f $(BINARY_NAME) $(BINARY_NAME)_linux $(BINARY_NAME)_windows.exe $(BINARY_NAME)_darwin $(BINARY_NAME)_darwin_arm64

## Show available targets
help:
	@echo "PaperCut Build Targets:"
	@echo ""
	@echo "  make build       Build for current OS"
	@echo "  make linux       Build for Linux (amd64)"
	@echo "  make windows     Build for Windows (amd64)"
	@echo "  make darwin      Build for macOS (amd64)"
	@echo "  make darwin-arm  Build for macOS (arm64)"
	@echo "  make all         Build all platforms"
	@echo "  make clean       Remove build artifacts"
	@echo "  make help        Show this help"

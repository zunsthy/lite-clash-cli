GO ?= go
BINARY ?= bin/lite-clash
VERSION ?= 0.2.0
BUILD_TIME ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

LDFLAGS := -s -w \
	-X main.version=$(VERSION) \
	-X main.buildTime=$(BUILD_TIME)

.PHONY: build clean check-go-version

build: check-go-version
	@mkdir -p $(dir $(BINARY))
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o $(BINARY) ./cmd/lite-clash

check-go-version:
	@version="$$($(GO) env GOVERSION)"; \
	case "$$version" in \
		go1.26.*) ;; \
		*) echo "error: standalone TLS behavior is pinned to Go 1.26.x; found $$version" >&2; exit 1 ;; \
	esac

clean:
	rm -f $(BINARY)

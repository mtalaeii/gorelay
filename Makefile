BINARY  := gorelay
PKG     := ./cmd/gorelay
LDFLAGS := -s -w
GOFLAGS := -trimpath

TARGETS := \
	linux/amd64       \
	linux/arm64       \
	linux/arm/6       \
	linux/arm/7       \
	linux/386         \
	darwin/amd64      \
	darwin/arm64      \
	windows/amd64     \
	windows/arm64     \
	windows/386       \
	freebsd/amd64

.PHONY: build run test fmt vet tidy clean xbuild help

help:
	@echo "make build    build local binary"
	@echo "make run      build and print --help"
	@echo "make test     run tests"
	@echo "make fmt      gofmt"
	@echo "make vet      go vet"
	@echo "make tidy     go mod tidy"
	@echo "make xbuild   cross-compile every release target into ./dist"
	@echo "make clean    remove build outputs"

build:
	go build $(GOFLAGS) -ldflags='$(LDFLAGS)' -o $(BINARY) $(PKG)

run: build
	./$(BINARY) --help || true

test:
	go test ./...

fmt:
	go fmt ./...

vet:
	go vet ./...

tidy:
	go mod tidy

clean:
	rm -f $(BINARY) $(BINARY).exe
	rm -rf dist/

xbuild: clean
	@mkdir -p dist
	@for t in $(TARGETS); do \
		os=$${t%%/*}; rest=$${t#*/}; arch=$${rest%%/*}; arm=$${rest#$$arch}; arm=$${arm#/}; \
		ext=""; [ "$$os" = "windows" ] && ext=".exe"; \
		suffix=""; [ -n "$$arm" ] && suffix="v$$arm"; \
		name="dist/$(BINARY)-$$os-$$arch$$suffix$$ext"; \
		echo "==> $$name"; \
		GOOS=$$os GOARCH=$$arch GOARM=$$arm CGO_ENABLED=0 \
			go build $(GOFLAGS) -ldflags='$(LDFLAGS)' -o "$$name" $(PKG) || exit 1; \
	done
	@cd dist && (command -v sha256sum >/dev/null && sha256sum * || shasum -a 256 *) > checksums.txt
	@ls -lh dist

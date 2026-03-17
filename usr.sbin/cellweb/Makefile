GO?=go
PROG?=cellweb
PKG=./cmd/cellweb
DISTDIR?=dist
TARGET_OS?=netbsd
TARGET_ARCH?=amd64
CGO?=0
OUT?=$(DISTDIR)/$(PROG)-$(TARGET_OS)-$(TARGET_ARCH)
NETBSD_AMD64_BIN?=$(DISTDIR)/$(PROG)-netbsd-amd64
NETBSD_AMD64_CGO_BIN?=$(DISTDIR)/$(PROG)-netbsd-amd64-cgo
NETBSD_CC?=x86_64--netbsd-gcc

.PHONY: all build build-host run fmt clean build-netbsd-amd64 build-netbsd-amd64-cgo

all: build

build:
	mkdir -p $(DISTDIR)
	@if [ "$(CGO)" = "1" ]; then \
		GOOS=$(TARGET_OS) GOARCH=$(TARGET_ARCH) CGO_ENABLED=1 CC=$(NETBSD_CC) $(GO) build -trimpath -o $(OUT) $(PKG); \
	else \
		GOOS=$(TARGET_OS) GOARCH=$(TARGET_ARCH) CGO_ENABLED=0 $(GO) build -trimpath -o $(OUT) $(PKG); \
	fi

build-host:
	$(GO) build -o $(PROG) $(PKG)

build-netbsd-amd64:
	$(MAKE) build TARGET_OS=netbsd TARGET_ARCH=amd64 CGO=0 OUT=$(NETBSD_AMD64_BIN)

build-netbsd-amd64-cgo:
	$(MAKE) build TARGET_OS=netbsd TARGET_ARCH=amd64 CGO=1 OUT=$(NETBSD_AMD64_CGO_BIN)

run: build-host
	./$(PROG)

fmt:
	$(GO) fmt $(PKG)

clean:
	rm -f ./$(PROG) $(NETBSD_AMD64_BIN) $(NETBSD_AMD64_CGO_BIN) $(OUT)
	rmdir $(DISTDIR) 2>/dev/null || true

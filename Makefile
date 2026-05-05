LIBPCAP_VERSION := 1.10.6
TCPDUMP_VERSION := 4.99.6
STATIC_TCPDUMP_NAME=static-tcpdump
NEW_PLUGIN_SYSTEM_MINIMUM_KUBECTL_VERSION=12
UNAME := $(shell uname)
ARCH_NAME := $(shell uname -m)
KUBECTL_MINOR_VERSION=$(shell kubectl version --client -o json 2>/dev/null | grep -oP '"minor":\s*"\K[0-9]+')
ifeq ($(KUBECTL_MINOR_VERSION),)
KUBECTL_MINOR_VERSION=99
endif
IS_NEW_PLUGIN_SUBSYSTEM := $(shell [ $(KUBECTL_MINOR_VERSION) -ge $(NEW_PLUGIN_SYSTEM_MINIMUM_KUBECTL_VERSION) ] && echo true)

ifeq ($(IS_NEW_PLUGIN_SUBSYSTEM),true)
PLUGIN_FOLDER=/usr/local/bin
else
PLUGIN_FOLDER=~/.kube/plugins/sniff
endif

ifeq ($(UNAME), Darwin)
ifeq ($(ARCH_NAME), arm64)
PLUGIN_NAME=kubectl-sniff-darwin-arm64
else
PLUGIN_NAME=kubectl-sniff-darwin
endif
endif

ifeq ($(UNAME), Linux)
PLUGIN_NAME=kubectl-sniff
endif

linux:
	 GOOS=linux GOARCH=amd64 go build -o kubectl-sniff cmd/kubectl-sniff.go

windows:
	 GOOS=windows GOARCH=amd64 go build -o kubectl-sniff-windows cmd/kubectl-sniff.go

darwin:
	 GOOS=darwin GOARCH=amd64 go build -o kubectl-sniff-darwin cmd/kubectl-sniff.go
	 GOOS=darwin GOARCH=arm64 go build -o kubectl-sniff-darwin-arm64 cmd/kubectl-sniff.go

all: linux windows darwin

IMAGE_REPO ?= ghcr.io/nyralei/ksniff-tcpdump
IMAGE_TAG  ?= latest

# Build multi-arch image and verify it compiles for both platforms (cached, not pushed).
# Use `make image-push` to publish to the registry.
image:
	docker run --privileged --rm tonistiigi/binfmt --install all
	docker buildx create --name ksniff-builder --driver docker-container 2>/dev/null; \
		docker buildx use ksniff-builder
	docker buildx build --platform linux/amd64,linux/arm64 \
		-t $(IMAGE_REPO):$(IMAGE_TAG) \
		images/ksniff-tcpdump

# Build and push multi-arch image to ghcr.io (requires docker login).
image-push:
	docker run --privileged --rm tonistiigi/binfmt --install all
	docker buildx create --name ksniff-builder --driver docker-container 2>/dev/null; \
		docker buildx use ksniff-builder
	docker buildx build --platform linux/amd64,linux/arm64 \
		-t $(IMAGE_REPO):$(IMAGE_TAG) \
		--push \
		images/ksniff-tcpdump

test:
	go test -race -cover ./...

static-tcpdump:
	wget https://www.tcpdump.org/release/libpcap-$(LIBPCAP_VERSION).tar.xz
	wget https://www.tcpdump.org/release/tcpdump-$(TCPDUMP_VERSION).tar.xz
	tar -xf libpcap-$(LIBPCAP_VERSION).tar.xz
	tar -xf tcpdump-$(TCPDUMP_VERSION).tar.xz
	cd libpcap-$(LIBPCAP_VERSION) && \
		./configure --disable-shared --disable-dbus --without-libnl && \
		make
	cd tcpdump-$(TCPDUMP_VERSION) && \
		./configure --without-crypto \
			CFLAGS="-static -I$(CURDIR)/libpcap-$(LIBPCAP_VERSION)" \
			LDFLAGS="-L$(CURDIR)/libpcap-$(LIBPCAP_VERSION)" && \
		make
	mv tcpdump-$(TCPDUMP_VERSION)/tcpdump ./$(STATIC_TCPDUMP_NAME)
	rm -rf libpcap-$(LIBPCAP_VERSION)* tcpdump-$(TCPDUMP_VERSION)*

package:
	zip ksniff.zip kubectl-sniff kubectl-sniff-windows kubectl-sniff-darwin kubectl-sniff-darwin-arm64 static-tcpdump Makefile plugin.yaml LICENSE

install:
	mkdir -p ${PLUGIN_FOLDER}
	cp ${PLUGIN_NAME} ${PLUGIN_FOLDER}/kubectl-sniff
	cp plugin.yaml ${PLUGIN_FOLDER}
	cp ${STATIC_TCPDUMP_NAME} ${PLUGIN_FOLDER}

uninstall:
	rm -f ${PLUGIN_FOLDER}/kubectl-sniff
	rm -f ${PLUGIN_FOLDER}/plugin.yaml
	rm -f ${PLUGIN_FOLDER}/${STATIC_TCPDUMP_NAME}

verify_version:
	./scripts/verify_version.sh

clean:
	rm -f kubectl-sniff
	rm -f kubectl-sniff-windows
	rm -f kubectl-sniff-darwin
	rm -f kubectl-sniff-darwin-arm64
	rm -f static-tcpdump
	rm -f ksniff.zip


VERSION := $(shell git describe --tags --abbrev=0 | tr -d '[:alpha:]')
LDFLAGS := "-s -w -X github.com/cloudflare/cfssl/cli/version.version=$(VERSION)"

export GOFLAGS := -mod=vendor
export GOPROXY := off

.PHONY: all
all: bin/cfssl bin/cfssl-bundle bin/cfssl-certinfo bin/cfssl-newkey bin/cfssl-scan bin/cfssljson bin/mkbundle bin/multirootca

bin/%: $(shell find . -type f -name '*.go')
	@mkdir -p $(dir $@)
ifneq ($(and $(TARGETOS),$(TARGETARCH)),)
	GOOS=$(TARGETOS) GOARCH=$(TARGETARCH) go build -ldflags $(LDFLAGS) -o $@ ./cmd/$(@F)
else
	go build -ldflags $(LDFLAGS) -o $@ ./cmd/$(@F)
endif

.PHONY: install
install: install-cfssl install-cfssl-bundle install-cfssl-certinfo install-cfssl-newkey install-cfssl-scan install-cfssljson install-mkbundle install-multirootca

.PHONY: install-%
install-%:
	go install ./cmd/$(@F:install-%=%)

.PHONY: serve
serve: bin/cfssl
serve:
	./bin/cfssl serve

bin/goose: $(shell find vendor -type f -name '*.go')
	@mkdir -p $(dir $@)
ifneq ($(and $(TARGETOS),$(TARGETARCH)),)
	GOOS=$(TARGETOS) GOARCH=$(TARGETARCH) go build -o $@ ./vendor/bitbucket.org/liamstask/goose/cmd/goose
else
	go build -o $@ ./vendor/bitbucket.org/liamstask/goose/cmd/goose
endif

.PHONY: clean
clean:
	rm -rf bin *.deb *.rpm

# Check that given variables are set and all have non-empty values,
# die with an error otherwise.
#
# Params:
#   1. Variable name(s) to test.
#   2. (optional) Error message to print.
#
# cf: https://stackoverflow.com/questions/10858261/abort-makefile-if-variable-not-set
check_defined = \
	$(strip $(foreach 1,$1, \
		$(call __check_defined,$1,$(strip $(value 2)))))
__check_defined = \
	$(if $(value $1),, \
		$(error Undefined $1$(if $2, ($2))))

.PHONY: snapshot
snapshot:
	docker run \
	--rm \
    -v $(PWD):/cross \
    -w /cross \
    ghcr.io/gythialy/golang-cross:v1.18 --rm-dist --snapshot --skip-publish

.PHONY: github-release
github-release:
	@:$(call check_defined, GITHUB_TOKEN)

	docker run \
	--rm \
	-e GITHUB_TOKEN=$(GITHUB_TOKEN) \
    -v $(PWD):/cross \
    -w /cross \
    ghcr.io/gythialy/golang-cross:v1.18 --rm-dist

.PHONY: docker-build
docker-build:
	docker build -f Dockerfile -t cfssl/cfssl:$(VERSION) .
.PHONY: docker-push
docker-push:
	docker push cfssl/cfssl:$(VERSION)

.PHONY: release
release: github-release docker-build docker-push

BUILD_PATH   := $(CURDIR)/build
INSTALL_PATH := $(BUILD_PATH)/usr/local/bin

FPM = fakeroot fpm -C $(BUILD_PATH) \
	-a $(shell uname -m) \
	-s dir \
	-v $(VERSION) \
	--url 'https://github.com/cloudflare/cfssl' \
	--vendor Cloudflare \
	-n cfssl

.PHONY: package
package: package-deb package-rpm

.PHONY: package-deb
package-deb: all
	$(RM) -r build
	mkdir -p $(INSTALL_PATH)
	cp bin/* $(INSTALL_PATH)
	$(FPM) -t deb .

.PHONY: package-rpm
package-rpm: all
	$(RM) -r build
	mkdir -p $(INSTALL_PATH)
	cp bin/* $(INSTALL_PATH)
	$(FPM) -t rpm .

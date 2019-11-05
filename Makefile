export GOFLAGS := -mod=vendor
export GOPROXY := off

.PHONY: all
all: bin/cfssl bin/cfssl-bundle bin/cfssl-certinfo bin/cfssl-newkey bin/cfssl-scan bin/cfssljson bin/mkbundle bin/multirootca

bin/%: $(shell find . -type f -name '*.go') cli/serve/rice-box.go
	@mkdir -p $(dir $@)
	go build -o $@ ./cmd/$(@F)

cli/serve/rice-box.go: bin/rice $(shell find cli/serve/static -type f)
cli/serve/rice-box.go:
	./bin/rice embed-go -i=./cli/serve

.PHONY: install
install: install-cfssl install-cfssl-bundle install-cfssl-certinfo install-cfssl-newkey install-cfssl-scan install-cfssljson install-mkbundle install-multirootca

.PHONY: install-%
install-%:
	go install ./cmd/$(@F:install-%=%)

.PHONY: serve
serve: bin/cfssl
serve:
	./bin/cfssl serve

bin/rice: $(shell find vendor -type f -name '*.go')
	@mkdir -p $(dir $@)
	go build -o $@ ./vendor/github.com/GeertJohan/go.rice/rice

bin/golint: $(shell find vendor -type f -name '*.go')
	@mkdir -p $(dir $@)
	go build -o $@ ./vendor/golang.org/x/lint/golint

bin/goose: $(shell find vendor -type f -name '*.go')
	@mkdir -p $(dir $@)
	go build -o $@ ./vendor/bitbucket.org/liamstask/goose/cmd/goose

.PHONY: clean
clean:
	rm -rf bin

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

.PHONY: release
release:
	@:$(call check_defined, GITHUB_TOKEN)
	docker run -e GITHUB_TOKEN=$(GITHUB_TOKEN) --rm  -v $(PWD):/workdir -w /workdir cbroglie/goreleaser-cgo:1.12.12 goreleaser --rm-dist

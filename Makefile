export GOFLAGS := -mod=vendor
export GOPROXY := off

.PHONY: all
all: bin/cfssl bin/cfssl-bundle bin/cfssl-certinfo bin/cfssl-newkey bin/cfssl-scan bin/cfssljson bin/mkbundle bin/multirootca

bin/%: $(shell find . -type f -name '*.go')
	@mkdir -p $(dir $@)
	go build -o $@ ./cmd/$(@F)

.PHONY: install
install: install-cfssl install-cfssl-bundle install-cfssl-certinfo install-cfssl-newkey install-cfssl-scan install-cfssljson install-mkbundle install-multirootca

.PHONY: install-%
install-%:
	go install ./cmd/$(@F:install-%=%)

bin/rice: $(shell find . -type f -name '*.go')
	@mkdir -p $(dir $@)
	go build -o $@ ./vendor/github.com/GeertJohan/go.rice/rice

bin/golint: $(shell find . -type f -name '*.go')
	@mkdir -p $(dir $@)
	go build -o $@ ./vendor/golang.org/x/lint/golint

bin/goose: $(shell find . -type f -name '*.go')
	@mkdir -p $(dir $@)
	go build -o $@ ./vendor/bitbucket.org/liamstask/goose/cmd/goose

.PHONY: clean
clean:
	rm -rf bin

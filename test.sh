#!/bin/bash
set -o errexit
cd $(dirname $0)
ls $GOPATH/src/github.com/cloudflare/cfssl

go vet ./...
if ! which fgt > /dev/null ; then
  echo "Please install fgt from https://github.com/GeertJohan/fgt."
  exit 1
fi
if ! which golint > /dev/null ; then
  echo "Please install golint from github.com/golang/lint/golint."
  exit 1
fi
fgt golint ./...
go test $BUILD_FLAGS ./...
go list -f '{{if len .TestGoFiles}}"go test -coverprofile={{.Dir}}/.coverprofile {{.ImportPath}}"{{end}}' ./... | xargs -i sh -c {}
gover . coverprofile.txt

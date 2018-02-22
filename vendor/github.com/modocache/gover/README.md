# gover

[![Build Status](https://drone.io/github.com/modocache/gover/status.png)](https://drone.io/github.com/modocache/gover/latest)
[![Coverage Status](https://coveralls.io/repos/modocache/gover/badge.png?branch=master)](https://coveralls.io/r/modocache/gover?branch=master)
[![GoDoc](https://godoc.org/github.com/modocache/gover?status.png)](https://godoc.org/github.com/modocache/gover)

Gather all your *.coverprofile files to send to [coveralls.io](https://coveralls.io/)!

## Usage

### Continuous Integration with [coveralls.io](https://coveralls.io/)

Use with [mattn/goveralls](https://github.com/mattn/goveralls) to send metrics
to [coveralls.io](https://coveralls.io/):

```sh
go get golang.org/x/tools/cmd/cover
go get github.com/modocache/gover
go get github.com/mattn/goveralls

go test ./...
gover
goveralls -coverprofile=gover.coverprofile -service drone.io -repotoken $COVERALLS_TOKEN
```

### Options

```console
Usage: gover [root] [out]

Collects all .coverprofile files rooted in [root] and concatenantes them
into a single file at [out].

[root] defaults to the current directory, [out] to 'gover.coverprofile'.
```

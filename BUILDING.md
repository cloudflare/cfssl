# How to Build CFSSL

## Docker 

The requirements to build `CFSSL` are:

1. A running instance of Docker 
2. The `bash` shell

To build, run:

    $ script/build    

This is will build by default all the cfssl command line utilities
for darwin (OSX), linux, and windows for i386 and amd64 and output the
binaries in the current path.

To build a specific platform and OS, run:

    $ script/build -os="darwin" -arch="amd64"

Note: for cross-compilation compatibility, the Docker build process will
build programs without PKCS #11.

## Without Docker

The requirements to build without Docker are:

1. Go version 1.4 is the minimum required version of Go.
2. A properly configured go environment
3. A properly configured GOPATH
4. The default behaviour is to build with PKCS #11, which  requires the
   `gcc` compiler and the libtool development library and header files. On
   Ubuntu, this is `libltdl-dev`.

To build with PKCS #11 support, run:

    $ go get -d ./...
    $ find ./cmd -type f -iname '*.go' | xargs -n 1 go build

To build without PKCS #11 support:

    $ go get -d ./...
    $ go build -tags nopkcs11 cmd/...

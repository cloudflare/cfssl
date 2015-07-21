# How to Build CFSSL

## Docker 

The requirements to build `CFSSL` are:

1. A running instance of Docker 
2. The `bash` shell

To build, run:

    $ script/build    

This is will build by default all the cfssl command line utilities for darwin (OSX), linux, and windows for i386 and amd64 and output the binaries in the current path.

To build a specific platform and OS, run:

    $ script/build -os="darwin" -arch="amd64"

## Without Docker

The requirements to build without docker are:

1. A properly configured go environment
2. A properly configured GOPATH
3. The `bash` shell

To build, run:

    $ go get -d ./...
    $ go build cmd/...



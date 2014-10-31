# CF-SSL
## CloudFlare's SSL tool

CF-SSL is CloudFlare's SSL swiss army knife. It is both a command line
tool and an HTTP API server for signing, verifying, and bundling SSL
certificates. It requires Go 1.3 to build.

### Installation

Installation requires a [working Go
installation](http://golang.org/doc/install) and a properly set `GOPATH`.

```
$ go get github.com/cloudflare/cfssl
```

will download and build the CFSSL tool, installing it in
`$GOPATH/bin/cfssl`. To install the other utility programs that are in
this repo:

```
$ go get github.com/cloudflare/cfssl/...
```

This will download, build, and install `cfssl`, `cfssljson`, and
`mkbundle` into `$GOPATH/bin/`.


### Using the Command Line Tool

The command line tool takes a command to specify what operation it
should carry out:

       sign             signs a certificate
       bundle           build a certificate bundle
       genkey           generate a private key and a certificate request
       gencert          generate a private key and a certificate
       serve            start the API server
       version          prints out the current version

Use "cfssl [command] -help" to find out more about a command.
The version command takes no arguments.

#### Signing

```
cfssl sign [-ca cert] [-ca-key key] hostname csr [subject]
```

The hostname and csr are the client's host name and certificate
request. The `-ca` and `-ca-key` flags are the CA's certificate
and private key, respectively. By default, they are "ca.pem" and
"ca_key.pem".  For example, assuming the CA's private key is in
`/etc/ssl/private/cfssl_key.pem` and the CA's certificate is in
`/etc/ssl/certs/cfssl.pem`, to sign the `cloudflare.pem` certificate
for cloudflare.com:

```
cfssl sign -ca /etc/ssl/certs/cfssl.pem \
           -ca-key /etc/ssl/private/cfssl_key.pem \
           cloudflare.com ./cloudflare.pem
```

It is also possible to specify hostname and clientcert through '-hostname'
and '-cert' flags. By doing so, flag values take precedence and will
overwrite the arguments.

The subject is an optional file that contains subject information that
should be used in place of the information from the CSR. It should be
a JSON file with the type:

```
{
    "hosts": [
        "example.com",
        "www.example.com"
    ],
    "CN": "example.com",
    "names": [
        {
            "C": "US",
            "L": "San Francisco",
            "O": "Internet Widgets, Inc.",
            "OU": "WWW",
            "ST": "California"
        }
    ]
}
```

#### Bundling

```
cfssl bundle [-ca-bundle bundle] [-int-bundle bundle] \
             cert [key] [intermediates]
```

The bundles are used for the root and intermediate certificate
pools. The certificate and key parameters are paths to the
PEM-encoded client certificate to be bundled. If key is specified,
the bundle will be built and verified with the key. Otherwise the bundle
will be built without a private key.

It is also possible to specify cert, key and intermediates through '-cert',
'-key' and '-intermediates' respectively. And like other commands, flag
values will take precedence and overwrite the arguments.

#### Generating certificate signing request and private key

```
cfssl genkey csrjson
```

To generate a private key and corresponding certificate request, specify
the key request as a JSON file. This file should follow the form

```
{
    "hosts": [
        "example.com",
        "www.example.com"
    ],
    "key": {
        "algo": "rsa",
        "size": 2048
    },
    "names": [
        {
            "C": "US",
            "L": "San Francisco",
            "O": "Internet Widgets, Inc.",
            "OU": "WWW",
            "ST": "California"
        }
    ]
}
```

#### Generating self-signed root CA certificate and private key

```
cfssl genkey -initca csrjson | cfssljson -bare ca
```

To generate a self-signed root CA certificate, specify the key request as
the JSON file in the same format as in 'genkey'. Three PEM-encoded entities
will appear in the output: the private key, the csr, and the self-signed
certificate.

#### Generating a remote-issued certificate and private key.

```
cfssl gencert -remote=remote_server hostname csrjson
```

This is calls genkey, but has a remote CFSSL server sign and issue
a certificate.

#### Generating a local-issued certificate and private key.

```
cfssl gencert -ca cert -ca-key key hostname csrjson
```

This is generates and issues a certificate and private key from a local CA
via a JSON request.

### Starting the API Server

CF-SSL comes with an HTTP-based API server; the endpoints are
documented in `doc/api.txt`. The server is started with the "serve"
command:

```
cfssl serve [-address address] [-ca cert] [-ca-bundle bundle] \
            [-ca-key key] [-int-bundle bundle] [-port port]   \
            [-remote remote_server]
```

Address and port default to "127.0.0.1:8888". The `-ca` and `-ca-key`
arguments should be the PEM-encoded certificate and private key to use
for signing; by default, they are "ca.pem" and "ca_key.pem". The
`-ca-bundle` and `-int-bundle` should be the certificate bundles used
for the root and intermediate certificate pools, respectively. These
default to "ca-bundle.crt" and "int-bundle." If the "remote" option is
provided, all signature operations will be forwarded to the remote CFSSL.

The amount of logging can be controlled with the `-loglevel` option. This
comes *before* the serve command:

```
cfssl -loglevel 2 serve
```

The levels are:

* 0. DEBUG
* 1. INFO (this is the default level)
* 2. WARNING
* 3. ERROR
* 4. CRITICAL


### The mkbundle Utility

`mkbundle` is used to build the root and intermediate bundles used in
verifying certificates. It can be installed with

```
go get github.com/cloudflare/cfssl/mkbundle
```

It takes a collection of certificates, checks for CRL revocation (OCSP
support is planned for the next release) and expired certificates, and
bundles them into one file. It takes directories of certificates and
certificate files (which may contain multiple certificates). For example,
if the directory `intermediates` contains a number of intermediate
certificates,

```
mkbundle -f int-bundle.crt intermediates
```

will check those certificates and combine valid ones into a single
`int-bundle.crt` file.

The `-f` flag specifies an output name; `-loglevel` specifies the verbosity
of the logging (using the same loglevels above), and `-nw` controls the
number of revocation-checking workers.

### The cfssljson Utility

Most of the output from `cfssl` is in JSON. The `cfssljson` will take
this output and split it out into separate key, certificate, CSR, and
bundle files as appropriate. The tool takes a single flag, `-f`, that
specifies the input file, and an argument that specifies the base name for
the files produced. If the input filename is "-" (which is the default),
`cfssljson` reads from standard input. It maps keys in the JSON file to
filenames in the following way:

* if there is a "cert" (or if not, if there's a "certificate") field, the
  file "basename.pem" will be produced.
* if there is a "key" (or if not, if there's a "private_key") field, the
  file "basename-key.pem" will be produced.
* if there is a "csr" (or if not, if there's a "certificate_request") field,
  the file "basename.csr" will be produced.
* if there is a "bundle" field, the file "basename-bundle.pem" will
  be producd.

### Additional Documentation

Additional documentation can be found in the "doc/" directory:

* `api.txt`: documents the API endpoints
* `bootstrap.txt`: a walkthrough from building the package to getting
  up and running

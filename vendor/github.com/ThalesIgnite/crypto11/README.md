Crypto11
========

[![GoDoc](https://godoc.org/github.com/ThalesIgnite/crypto11?status.svg)](https://godoc.org/github.com/ThalesIgnite/crypto11)
[![Build Status](https://travis-ci.com/ThalesIgnite/crypto11.svg?branch=master)](https://travis-ci.com/ThalesIgnite/crypto11)

This is an implementation of the standard Golang hardware crypto interface that
uses [PKCS#11](http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/errata01/os/pkcs11-base-v2.40-errata01-os-complete.html) as a backend. The supported features are:

* Generation and retrieval of RSA, DSA and ECDSA keys.
* PKCS#1 v1.5 signing.
* PKCS#1 PSS signing.
* PKCS#1 v1.5 decryption
* PKCS#1 OAEP decryption
* ECDSA signing.
* DSA signing.
* Random number generation.
* (Experimental) AES and DES3 encryption and decryption.
* (Experimental) HMAC support.

Signing is done through the
[crypto.Signer](https://golang.org/pkg/crypto/#Signer) interface and
decryption through
[crypto.Decrypter](https://golang.org/pkg/crypto/#Decrypter).

To verify signatures or encrypt messages, retrieve the public key and do it in software.

See the documentation for details of various limitations.

There are some rudimentary tests.

There is a demo web server in the `demo` directory, which publishes
the contents of `/usr/share/doc`.

Installation
============

(If you don't have one already) create [a standard Go workspace](https://golang.org/doc/code.html#Workspaces) and set the `GOPATH` environment variable to point to the workspace root.

crypto11 manages it's dependencies via `dep`.  To Install `dep` run:

	go get -u github.com/golang/dep/cmd/dep

Clone, ensure deps, and build:

    go get github.com/ThalesIgnite/crypto11
    cd $GOPATH/src/github.com/ThalesIgnite/crypto11
    dep ensure
    go build

Edit `config` to taste, and then run the test program:

    go test  -count=1

Testing Guidance
================

Testing with nShield
--------------------

In all cases, it's worth enabling nShield PKCS#11 log output:

    export CKNFAST_DEBUG=2

To protect keys with a 1/N operator cardset:

    $ cat config
    {
      "Path" : "/opt/nfast/toolkits/pkcs11/libcknfast.so",
      "TokenLabel": "rjk",
      "Pin" : "password"
    }

You can also identify the token by serial number, which in this case
means the first 16 hex digits of the operator cardset's token hash:

    $ cat config
    {
      "Path" : "/opt/nfast/toolkits/pkcs11/libcknfast.so",
      "TokenSerial": "1d42780caa22efd5",
      "Pin" : "password"
    }

A card from the cardset must be in the slot when you run `go test`.

To protect keys with the module only, use the 'accelerator' token:

    $ cat config
    {
      "Path" : "/opt/nfast/toolkits/pkcs11/libcknfast.so",
      "TokenLabel": "accelerator",
      "Pin" : "password"
    }

(At time of writing) GCM is not implemented, so expect test skips.

Testing with SoftHSM
--------------------

While the aim of the exercise is to use an HSM, it can be convenient
to test with a software-only provider.

To set up a slot:

    $ cat softhsm.conf
    0:softhsm0.db
    $ export SOFTHSM_CONF=`pwd`/softhsm.conf
    $ softhsm --init-token --slot 0 --label test
    The SO PIN must have a length between 4 and 255 characters.
    Enter SO PIN:
    The user PIN must have a length between 4 and 255 characters.
    Enter user PIN:
    The token has been initialized.

Configure as follows:

    $ cat config
    {
      "Path" : "/usr/lib/softhsm/libsofthsm.so",
      "TokenLabel": "test",
      "Pin" : "password"
    }

DSA, ECDSA, PSS and OAEP aren't supported, so expect test failures.

Testing with SoftHSM2
---------------------

To set up a slot:

    $ cat softhsm2.conf
    directories.tokendir = /home/rjk/go/src/github.com/ThalesIgnite/crypto11/tokens
    objectstore.backend = file
    log.level = INFO
    $ mkdir tokens
    $ export SOFTHSM2_CONF=`pwd`/softhsm2.conf
    $ softhsm2-util --init-token --slot 0 --label test
    === SO PIN (4-255 characters) ===
    Please enter SO PIN: ********
    Please reenter SO PIN: ********
    === User PIN (4-255 characters) ===
    Please enter user PIN: ********
    Please reenter user PIN: ********
    The token has been initialized.

The configuration looks like this:

    $ cat config
    {
      "Path" : "/usr/lib/softhsm/libsofthsm2.so",
      "TokenLabel": "test",
      "Pin" : "password"
    }

(At time of writing) OAEP is only partial and HMAC is unsupported, so expect test skips.

Limitations
===========

 * The [PKCS1v15DecryptOptions SessionKeyLen](https://golang.org/pkg/crypto/rsa/#PKCS1v15DecryptOptions) field
is not implemented and an error is returned if it is nonzero.
The reason for this is that it is not possible for crypto11 to guarantee the constant-time behavior in the specification.
See [issue #5](https://github.com/ThalesIgnite/crypto11/issues/5) for further discussion.
 * Symmetric crypto support via [cipher.Block](https://golang.org/pkg/crypto/cipher/#Block) is very slow.
You can use the `BlockModeCloser` API
(over 400 times as fast on my computer)
but you must call the Close()
interface (not found in [cipher.BlockMode](https://golang.org/pkg/crypto/cipher/#BlockMode)).
See [issue #6](https://github.com/ThalesIgnite/crypto11/issues/6) for further discussion.

Wishlist
========

* Full test instructions for additional PKCS#11 implementations.
* A pony.

Copyright
=========

MIT License.

Copyright 2016-2018 Thales e-Security, Inc

Permission is hereby granted, free of charge, to any person obtaining
a copy of this software and associated documentation files (the
"Software"), to deal in the Software without restriction, including
without limitation the rights to use, copy, modify, merge, publish,
distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so, subject to
the following conditions:

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

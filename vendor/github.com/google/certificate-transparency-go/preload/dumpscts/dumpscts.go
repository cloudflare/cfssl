// Copyright 2015 Google Inc. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"compress/zlib"
	"encoding/gob"
	"flag"
	"io"
	"log"
	"os"

	"github.com/google/certificate-transparency-go/preload"
)

var sctFile = flag.String("sct_file", "", "File to load SCTs & leaf data from")

func main() {
	flag.Parse()
	var sctReader io.ReadCloser
	if *sctFile == "" {
		log.Fatal("Must specify --sct_file")
	}

	sctFileReader, err := os.Open(*sctFile)
	if err != nil {
		log.Fatal(err)
	}
	sctReader, err = zlib.NewReader(sctFileReader)
	if err != nil {
		log.Fatal(err)
	}
	defer func() {
		err := sctReader.Close()
		if err != nil && err != io.EOF {
			log.Fatalf("Error closing file: %s", err)
		}
	}()

	// TODO(alcutter) should probably store this stuff in a protobuf really.
	decoder := gob.NewDecoder(sctReader)
	var addedCert preload.AddedCert
	numAdded := 0
	numFailed := 0
	for {
		err = decoder.Decode(&addedCert)
		if err != nil {
			break
		}
		if addedCert.AddedOk {
			log.Println(addedCert.SignedCertificateTimestamp)
			numAdded++
		} else {
			log.Printf("Cert was not added: %s", addedCert.ErrorMessage)
			numFailed++
		}
	}
	log.Printf("Num certs added: %d, num failed: %d\n", numAdded, numFailed)
}

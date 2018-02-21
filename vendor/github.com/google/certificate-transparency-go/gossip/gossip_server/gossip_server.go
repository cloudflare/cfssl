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
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strings"

	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/gossip"
)

var dbPath = flag.String("database", "/tmp/gossip.sq3", "Path to database.")
var listenAddress = flag.String("listen", ":8080", "Listen address:port for HTTP server.")
var logKeys = flag.String("log_public_keys", "", "Comma separated list of files containing trusted Logs' public keys in PEM format")

func createVerifiers() (*gossip.SignatureVerifierMap, error) {
	m := make(gossip.SignatureVerifierMap)
	if len(*logKeys) == 0 {
		return nil, errors.New("--log_public_keys is empty")
	}
	keys := strings.Split(*logKeys, ",")
	for _, k := range keys {
		pem, err := ioutil.ReadFile(k)
		if err != nil {
			return nil, fmt.Errorf("failed to read specified PEM file %s: %v", k, err)
		}
		for len(pem) > 0 {
			key, id, rest, err := ct.PublicKeyFromPEM(pem)
			pem = rest
			if err != nil {
				return nil, fmt.Errorf("failed to read public key from PEM in file %s: %v", k, err)
			}
			sv, err := ct.NewSignatureVerifier(key)
			if err != nil {
				return nil, fmt.Errorf("Failed to create new SignatureVerifier: %v", err)
			}
			m[id] = *sv
			log.Printf("Loaded key for LogID %v", id)
		}
	}
	return &m, nil
}

func main() {
	flag.Parse()
	verifierMap, err := createVerifiers()
	if err != nil {
		log.Fatalf("Failed to load log public keys: %v", err)
	}
	log.Print("Starting gossip server.")

	storage := gossip.Storage{}
	if err := storage.Open(*dbPath); err != nil {
		log.Fatalf("Failed to open storage: %v", err)
	}
	defer storage.Close()

	handler := gossip.NewHandler(&storage, *verifierMap)
	serveMux := http.NewServeMux()
	serveMux.HandleFunc("/.well-known/ct/v1/sct-feedback", handler.HandleSCTFeedback)
	serveMux.HandleFunc("/.well-known/ct/v1/sth-pollination", handler.HandleSTHPollination)
	server := &http.Server{
		Addr:    *listenAddress,
		Handler: serveMux,
	}
	if err := server.ListenAndServe(); err != nil {
		log.Printf("Error serving: %v", err)
	}
}

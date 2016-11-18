package main

import (
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"time"

	ct "github.com/google/certificate-transparency/go"
	"github.com/google/certificate-transparency/go/client"
	"github.com/google/certificate-transparency/go/jsonclient"
	"github.com/google/certificate-transparency/go/x509"
	"github.com/google/certificate-transparency/go/x509util"
	httpclient "github.com/mreiferson/go-httpclient"
	"golang.org/x/net/context"
)

var logURI = flag.String("log_uri", "http://ct.googleapis.com/aviator", "CT log base URI")
var pubKey = flag.String("pub_key", "", "Name of file containing log's public key")
var certChain = flag.String("cert_chain", "", "Name of file containing certificate chain as concatenated PEM files")
var textOut = flag.Bool("text", true, "Display certificates as text")

func ctTimestampToTime(ts uint64) time.Time {
	secs := int64(ts / 1000)
	msecs := int64(ts % 1000)
	return time.Unix(secs, msecs*1000000)
}

func signatureToString(signed *ct.DigitallySigned) string {
	return fmt.Sprintf("Signature: Hash=%v Sign=%v Value=%x", signed.Algorithm.Hash, signed.Algorithm.Signature, signed.Signature)
}

func getSTH(ctx context.Context, logClient *client.LogClient) {
	sth, err := logClient.GetSTH(ctx)
	if err != nil {
		log.Fatal(err)
	}
	// Display the STH
	when := ctTimestampToTime(sth.Timestamp)
	fmt.Printf("%v: Got STH for %v log (size=%d) at %v, hash %x\n", when, sth.Version, sth.TreeSize, *logURI, sth.SHA256RootHash)
	fmt.Printf("%v\n", signatureToString(&sth.TreeHeadSignature))
}

func addChain(ctx context.Context, logClient *client.LogClient) {
	if *certChain == "" {
		log.Fatalf("No certificate chain file specified with -cert_chain")
	}
	rest, err := ioutil.ReadFile(*certChain)
	if err != nil {
		log.Fatalf("Failed to read certificate file: %v", err)
	}
	var chain []ct.ASN1Cert
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			chain = append(chain, ct.ASN1Cert(block.Bytes))
		}
	}

	sct, err := logClient.AddChain(ctx, chain)
	if err != nil {
		log.Fatal(err)
	}
	// Display the SCT
	when := ctTimestampToTime(sct.Timestamp)
	fmt.Printf("%v: Uploaded chain of %d certs to %v log at %v\n", when, len(chain), sct.SCTVersion, *logURI)
	fmt.Printf("%v\n", signatureToString(&sct.Signature))
}

func getRoots(ctx context.Context, logClient *client.LogClient) {
	roots, err := logClient.GetAcceptedRoots(ctx)
	if err != nil {
		log.Fatal(err)
	}
	for _, root := range roots {
		if *textOut {
			cert, err := x509.ParseCertificate(root)
			if err != nil {
				log.Printf("Error parsing certificate: %q", err.Error())
				continue
			}
			fmt.Printf("%s\n", x509util.CertificateToString(cert))
		} else {
			if err := pem.Encode(os.Stdout, &pem.Block{Type: "CERTIFICATE", Bytes: root}); err != nil {
				log.Printf("Failed to PEM encode cert: %q", err.Error())
			}
		}
	}
}
func dieWithUsage(msg string) {
	fmt.Fprintf(os.Stderr, msg)
	fmt.Fprintf(os.Stderr, "Usage: ctclient [options] <cmd>\n"+
		"where cmd is one of:\n"+
		"   sth       retrieve signed tree head\n"+
		"   upload    upload cert chain and show SCT (requires -cert_chain)\n"+
		"   getroots  show accepted roots\n")
	os.Exit(1)
}

func main() {
	flag.Parse()
	httpClient := &http.Client{
		Transport: &httpclient.Transport{
			ConnectTimeout:        10 * time.Second,
			RequestTimeout:        30 * time.Second,
			ResponseHeaderTimeout: 30 * time.Second,
			MaxIdleConnsPerHost:   10,
			DisableKeepAlives:     false,
		}}
	var opts jsonclient.Options
	if *pubKey != "" {
		pubkey, err := ioutil.ReadFile(*pubKey)
		if err != nil {
			log.Fatal(err)
		}
		opts.PublicKey = string(pubkey)
	}
	logClient, err := client.New(*logURI, httpClient, opts)
	if err != nil {
		log.Fatal(err)
	}
	args := flag.Args()
	if len(args) != 1 {
		dieWithUsage("Need command argument")
	}
	ctx := context.Background()
	cmd := args[0]
	switch cmd {
	case "sth":
		getSTH(ctx, logClient)
	case "upload":
		addChain(ctx, logClient)
	case "getroots", "get_roots", "get-roots":
		getRoots(ctx, logClient)
	default:
		dieWithUsage(fmt.Sprintf("Unknown command '%s'", cmd))
	}
}

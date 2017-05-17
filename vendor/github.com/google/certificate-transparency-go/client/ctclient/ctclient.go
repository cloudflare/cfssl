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

	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/client"
	"github.com/google/certificate-transparency-go/jsonclient"
	"github.com/google/certificate-transparency-go/x509"
	"github.com/google/certificate-transparency-go/x509util"
	"golang.org/x/net/context"
)

var logURI = flag.String("log_uri", "http://ct.googleapis.com/aviator", "CT log base URI")
var pubKey = flag.String("pub_key", "", "Name of file containing log's public key")
var certChain = flag.String("cert_chain", "", "Name of file containing certificate chain as concatenated PEM files")
var textOut = flag.Bool("text", true, "Display certificates as text")
var getFirst = flag.Int64("first", -1, "First entry to get")
var getLast = flag.Int64("last", -1, "Last entry to get")

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
			chain = append(chain, ct.ASN1Cert{Data: block.Bytes})
		}
	}
	if len(chain) == 0 {
		log.Fatalf("No certificates found in %s", *certChain)
	}

	// Examine the leaf to see if it looks like a pre-certificate.
	isPrecert := false
	leaf, err := x509.ParseCertificate(chain[0].Data)
	if err == nil {
		count, _ := x509util.OidInExtensions(x509.OIDExtensionCTPoison, leaf.Extensions)
		if count > 0 {
			isPrecert = true
			fmt.Print("Uploading pre-certificate to log\n")
		}
	}

	var sct *ct.SignedCertificateTimestamp
	if isPrecert {
		sct, err = logClient.AddPreChain(ctx, chain)
	} else {
		sct, err = logClient.AddChain(ctx, chain)
	}
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
		showCert(root)
	}
}

func getEntries(ctx context.Context, logClient *client.LogClient) {
	if *getFirst == -1 {
		log.Fatal("No -first option supplied")
	}
	if *getLast == -1 {
		log.Fatal("No -last option supplied")
	}
	entries, err := logClient.GetEntries(ctx, *getFirst, *getLast)
	if err != nil {
		log.Fatal(err)
	}
	for _, entry := range entries {
		ts := entry.Leaf.TimestampedEntry
		when := ctTimestampToTime(ts.Timestamp)
		fmt.Printf("Index=%d Timestamp=%v ", entry.Index, when)
		switch ts.EntryType {
		case ct.X509LogEntryType:
			fmt.Printf("X.509 certificate:\n")
			showCert(*ts.X509Entry)
		case ct.PrecertLogEntryType:
			fmt.Printf("pre-certificate from issuer with keyhash %x:\n", ts.PrecertEntry.IssuerKeyHash)
			showTBSCert(ts.PrecertEntry.TBSCertificate)
		default:
			log.Fatalf("Unhandled log entry type %d", entry.Leaf.TimestampedEntry.EntryType)
		}
	}
}

func showCert(cert ct.ASN1Cert) {
	if *textOut {
		c, err := x509.ParseCertificate(cert.Data)
		if err != nil {
			log.Printf("Error parsing certificate: %q", err.Error())
			return
		}
		fmt.Printf("%s\n", x509util.CertificateToString(c))
	} else {
		if err := pem.Encode(os.Stdout, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Data}); err != nil {
			log.Printf("Failed to PEM encode cert: %q", err.Error())
		}
	}
}

func showTBSCert(tbs []byte) {
	if *textOut {
		c, err := x509.ParseTBSCertificate(tbs)
		if err != nil {
			log.Printf("Error parsing certificate: %q", err.Error())
			return
		}
		fmt.Printf("%s\n", x509util.CertificateToString(c))
	} else {
		fmt.Printf("%x\n", tbs)
	}
}

func dieWithUsage(msg string) {
	fmt.Fprintf(os.Stderr, msg)
	fmt.Fprintf(os.Stderr, "Usage: ctclient [options] <cmd>\n"+
		"where cmd is one of:\n"+
		"   sth         retrieve signed tree head\n"+
		"   upload      upload cert chain and show SCT (needs -cert_chain)\n"+
		"   getroots    show accepted roots\n"+
		"   getentries  get log entries (needs -first and -last)\n")
	os.Exit(1)
}

func main() {
	flag.Parse()
	httpClient := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSHandshakeTimeout:   30 * time.Second,
			ResponseHeaderTimeout: 30 * time.Second,
			MaxIdleConnsPerHost:   10,
			DisableKeepAlives:     false,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		},
	}
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
	case "getentries", "get_entries":
		getEntries(ctx, logClient)
	default:
		dieWithUsage(fmt.Sprintf("Unknown command '%s'", cmd))
	}
}

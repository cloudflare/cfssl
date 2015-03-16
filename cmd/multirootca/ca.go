package main

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"errors"
	"flag"
	"net/http"
	"os"

	"github.com/cloudflare/cfssl/cmd/multirootca/config"
	"github.com/cloudflare/cfssl/log"
	"github.com/cloudflare/cfssl/signer"
	"github.com/cloudflare/cfssl/signer/local"
)

func parseSigner(root *config.Root) (signer.Signer, error) {
	privateKey := root.PrivateKey
	switch priv := privateKey.(type) {
	case *rsa.PrivateKey, *ecdsa.PrivateKey:
		s, err := local.NewSigner(priv, root.Certificate, signer.DefaultSigAlgo(priv), nil)
		if err != nil {
			return nil, err
		}
		s.SetPolicy(root.Config)
		return s, nil
	default:
		return nil, errors.New("unsupported private key type")
	}
}

var (
	defaultLabel string
	signers      = map[string]signer.Signer{}
)

func main() {
	flagAddr := flag.String("a", ":8888", "listening address")
	flagRootFile := flag.String("roots", "", "configuration file specifying root keys")
	flagDefaultLabel := flag.String("l", "", "specify a default label")
	flag.IntVar(&log.Level, "loglevel", log.LevelInfo, "log level (0 = DEBUG, 4 = ERROR)")
	flag.Parse()

	if *flagRootFile == "" {
		log.Criticalf("no root file specified")
		os.Exit(1)
	}

	roots, err := config.Parse(*flagRootFile)
	if err != nil {
		log.Criticalf("%v", err)
		os.Exit(1)
	}

	for label, root := range roots {
		s, err := parseSigner(root)
		if err != nil {
			log.Criticalf("%v", err)
		}
		signers[label] = s
		log.Info("loaded signer ", label)
	}

	defaultLabel = *flagDefaultLabel
	initStats()

	http.HandleFunc("/api/v1/cfssl/authsign", dispatchRequest)
	http.HandleFunc("/api/v1/cfssl/metrics", dumpMetrics)
	log.Info("listening on ", *flagAddr)
	log.Error(http.ListenAndServe(*flagAddr, nil))
}

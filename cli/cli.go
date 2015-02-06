package cli

/*
cfssl is the command line tool to issue/sign/bundle client certificate. It's
also a tool to start a HTTP server to handle web requests for signing, bundling
and verification.

Usage:
	cfssl command [-flags] arguments

The commands are defined in the cli subpackages and include

	bundle	 create a certificate bundle
	sign	 signs a certificate signing request (CSR)
	serve	 starts a HTTP server handling sign and bundle requests
	version	 prints the current cfssl version
	genkey   generates a key and an associated CSR
	gencert  generates a key and a signed certificate
	selfsign generates a self-signed certificate

Use "cfssl [command] -help" to find out more about a command.
*/

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/cloudflare/cfssl/config"
)

// Command holds the implementation details of a cfssl command.
type Command struct {
	// The Usage Text
	UsageText string
	// Flags to look up in the global table
	Flags []string
	// Main runs the command, args are the arguments after flags
	Main func(args []string, c Config) error
}

// Config is a type to hold flag values used by cfssl commands.
type Config struct {
	Hostname          string
	CertFile          string
	CSRFile           string
	CAFile            string
	CAKeyFile         string
	KeyFile           string
	IntermediatesFile string
	CABundleFile      string
	IntBundleFile     string
	Address           string
	Port              int
	ConfigFile        string
	CFG               *config.Config
	Profile           string
	IsCA              bool
	IntDir            string
	Flavor            string
	Metadata          string
	Domain            string
	IP                string
	Remote            string
	Label             string
}

// Parsed command name
var cmdName string

// registerFlags defines all cfssl command flags and associates their values with variables.
func registerFlags(c *Config, f *flag.FlagSet) {
	f.StringVar(&c.Hostname, "hostname", "", "Hostname for the cert")
	f.StringVar(&c.CertFile, "cert", "", "Client certificate that contains the public key")
	f.StringVar(&c.CSRFile, "csr", "", "Certificate signature request file for new public key")
	f.StringVar(&c.CAFile, "ca", "ca.pem", "CA used to sign the new certificate")
	f.StringVar(&c.CAKeyFile, "ca-key", "ca-key.pem", "CA private key")
	f.StringVar(&c.KeyFile, "key", "", "private key for the certificate")
	f.StringVar(&c.IntermediatesFile, "intermediates", "", "intermediate certs")
	f.StringVar(&c.CABundleFile, "ca-bundle", "/etc/cfssl/ca-bundle.crt", "Bundle to be used for root certificates pool")
	f.StringVar(&c.IntBundleFile, "int-bundle", "/etc/cfssl/int-bundle.crt", "Bundle to be used for intermediate certificates pool")
	f.StringVar(&c.Address, "address", "127.0.0.1", "Address to bind")
	f.IntVar(&c.Port, "port", 8888, "Port to bind")
	f.StringVar(&c.ConfigFile, "config", "", "path to configuration file")
	f.StringVar(&c.Profile, "profile", "", "signing profile to use")
	f.BoolVar(&c.IsCA, "initca", false, "initialise new CA")
	f.StringVar(&c.IntDir, "int-dir", "/etc/cfssl/intermediates", "specify intermediates directory")
	f.StringVar(&c.Flavor, "flavor", "ubiquitous", "Bundle Flavor: ubiquitous, optimal and force.")
	f.StringVar(&c.Metadata, "metadata", "/etc/cfssl/ca-bundle.crt.metadata", "Metadata file for root certificate presence. The content of the file is a json dictionary (k,v): each key k is SHA-1 digest of a root certificate while value v is a list of key store filenames.")
	f.StringVar(&c.Domain, "domain", "", "remote server domain name")
	f.StringVar(&c.IP, "ip", "", "remote server ip")
	f.StringVar(&c.Remote, "remote", "", "remote CFSSL server")
	f.StringVar(&c.Label, "label", "", "key label to use in remote CFSSL server")
}

// usage is the cfssl usage heading. It will be appended with names of defined commands in cmds
// to form the final usage message of cfssl.
const usage = `Usage:
Available commands:
`

// printDefaultValue is a helper function to print out a user friendly
// usage message of a flag. It's useful since we want to write customized
// usage message on selected subsets of the global flag set. It is
// borrowed from standard library source code. Since flag value type is
// not exported, default string flag values are printed without
// quotes. The only exception is the empty string, which is printed as "".
func printDefaultValue(f *flag.Flag) {
	format := "  -%s=%s: %s\n"
	if f.DefValue == "" {
		format = "  -%s=%q: %s\n"
	}
	fmt.Fprintf(os.Stderr, format, f.Name, f.DefValue, f.Usage)
}

// PopFirstArgument returns the first element and the rest of a string
// slice and return error if failed to do so. It is a helper function
// to parse non-flag arguments previously used in cfssl commands.
func PopFirstArgument(args []string) (string, []string, error) {
	if len(args) < 1 {
		return "", nil, errors.New("not enough arguments are supplied --- please refer to the usage")
	}
	return args[0], args[1:], nil
}

// Start is the entrance point of cfssl command line tools.
func Start(cmds map[string]*Command) {
	// cfsslFlagSet is the flag sets for cfssl.
	var cfsslFlagSet = flag.NewFlagSet("cfssl", flag.ExitOnError)
	var c Config

	registerFlags(&c, cfsslFlagSet)
	// Initial parse of command line arguments. By convention, only -h/-help is supported.
	flag.Parse()
	if flag.Usage == nil {
		flag.Usage = func() {
			fmt.Fprintf(os.Stderr, usage)
			for name := range cmds {
				fmt.Fprintf(os.Stderr, "%s\n", name)
			}
		}
	}

	if flag.NArg() < 1 {
		fmt.Fprintf(os.Stderr, "No command is given.\n")
		flag.Usage()
		return
	}

	// Clip out the command name and args for the command
	cmdName = flag.Arg(0)
	args := flag.Args()[1:]
	cmd, found := cmds[cmdName]
	if !found {
		fmt.Fprintf(os.Stderr, "Command %s is not defined.\n", cmdName)
		flag.Usage()
		return
	}
	// The usage of each individual command is re-written to mention
	// flags defined and referenced only in that command.
	cfsslFlagSet.Usage = func() {
		fmt.Fprintf(os.Stderr, "%s", cmd.UsageText)
		for _, name := range cmd.Flags {
			if f := cfsslFlagSet.Lookup(name); f != nil {
				printDefaultValue(f)
			}
		}
	}

	// Parse all flags and take the rest as argument lists for the command
	cfsslFlagSet.Parse(args)
	args = cfsslFlagSet.Args()

	var err error
	c.CFG, err = config.LoadFile(c.ConfigFile)
	if c.ConfigFile != "" && err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load config file\n")
		os.Exit(1)
	}

	if err := cmd.Main(args, c); err != nil {
		fmt.Fprintln(os.Stderr, err)
	}
}

// ReadStdin reads from stdin if the file is "-"
func ReadStdin(filename string) ([]byte, error) {
	if filename == "-" {
		return ioutil.ReadAll(os.Stdin)
	}
	return ioutil.ReadFile(filename)
}

// PrintCert outputs a cert, key and csr to stdout
func PrintCert(key, csrBytes, cert []byte) {
	out := map[string]string{}
	if cert != nil {
		out["cert"] = string(cert)
	}

	if key != nil {
		out["key"] = string(key)
	}

	if csrBytes != nil {
		out["csr"] = string(csrBytes)
	}

	jsonOut, err := json.Marshal(out)
	if err != nil {
		return
	}
	fmt.Printf("%s\n", jsonOut)
}

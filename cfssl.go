/*
cfssl is the command line tool to issue/sign/bundle client certificate. It's also a tool to
start a HTTP server to handle web requests for signing, bundling and verification.

Usage:
	cfssl command [-flags] arguments

The commands are

	bundle	create a client cert bundle
	sign	signs a client cert
	serve	starts a HTTP server handling sign and bundle requests
	version	prints the current cfssl version

Use "cfssl [command] -help" to find out more about a command.
*/
package main

import (
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/cloudflare/cfssl/config"
	"github.com/cloudflare/cfssl/log"
)

// Command holds the implementation details of a cfssl command.
type Command struct {
	// The Usage Text
	UsageText string
	// Flags to look up in the global table
	Flags []string
	// Main runs the command, args are the arguments after flags
	Main func(args []string) error
}

// cmds is a registry of defined commands.
var cmds map[string]*Command

// cfsslFlagSet is the global flag sets for cfssl.
var cfsslFlagSet = flag.NewFlagSet("cfssl", flag.ExitOnError)

// Global struct to hold flag values used by cfssl commands.
// All cfssl commands share the flags.
var Config struct {
	hostname          string
	certFile          string
	csrFile           string
	caFile            string
	caKeyFile         string
	keyFile           string
	intermediatesFile string
	caBundleFile      string
	intBundleFile     string
	address           string
	port              int
	configFile        string
	cfg               *config.Config
	profile           string
	isCA              bool
	intDir            string
	flavor            string
	metadata          string
	domain            string
	ip                string
	remote            string
}

// Parsed command name
var cmdName string

// registerFlags defines all cfssl command flags and associates their values with variables.
func registerFlags() {
	cfsslFlagSet.StringVar(&Config.hostname, "hostname", "", "Hostname for the cert")
	cfsslFlagSet.StringVar(&Config.certFile, "cert", "", "Client certificate that contains the public key")
	cfsslFlagSet.StringVar(&Config.csrFile, "csr", "", "Certificate signature request file for new public key")
	cfsslFlagSet.StringVar(&Config.caFile, "ca", "ca.pem", "CA used to sign the new certificate")
	cfsslFlagSet.StringVar(&Config.caKeyFile, "ca-key", "ca-key.pem", "CA private key")
	cfsslFlagSet.StringVar(&Config.keyFile, "key", "", "private key for the certificate")
	cfsslFlagSet.StringVar(&Config.intermediatesFile, "intermediates", "", "intermediate certs")
	cfsslFlagSet.StringVar(&Config.caBundleFile, "ca-bundle", "/etc/cfssl/ca-bundle.crt", "Bundle to be used for root certificates pool")
	cfsslFlagSet.StringVar(&Config.intBundleFile, "int-bundle", "/etc/cfssl/int-bundle.crt", "Bundle to be used for intermediate certificates pool")
	cfsslFlagSet.StringVar(&Config.address, "address", "127.0.0.1", "Address to bind")
	cfsslFlagSet.IntVar(&Config.port, "port", 8888, "Port to bind")
	cfsslFlagSet.StringVar(&Config.configFile, "f", "", "path to configuration file")
	cfsslFlagSet.StringVar(&Config.profile, "profile", "", "signing profile to use")
	cfsslFlagSet.BoolVar(&Config.isCA, "initca", false, "initialise new CA")
	cfsslFlagSet.StringVar(&Config.intDir, "int-dir", "/etc/cfssl/intermediates", "specify intermediates directory")
	cfsslFlagSet.StringVar(&Config.flavor, "flavor", "ubiquitous", "Bundle Flavor: ubiquitous, optimal.")
	cfsslFlagSet.StringVar(&Config.metadata, "metadata", "/etc/cfssl/ca-bundle.crt.metadata", "Metadata file for root certificate presence. The content of the file is a json dictionary (k,v): each key k is SHA-1 digest of a root certificate while value v is a list of key store filenames.")
	cfsslFlagSet.StringVar(&Config.domain, "domain", "", "remote server domain name")
	cfsslFlagSet.StringVar(&Config.ip, "ip", "", "remote server ip")
	cfsslFlagSet.StringVar(&Config.remote, "remote", "", "remote CFSSL server")
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

// popFirstArgument returns the first element and the rest of a string
// slice and return error if failed to do so. It is a helper function
// to parse non-flag arguments previously used in cfssl commands.
func popFirstArgument(args []string) (string, []string, error) {
	if len(args) < 1 {
		cfsslFlagSet.Usage()
		return "", nil, errors.New("not enough arguments are supplied --- please refer to the usage")
	}
	return args[0], args[1:], nil
}

// init defines the cfssl usage and registers all defined commands and flags.
func init() {
	// Add command names to cfssl usage
	flag.IntVar(&log.Level, "loglevel", log.LevelInfo, "Log level")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, usage)
		for name := range cmds {
			fmt.Fprintf(os.Stderr, "%s\n", name)
		}
	}
	// Register commands.
	cmds = map[string]*Command{
		"bundle":  CLIBundler,
		"sign":    CLISigner,
		"serve":   CLIServer,
		"version": CLIVersioner,
		"genkey":  CLIGenKey,
		"gencert": CLIGenCert,
	}
	// Register all command flags.
	registerFlags()
}

// The main entrance point of cfssl command line tools.
func main() {
	// Initial parse of command line arguments. By convention, only -h/-help is supported.
	flag.Parse()

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

	Config.cfg = config.LoadFile(Config.configFile)
	if Config.configFile != "" && Config.cfg == nil {
		fmt.Fprintf(os.Stderr, "Failed to load config file\n")
		os.Exit(1)
	}

	if err := cmd.Main(args); err != nil {
		fmt.Fprintln(os.Stderr, err)
	}
}

func readStdin(filename string) ([]byte, error) {
	if filename == "-" {
		return ioutil.ReadAll(os.Stdin)
	}
	return ioutil.ReadFile(filename)
}

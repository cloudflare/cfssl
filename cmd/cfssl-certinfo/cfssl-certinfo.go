package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/cloudflare/cfssl/cli"
	"github.com/cloudflare/cfssl/cli/certinfo"
	"github.com/cloudflare/cfssl/config"

	_ "github.com/go-sql-driver/mysql" // import to support MySQL
	_ "github.com/lib/pq"              // import to support Postgres
	_ "github.com/mattn/go-sqlite3"    // import to support SQLite3
)

// main defines the newkey usage and registers all defined commands and flags.
func main() {

	var certinfoFlagSet = flag.NewFlagSet("certinfo", flag.ExitOnError)
	var c cli.Config
	registerFlags(&c, certinfoFlagSet)
	var usageText = `cfssl-certinfo -- output certinfo about the given cert

	Usage of certinfo:
		- Data from local certificate files
        	certinfo -cert file
		- Data from certificate from remote server.
        	certinfo -domain domain_name
		- Data from CA storage
        	certinfo -serial serial_number -aki authority_key_id (requires -db-config)

	Flags:
	`

	certinfoFlagSet.Usage = func() {
		fmt.Fprintf(os.Stderr, "\t%s", usageText)
		for _, name := range certinfo.Command.Flags {
			if f := certinfoFlagSet.Lookup(name); f != nil {
				printDefaultValue(f)
			}
		}
	}
	args := os.Args[1:]
	certinfoFlagSet.Parse(args)
	args = certinfoFlagSet.Args()

	var err error
	c.CFG, err = config.LoadFile(c.ConfigFile)
	if c.ConfigFile != "" && err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load config file: %v", err)
	}

	if err := certinfo.Command.Main(args, c); err != nil {
		fmt.Fprintln(os.Stderr, err)
	}
}

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

// registerFlags defines all cfssl command flags and associates their values with variables.
func registerFlags(c *cli.Config, f *flag.FlagSet) {
	f.StringVar(&c.CertFile, "cert", "", "Client certificate that contains the public key")
	f.StringVar(&c.Domain, "domain", "", "remote server domain name")
	f.StringVar(&c.Serial, "serial", "", "certificate serial number")
	f.StringVar(&c.AKI, "aki", "", "certificate issuer (authority) key identifier")
	f.StringVar(&c.DBConfigFile, "db-config", "", "certificate db configuration file")
}

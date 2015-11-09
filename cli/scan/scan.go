package scan

import (
	"encoding/json"
	"fmt"
	"sync"

	"github.com/cloudflare/cfssl/cli"
	"github.com/cloudflare/cfssl/log"
	"github.com/cloudflare/cfssl/scan"
)

var scanUsageText = `cfssl scan -- scan a host for issues
Usage of scan:
        cfssl scan [-family regexp] [-scanner regexp] [-timeout duration] [-ip IPAddr] HOST+
        cfssl scan -list

Arguments:
        HOST:    Host(s) to scan (including port)
Flags:
`
var scanFlags = []string{"list", "family", "scanner", "timeout", "ip", "ca-bundle"}

func printJSON(v interface{}) {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		fmt.Println(err)
	}
	fmt.Printf("%s\n\n", b)
}

type context struct {
	sync.WaitGroup
	c cli.Config
}

func newContext(c cli.Config, numHosts int) *context {
	ctx := &context{c: c}
	ctx.Add(numHosts)
	return ctx
}

func (ctx *context) RunScans(host string) {
	fmt.Printf("Scanning %s...\n", host)
	results, err := scan.Default.RunScans(host, ctx.c.IP, ctx.c.Family, ctx.c.Scanner, ctx.c.Timeout)
	fmt.Printf("=== %s ===\n", host)
	if err != nil {
		log.Error(err)
	} else {
		printJSON(results)
	}
	ctx.Done()
}

func scanMain(args []string, c cli.Config) (err error) {
	if c.List {
		printJSON(scan.Default)
	} else {
		if err = scan.LoadRootCAs(c.CABundleFile); err != nil {
			return
		}

		ctx := newContext(c, len(args))
		// Execute for each HOST argument given
		for len(args) > 0 {
			var host string
			host, args, err = cli.PopFirstArgument(args)
			if err != nil {
				return
			}

			go ctx.RunScans(host)
		}
		ctx.Wait()
	}
	return
}

// Command assembles the definition of Command 'scan'
var Command = &cli.Command{UsageText: scanUsageText, Flags: scanFlags, Main: scanMain}

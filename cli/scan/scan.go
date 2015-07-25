package scan

import (
	"encoding/json"
	"fmt"
	"github.com/cloudflare/cfssl/cli"
	"github.com/cloudflare/cfssl/scan"
	"time"
)

var scanUsageText = `cfssl scan -- scan a host for issues
Usage of scan:
        cfssl scan [-family regexp] [-scanner regexp] [-timeout duration] HOST+
        cfssl scan -list

Arguments:
        HOST:    Host(s) to scan (including port)
Flags:
`
var scanFlags = []string{"list", "family", "scanner", "timeout"}

func printJSON(v interface{}) {
	b, _ := json.MarshalIndent(v, "", "  ")
	fmt.Printf("%s\n\n", b)
}

func scanMain(args []string, c cli.Config) (err error) {
	if c.List {
		printJSON(scan.Default)
	} else {
		hosts := 0
		done := make(chan bool)

		// Execute for each HOST argument given
		for len(args) > 0 {
			var host string
			host, args, err = cli.PopFirstArgument(args)
			if err != nil {
				return
			}
			hosts++
			fmt.Printf("Scanning %s...\n", host)

			resChan := make(chan scan.PackagedFamilyResult)
			errChan := make(chan error)
			results := make(map[string]scan.FamilyResult)

			go scan.Default.RunScans(host, c.Family, c.Scanner, resChan, errChan)

			go func() {
				time.AfterFunc(c.Timeout, func() {
					fmt.Printf("%s timed out after % v...available results:\n", host, c.Timeout)
					printJSON(results)
					done <- true
				})

				for res := range resChan {
					results[res.FamilyName] = res.Result
				}

				fmt.Printf("Results for %s:\n", host)
				printJSON(results)
				done <- true
			}()

			go func() {
				e := <-errChan
				if e != nil {
					done <- true
				}
			}()
		}

		// Block until feedback received for each host
		for hosts > 0 {
			<-done
			hosts--
		}
	}
	return
}

// Command assembles the definition of Command 'scan'
var Command = &cli.Command{UsageText: scanUsageText, Flags: scanFlags, Main: scanMain}

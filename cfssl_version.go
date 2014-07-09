package main

import (
	"fmt"
	"runtime"
)

var version string
var revision string

// Usage text for 'cfssl version'
var versionUsageText = `cfssl version -- print out the version of CF SSL

Usage of version:
	cfssl version
`

// The main functionality of 'cfssl version' is to print out the version info.
func versionMain(args []string) (err error) {
	fmt.Printf("Version: %s\nRevision: %s\nRuntime: %s\n", version, revision, runtime.Version())
	return nil
}

// CLIVersioner defines Command 'version'
var CLIVersioner = &Command{versionUsageText, nil, versionMain}

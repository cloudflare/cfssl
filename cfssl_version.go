package main

import (
	"fmt"
	"runtime"
)

// Version stores the semantic versioning information for CFSSL.
var version = struct {
	Major    int
	Minor    int
	Patch    int
	Revision string
}{1, 0, 1, "release"}

func versionString() string {
	return fmt.Sprintf("%d.%d.%d", version.Major, version.Minor, version.Patch)
}

// Usage text for 'cfssl version'
var versionUsageText = `cfssl version -- print out the version of CF SSL

Usage of version:
	cfssl version
`

// The main functionality of 'cfssl version' is to print out the version info.
func versionMain(args []string) (err error) {
	fmt.Printf("Version: %s\nRevision: %s\nRuntime: %s\n", versionString(), version.Revision, runtime.Version())
	return nil
}

// CLIVersioner defines Command 'version'
var CLIVersioner = &Command{versionUsageText, nil, versionMain}

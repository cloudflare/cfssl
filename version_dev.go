// +build !release

package main

func init() {
	version.Major = 1
	version.Minor = 0
	version.Patch = 0
	version.Revision = "dev"
}

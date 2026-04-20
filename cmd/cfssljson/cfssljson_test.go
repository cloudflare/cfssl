package main

import (
	"testing"
)

func TestReadFile(t *testing.T) {
	_, err := readFile("-")
	if err != nil {
		t.Fatal(err)
	}

	file, err := readFile("./testdata/test.txt")
	if err != nil {
		t.Fatal(err)
	}
	if string(file) != "This is a test file" {
		t.Fatal("File not read correctly")
	}
}

func TestIsDirectory(t *testing.T) {
	t.Run("OK", func(t *testing.T) {
		ok, err := isDirectory("testdata")
		if err != nil {
			t.Fatal(err)
		}

		if ok == false {
			t.Fatal("should be a directory")
		}
	})

	t.Run("NOK - Not a directory", func(t *testing.T) {
		ok, err := isDirectory("cfssljson.go")
		if err != nil {
			t.Fatal(err)
		}

		if ok == true {
			t.Fatal("should not be a directory")
		}
	})

	t.Run("NOK - File not present", func(t *testing.T) {
		ok, err := isDirectory("notpresent")
		if err == nil {
			t.Fatal(err)
		}

		if ok == true {
			t.Fatal("should not exist")
		}
	})
}

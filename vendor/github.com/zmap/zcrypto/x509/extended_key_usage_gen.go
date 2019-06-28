// The following directive is necessary to make the package coherent:

// +build ignore

// This program generates extended_key_usage.go. It can be invoked by running
// `$ go generate`
package main

import (
	"bytes"
	"encoding/csv"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
)

const (
	COLUMN_IDX_OID        = 0
	COLUMN_IDX_SHORT_NAME = 2
)

const (
	GO_PREFIX    = "oidExtKeyUsage"
	CONST_PREFIX = "OID_EKU"
)

type OID struct {
	OID       string
	ShortName string
}

func (o *OID) OIDDecl() string {
	parts := strings.Split(o.OID, ".")
	buffer := bytes.Buffer{}
	buffer.WriteString("asn1.ObjectIdentifier{")
	for idx, p := range parts {
		buffer.WriteString(p)
		if idx != len(parts)-1 {
			buffer.WriteString(", ")
		}
	}
	buffer.WriteString("}")
	return buffer.String()
}

func (o *OID) GoName(prefix string) string {
	parts := strings.Split(o.ShortName, "-")
	for idx, p := range parts {
		if prefix == "" && idx == 0 {
			continue
		}
		parts[idx] = strings.Title(p)
	}
	return prefix + strings.Join(parts, "")
}

func (o *OID) GoConstant(prefix string) string {
	parts := strings.Split(o.ShortName, "-")
	buffer := bytes.Buffer{}
	if prefix != "" {
		buffer.WriteString(strings.ToUpper(prefix))
		buffer.WriteString("_")
	}
	for idx, p := range parts {
		buffer.WriteString(strings.ToUpper(p))
		if idx != len(parts)-1 {
			buffer.WriteString("_")
		}
	}
	return buffer.String()
}

func (o *OID) JSONName(prefix string) string {
	parts := strings.Split(o.ShortName, "-")
	buffer := bytes.Buffer{}
	if prefix != "" {
		buffer.WriteString(strings.ToLower(prefix))
		buffer.WriteString("_")
	}
	for idx, p := range parts {
		buffer.WriteString(strings.ToLower(p))
		if idx != len(parts)-1 {
			buffer.WriteString("_")
		}
	}
	return buffer.String()
}

func (o *OID) StructFieldName() string {
	parts := strings.Split(o.ShortName, "-")
	buffer := bytes.Buffer{}
	for _, p := range parts {
		buffer.WriteString(strings.Title(p))
	}
	return buffer.String()
}

func writeHeader(out io.Writer) {
	s := `// Created by extended_key_usage_gen; DO NOT EDIT

// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package x509

import (
	"encoding/asn1"
)

`
	out.Write([]byte(s))
}

func generateASN1(rawToOID map[string]OID) []byte {
	buffer := bytes.Buffer{}
	// Create sorted slice of keys to ensure deterministic output
	var keys = make([]string, 0, len(rawToOID))
	for k := range rawToOID {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		oid := rawToOID[k]
		goName := oid.GoName(GO_PREFIX)
		oidDecl := oid.OIDDecl()
		buffer.WriteString(goName)
		buffer.WriteString(" = ")
		buffer.WriteString(oidDecl)
		buffer.WriteString("\n")
	}
	return buffer.Bytes()
}

func generateIntegerConstants(rawToOID map[string]OID) []byte {
	buffer := bytes.Buffer{}
	buffer.WriteString("const (\n")
	first := true
	// Create sorted slice of keys to ensure deterministic output
	var keys = make([]string, 0, len(rawToOID))
	for k := range rawToOID {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		oid := rawToOID[k]
		goName := oid.GoName("ExtKeyUsage")
		buffer.WriteString(goName)
		if first {
			buffer.WriteString(" ExtKeyUsage = iota")
			first = false
		}
		buffer.WriteString("\n")
	}
	buffer.WriteString(")\n")
	return buffer.Bytes()
}

func generateNameConstants(rawToOID map[string]OID) []byte {
	buffer := bytes.Buffer{}
	// Create sorted slice of keys to ensure deterministic output
	var keys = make([]string, 0, len(rawToOID))
	for k := range rawToOID {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		oid := rawToOID[k]
		constantName := oid.GoConstant(CONST_PREFIX)
		buffer.WriteString(constantName)
		buffer.WriteString(" = \"")
		buffer.WriteString(oid.OID)
		buffer.WriteString("\"\n")
	}
	return buffer.Bytes()
}

func generateOIDMap(rawToOID map[string]OID, mapName string) []byte {
	buffer := bytes.Buffer{}
	buffer.WriteString(mapName)
	buffer.WriteString(" = make(map[string]asn1.ObjectIdentifier)\n")

	// Create sorted slice of keys to ensure deterministic output
	var keys = make([]string, 0, len(rawToOID))
	for k := range rawToOID {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		oid := rawToOID[k]
		constantName := oid.GoConstant(CONST_PREFIX)
		goName := oid.GoName(GO_PREFIX)
		buffer.WriteString(mapName)
		buffer.WriteString("[")
		buffer.WriteString(constantName)
		buffer.WriteString("] = ")
		buffer.WriteString(goName)
		buffer.WriteString("\n")
	}
	return buffer.Bytes()
}

func generateIntegerMap(rawToOID map[string]OID, mapName string) []byte {
	buffer := bytes.Buffer{}
	buffer.WriteString(mapName)
	buffer.WriteString(" = make(map[string]ExtKeyUsage)\n")

	// Create sorted slice of keys to ensure deterministic output
	var keys = make([]string, 0, len(rawToOID))
	for k := range rawToOID {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		oid := rawToOID[k]
		constantName := oid.GoConstant(CONST_PREFIX)
		goName := oid.GoName("ExtKeyUsage")
		buffer.WriteString(mapName)
		buffer.WriteString("[")
		buffer.WriteString(constantName)
		buffer.WriteString("] = ")
		buffer.WriteString(goName)
		buffer.WriteString("\n")
	}
	return buffer.Bytes()
}

func generateEKUJSONStruct(rawToOID map[string]OID) []byte {
	buffer := bytes.Buffer{}
	buffer.WriteString("type auxExtendedKeyUsage struct {\n")

	// Create sorted slice of keys to ensure deterministic output
	var keys = make([]string, 0, len(rawToOID))
	for k := range rawToOID {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		oid := rawToOID[k]
		buffer.WriteString(oid.StructFieldName())
		buffer.WriteString(" bool `json:\"")
		buffer.WriteString(oid.JSONName(""))
		buffer.WriteString(",omitempty\" oid:\"")
		buffer.WriteString(oid.OID)
		buffer.WriteString("\"`\n")
	}
	buffer.WriteString("Unknown []string `json:\"unknown,omitempty\"`")
	buffer.WriteString("}\n\n")
	buffer.WriteString("func (aux *auxExtendedKeyUsage) populateFromASN1(oid asn1.ObjectIdentifier) {\n")
	buffer.WriteString("s := oid.String()\n")
	buffer.WriteString("switch s {\n")
	for _, k := range keys {
		oid := rawToOID[k]
		buffer.WriteString("case ")
		constantName := oid.GoConstant(CONST_PREFIX)
		buffer.WriteString(constantName)
		buffer.WriteString(":\n")
		buffer.WriteString("aux.")
		buffer.WriteString(oid.StructFieldName())
		buffer.WriteString(" = true\n")
	}
	buffer.WriteString("default:\n")
	buffer.WriteString("}\n")
	buffer.WriteString("return")
	buffer.WriteString("}\n\n")

	buffer.WriteString("func (aux *auxExtendedKeyUsage) populateFromExtKeyUsage(eku ExtKeyUsage) {\n")
	buffer.WriteString("switch eku {\n")
	for _, k := range keys {
		oid := rawToOID[k]
		buffer.WriteString("case ")
		ekuName := oid.GoName("ExtKeyUsage")
		buffer.WriteString(ekuName)
		buffer.WriteString(":\n")
		buffer.WriteString("aux.")
		buffer.WriteString(oid.StructFieldName())
		buffer.WriteString(" = true\n")
	}
	buffer.WriteString("default:\n")
	buffer.WriteString("}\n")
	buffer.WriteString("return")
	buffer.WriteString("}\n\n")

	return buffer.Bytes()
}

func main() {
	out, err := os.Create("extended_key_usage.go")
	if err != nil {
		panic(err.Error())
	}
	defer out.Close()
	writeHeader(out)

	resp, err := http.Get("https://raw.githubusercontent.com/zmap/constants/master/x509/extended_key_usage.csv")
	if err != nil {
		panic(err.Error())
	}
	defer resp.Body.Close()

	rawToOID := make(map[string]OID)
	r := csv.NewReader(resp.Body)
	for lines := 0; ; lines++ {
		record, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			panic(err.Error())
		}
		if lines == 0 {
			// Header row
			continue
		}
		oid := record[COLUMN_IDX_OID]
		shortName := record[COLUMN_IDX_SHORT_NAME]
		rawToOID[oid] = OID{
			OID:       oid,
			ShortName: shortName,
		}
	}

	out.Write([]byte("const (\n"))
	constants := generateNameConstants(rawToOID)
	out.Write(constants)
	out.Write([]byte(")\n"))

	out.Write([]byte("var (\n"))
	oidDecls := generateASN1(rawToOID)
	out.Write(oidDecls)
	out.Write([]byte(")\n"))

	integersConstants := generateIntegerConstants(rawToOID)
	out.Write(integersConstants)

	out.Write(generateEKUJSONStruct(rawToOID))

	out.Write([]byte("\nvar ekuOIDs map[string]asn1.ObjectIdentifier\n\n"))
	out.Write([]byte("\nvar ekuConstants map[string]ExtKeyUsage\n\n"))

	out.Write([]byte("func init() {\n"))
	mapEntries := generateOIDMap(rawToOID, "ekuOIDs")
	out.Write(mapEntries)
	out.Write([]byte("\n"))
	intMapEntries := generateIntegerMap(rawToOID, "ekuConstants")
	out.Write(intMapEntries)
	out.Write([]byte("}\n"))
}

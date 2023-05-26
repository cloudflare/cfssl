// Copyright 2014 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !amd64 && !amd64p32 && !386 && !arm
// +build !amd64,!amd64p32,!386,!arm

package sha1

var block = blockGeneric

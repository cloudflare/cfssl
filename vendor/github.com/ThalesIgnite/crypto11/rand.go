// Copyright 2016, 2017 Thales e-Security, Inc
//
// Permission is hereby granted, free of charge, to any person obtaining
// a copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to
// permit persons to whom the Software is furnished to do so, subject to
// the following conditions:
//
// The above copyright notice and this permission notice shall be
// included in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
// NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
// LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
// OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
// WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

package crypto11

// PKCS11RandReader is a random number reader that uses PKCS#11.
type PKCS11RandReader struct {
}

// Read fills data with random bytes generated via PKCS#11 using the default slot.
//
// This implements the Reader interface for PKCS11RandReader.
func (reader PKCS11RandReader) Read(data []byte) (n int, err error) {
	var result []byte
	if instance.ctx == nil {
		return 0, ErrNotConfigured
	}
	if err = withSession(instance.slot, func(session *PKCS11Session) error {
		result, err = instance.ctx.GenerateRandom(session.Handle, len(data))
		return err
	}); err != nil {
		return 0, err
	}
	copy(data, result)
	return len(result), err
}

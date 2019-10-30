// Package streamquote implements a streaming version of strconv.Quote.
package streamquote

import (
	"io"
	"strconv"
	"unicode/utf8"
)

// Converter converts data by escaping control characters and
// non-printable characters using Go escape sequences.
type Converter interface {
	// Convert converts the data in "in", writing it to "out".
	// It uses Go escape sequences (\t, \n, \xFF, \u0100) for control characters
	// and non-printable characters as defined by strconv.IsPrint.
	// It is not safe for concurrent use.
	Convert(in io.Reader, out io.Writer) (int, error)
}

const bufSize = 100 * 1024

const lowerhex = "0123456789abcdef"

type converter struct {
	readBuffer  [bufSize]byte
	writeBuffer [10]byte
}

// New returns a new Converter.
func New() Converter {
	return &converter{}
}

// Convert converts the data in "in", writing it to "out".
// It uses Go escape sequences (\t, \n, \xFF, \u0100) for control characters
// and non-printable characters as defined by strconv.IsPrint.
// It is not safe for concurrent use.
func (c *converter) Convert(in io.Reader, out io.Writer) (int, error) {
	var err error
	bufSize := len(c.readBuffer)
	n := 0

	var processed = bufSize
	var dataLen = 0

	for {
		if processed+utf8.UTFMax > bufSize {
			// need to read more
			leftover := bufSize - processed
			if leftover > 0 {
				copy(c.readBuffer[:leftover], c.readBuffer[processed:])
			}
			read, peekErr := in.Read(c.readBuffer[leftover:])
			if peekErr != nil && peekErr != io.EOF {
				err = peekErr
				break
			}
			dataLen = leftover + read
			processed = 0
		}
		if dataLen-processed == 0 {
			break
		}

		maxRune := processed + utf8.UTFMax
		if maxRune > dataLen {
			maxRune = dataLen
		}
		data := c.readBuffer[processed:maxRune]

		var discard, n2 int
		r, width := utf8.DecodeRune(data)
		if width == 1 && r == utf8.RuneError {
			c.writeBuffer[0] = '\\'
			c.writeBuffer[1] = 'x'
			c.writeBuffer[2] = lowerhex[data[0]>>4]
			c.writeBuffer[3] = lowerhex[data[0]&0xF]
			out.Write(c.writeBuffer[0:4])
			n2 = 4
			discard = 1
		} else {
			discard = width
			if r == rune('"') || r == '\\' { // always backslashed
				c.writeBuffer[0] = '\\'
				c.writeBuffer[1] = byte(r)
				out.Write(c.writeBuffer[0:2])
				n2 = 2
			} else if strconv.IsPrint(r) {
				out.Write(data[:width])
				n2 = width
			} else {
				switch r {
				case '\a':
					c.writeBuffer[0] = '\\'
					c.writeBuffer[1] = 'a'
					out.Write(c.writeBuffer[0:2])
					n2 = 2
				case '\b':
					c.writeBuffer[0] = '\\'
					c.writeBuffer[1] = 'b'
					out.Write(c.writeBuffer[0:2])
					n2 = 2
				case '\f':
					c.writeBuffer[0] = '\\'
					c.writeBuffer[1] = 'f'
					out.Write(c.writeBuffer[0:2])
					n2 = 2
				case '\n':
					c.writeBuffer[0] = '\\'
					c.writeBuffer[1] = 'n'
					out.Write(c.writeBuffer[0:2])
					n2 = 2
				case '\r':
					c.writeBuffer[0] = '\\'
					c.writeBuffer[1] = 'r'
					out.Write(c.writeBuffer[0:2])
					n2 = 2
				case '\t':
					c.writeBuffer[0] = '\\'
					c.writeBuffer[1] = 't'
					out.Write(c.writeBuffer[0:2])
					n2 = 2
				case '\v':
					c.writeBuffer[0] = '\\'
					c.writeBuffer[1] = 'v'
					out.Write(c.writeBuffer[0:2])
					n2 = 2
				default:
					switch {
					case r < ' ':
						c.writeBuffer[0] = '\\'
						c.writeBuffer[1] = 'x'
						c.writeBuffer[2] = lowerhex[data[0]>>4]
						c.writeBuffer[3] = lowerhex[data[0]&0xF]
						out.Write(c.writeBuffer[0:4])
						n2 = 4
					case r > utf8.MaxRune:
						r = 0xFFFD
						fallthrough
					case r < 0x10000:
						c.writeBuffer[0] = '\\'
						c.writeBuffer[1] = 'u'
						n2 = 2
						i := 2
						for s := 12; s >= 0; s -= 4 {
							c.writeBuffer[i] = lowerhex[r>>uint(s)&0xF]
							i++
							n2++
						}
						out.Write(c.writeBuffer[0:i])
					default:
						c.writeBuffer[0] = '\\'
						c.writeBuffer[1] = 'U'
						n2 = 2
						i := 2
						for s := 28; s >= 0; s -= 4 {
							c.writeBuffer[i] = lowerhex[r>>uint(s)&0xF]
							i++
							n2++
						}
						out.Write(c.writeBuffer[0:i])
					}
				}
			}
		}
		processed += discard
		n += n2
	}

	return n, err
}

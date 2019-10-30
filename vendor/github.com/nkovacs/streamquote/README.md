## streamquote [![Build Status](https://travis-ci.org/nkovacs/streamquote.svg?branch=master)](https://travis-ci.org/nkovacs/streamquote) [![GoDoc](https://godoc.org/github.com/nkovacs/streamquote?status.svg)](https://godoc.org/github.com/nkovacs/streamquote)

This package provides a streaming version of `strconv.Quote`.

It allows you to quote the data in an `io.Reader` and write it out to
an `io.Writer` without having to store the entire input
and the entire output in memory.

Its primary use case is [go.rice](https://github.com/GeertJohan/go.rice) and similar tools, which need to
convert lots of files, some of them quite large, to go strings.

```go
converter := streamquote.New()
converter.Convert(inputfile, outfile)
```

Unlike `strconv.Quote`, it does not add quotes around the output.

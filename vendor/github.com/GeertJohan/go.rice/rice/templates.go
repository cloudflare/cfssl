package main

import (
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"text/template"

	"github.com/nkovacs/streamquote"
	"github.com/valyala/fasttemplate"
)

var (
	tmplEmbeddedBox          *template.Template
	tagEscaper, tagUnescaper *strings.Replacer
)

const (
	unescapeTag = "unescape:"
	injectTag   = "injectfile:"
)

func init() {
	var err error

	// $ is used as the escaping character,
	// because it has no special meaning in go strings,
	// so it won't be changed by strconv.Quote.
	replacements := []string{"$", "$$", "{%", "{$%", "%}", "%$}"}
	reverseReplacements := make([]string, len(replacements))
	l := len(reverseReplacements) - 1
	for i := range replacements {
		reverseReplacements[l-i] = replacements[i]
	}
	tagEscaper = strings.NewReplacer(replacements...)
	tagUnescaper = strings.NewReplacer(reverseReplacements...)

	// parse embedded box template
	tmplEmbeddedBox, err = template.New("embeddedBox").Funcs(template.FuncMap{
		"tagescape": func(s string) string {
			return fmt.Sprintf("{%%%v%v%%}", unescapeTag, tagEscaper.Replace(s))
		},
		"injectfile": func(s string) string {
			return fmt.Sprintf("{%%%v%v%%}", injectTag, tagEscaper.Replace(s))
		},
	}).Parse(`package {{.Package}}

import (
	"time"

	"github.com/GeertJohan/go.rice/embedded"
)

{{range .Boxes}}
func init() {

	// define files
	{{range .Files}}{{.Identifier}} := &embedded.EmbeddedFile{
		Filename:    {{.FileName | tagescape | printf "%q"}},
		FileModTime: time.Unix({{.ModTime}}, 0),

		Content:     string({{.Path | injectfile | printf "%q"}}),
	}
	{{end}}

	// define dirs
	{{range .Dirs}}{{.Identifier}} := &embedded.EmbeddedDir{
		Filename:    {{.FileName | tagescape | printf "%q"}},
		DirModTime: time.Unix({{.ModTime}}, 0),
		ChildFiles:  []*embedded.EmbeddedFile{
			{{range .ChildFiles}}{{.Identifier}}, // {{.FileName | tagescape | printf "%q"}}
			{{end}}
		},
	}
	{{end}}

	// link ChildDirs
	{{range .Dirs}}{{.Identifier}}.ChildDirs = []*embedded.EmbeddedDir{
		{{range .ChildDirs}}{{.Identifier}}, // {{.FileName | tagescape | printf "%q"}}
		{{end}}
	}
	{{end}}

	// register embeddedBox
	embedded.RegisterEmbeddedBox(` + "`" + `{{.BoxName}}` + "`" + `, &embedded.EmbeddedBox{
		Name: ` + "`" + `{{.BoxName}}` + "`" + `,
		Time: time.Unix({{.UnixNow}}, 0),
		Dirs: map[string]*embedded.EmbeddedDir{
			{{range .Dirs}}{{.FileName | tagescape | printf "%q"}}: {{.Identifier}},
			{{end}}
		},
		Files: map[string]*embedded.EmbeddedFile{
			{{range .Files}}{{.FileName | tagescape | printf "%q"}}: {{.Identifier}},
			{{end}}
		},
	})
}
{{end}}`)
	if err != nil {
		fmt.Printf("error parsing embedded box template: %s\n", err)
		os.Exit(-1)
	}
}

// embeddedBoxFasttemplate will inject file contents and unescape {% and %}.
func embeddedBoxFasttemplate(w io.Writer, src string) error {
	ft, err := fasttemplate.NewTemplate(src, "{%", "%}")
	if err != nil {
		return fmt.Errorf("error compiling fasttemplate: %s\n", err)
	}

	converter := streamquote.New()

	_, err = ft.ExecuteFunc(w, func(w io.Writer, tag string) (int, error) {
		if strings.HasPrefix(tag, unescapeTag) {
			tag = strings.TrimPrefix(tag, unescapeTag)
			return w.Write([]byte(tagUnescaper.Replace(tag)))
		}
		if !strings.HasPrefix(tag, injectTag) {
			return 0, fmt.Errorf("invalid fasttemplate tag: %v", tag)
		}
		tag = strings.TrimPrefix(tag, injectTag)

		fileName, err := strconv.Unquote("\"" + tag + "\"")
		if err != nil {
			return 0, fmt.Errorf("error unquoting filename %v: %v\n", tag, err)
		}
		f, err := os.Open(tagUnescaper.Replace(fileName))
		if err != nil {
			return 0, fmt.Errorf("error opening file %v: %v\n", fileName, err)
		}

		n, err := converter.Convert(f, w)

		f.Close()
		if err != nil {
			return n, fmt.Errorf("error converting file %v: %v\n", fileName, err)
		}

		return n, nil
	})
	if err != nil {
		return fmt.Errorf("error executing fasttemplate: %s\n", err)
	}

	return nil
}

type embedFileDataType struct {
	Package string
	Boxes   []*boxDataType
}

type boxDataType struct {
	BoxName string
	UnixNow int64
	Files   []*fileDataType
	Dirs    map[string]*dirDataType
}

type fileDataType struct {
	Identifier string
	FileName   string
	Path       string
	ModTime    int64
}

type dirDataType struct {
	Identifier string
	FileName   string
	Content    []byte
	ModTime    int64
	ChildDirs  []*dirDataType
	ChildFiles []*fileDataType
}

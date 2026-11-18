//go:build !js || !wasm

package browserpage

import (
	"html/template"
	"io"
	"strings"
)

type Template struct{ page *template.Template }

type Page struct {
	Title   string
	Content any
}

// New composes an authored control or development page with the shared shell.
// pass data through Page.Content so html/template escapes it in context. the
// portable pages do not use this renderer.
func New(body string) *Template {
	const shell = shellHead + `
<title>{{.Title}} - tnl</title>
<style>{{styles}}</style>` + shellBody + `{{template "content" .Content}}` + shellEnd
	return &Template{template.Must(template.New("page").Funcs(template.FuncMap{
		"styles": func() template.CSS { return template.CSS(styles) },
	}).Parse(shell + `{{define "content"}}` + body + `{{end}}`))}
}

func (t *Template) Write(w io.Writer, page Page) error { return t.page.Execute(w, page) }

func (t *Template) HTML(page Page) string {
	var result strings.Builder
	if err := t.Write(&result, page); err != nil {
		panic(err)
	}
	return result.String()
}

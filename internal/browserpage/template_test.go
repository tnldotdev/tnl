//go:build !js || !wasm

package browserpage

import (
	"errors"
	"strings"
	"testing"

	"golang.org/x/net/html"
)

func TestTemplatesEscapeDynamicValues(t *testing.T) {
	t.Parallel()
	attack := `"><script>alert("unsafe")</script><img src=x onerror=alert(1)>`
	page := New(`<h1>{{.Text}}</h1><form><input name="value" value="{{.Text}}"><a href="{{.URL}}">continue</a></form>`)
	body := page.HTML(Page{Title: attack, Content: struct{ Text, URL string }{attack, "javascript:alert(1)"}})
	document, err := html.Parse(strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	for node := range document.Descendants() {
		if node.Type == html.ElementNode && (node.Data == "script" || node.Data == "img") {
			t.Fatalf("dynamic value created an element: %s", node.Data)
		}
		for _, attribute := range node.Attr {
			if strings.HasPrefix(attribute.Key, "on") || attribute.Val == "javascript:alert(1)" {
				t.Fatal("dynamic value became executable markup")
			}
		}
	}
	if !strings.Contains(body, "&lt;script&gt;") || !strings.Contains(body, "#ZgotmplZ") {
		t.Fatal("template did not escape text and reject an executable link")
	}
}

type failedWriter struct{ err error }

func (w failedWriter) Write([]byte) (int, error) { return 0, w.err }

func TestTemplateReportsWriteFailure(t *testing.T) {
	cause := errors.New("connection closed")
	page := New(`<h1>{{.}}</h1>`)
	if err := page.Write(failedWriter{cause}, Page{Content: "message"}); !errors.Is(err, cause) {
		t.Fatalf("write failure = %v", err)
	}
}

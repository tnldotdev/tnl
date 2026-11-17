package browserpage

import (
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/tnldotdev/tnl/internal/browserfonts"
	"golang.org/x/net/html"
)

func TestSharedShellAndBundledFont(t *testing.T) {
	body := MessageHTML(Message{Title: "target unavailable", Summary: "Start your app and retry."})
	for _, fragment := range []string{
		`<html lang="en">`, `<title>target unavailable - tnl</title>`,
		`name="viewport"`, `name="color-scheme" content="dark"`,
		`aria-label="tnl home"`, `#0d1117`, `#86ead4`,
		`font-family:"Fira Code"`, `@media (max-width: 480px)`,
		`outline: 2px dashed`, `<h1>target unavailable</h1>`,
		`data:font/woff2;base64,` + base64.StdEncoding.EncodeToString(browserfonts.Latin),
	} {
		if !strings.Contains(body, fragment) {
			t.Fatalf("shared page is missing %q", fragment[:min(len(fragment), 80)])
		}
	}
	if strings.Contains(body, `/fonts/`) || strings.Contains(body, `<script`) {
		t.Fatal("standalone page requires an asset endpoint or script")
	}
	if strings.Contains(body, "<footer") || strings.Contains(body, "[ tnl ]") {
		t.Fatal("standalone page repeats the wordmark")
	}
}

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

func TestRedirectKeepsExactURLWithoutScript(t *testing.T) {
	location := `https://app.example.test/settings?tab=profile&next=a%2Fb&next=a+b&quote=%22`
	response := httptest.NewRecorder()
	Redirect(response, location)
	document, err := html.Parse(strings.NewReader(response.Body.String()))
	if err != nil {
		t.Fatal(err)
	}
	var refresh, link bool
	for node := range document.Descendants() {
		attributes := make(map[string]string)
		for _, attribute := range node.Attr {
			attributes[attribute.Key] = attribute.Val
		}
		if node.Data == "meta" && attributes["http-equiv"] == "refresh" {
			refresh = attributes["content"] == "0;url="+location
		}
		if node.Data == "a" && attributes["class"] == "button" {
			link = attributes["href"] == location
		}
	}
	if !refresh || !link || strings.Contains(response.Body.String(), "<script") {
		t.Fatal("handoff changed its refresh or fallback URL or introduced a script")
	}
	if response.Code != http.StatusOK || response.Header().Get("Content-Security-Policy") != ContentSecurityPolicy ||
		response.Header().Get("Referrer-Policy") != "no-referrer" || response.Header().Get("Cache-Control") != "no-store" ||
		response.Header().Get("Content-Type") != "text/html; charset=utf-8" || response.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatal("handoff lost standalone page headers", response.Header())
	}
}

func TestAcceptsHTML(t *testing.T) {
	for _, test := range []struct {
		accept string
		html   bool
	}{
		{"", false}, {"*/*", false}, {"text/*", false}, {"application/json", false},
		{"text/html", true}, {"text/html,application/xhtml+xml", true},
		{"TEXT/HTML; charset=utf-8", true}, {"text/plain,text/html;q=0.1", true},
		{"text/html;q=0,*/*;q=1", false}, {"text/html;q=invalid", false},
		{"text/html;q=-1", false}, {`text/html; broken`, false},
	} {
		t.Run(test.accept, func(t *testing.T) {
			if got := AcceptsHTML(test.accept); got != test.html {
				t.Fatalf("AcceptsHTML(%q) = %v", test.accept, got)
			}
		})
	}
}

func TestErrorPreservesPlainTextAndNegotiatesHTML(t *testing.T) {
	for _, accept := range []string{"", "*/*", "text/plain", "text/html;q=0", "text/html"} {
		request := httptest.NewRequest(http.MethodGet, "https://app.example.test/", nil)
		request.Header.Set("Accept", accept)
		response := httptest.NewRecorder()
		Error(response, request, "sign-in expired", http.StatusForbidden)
		if response.Code != http.StatusForbidden || response.Header().Get("Vary") != "Accept" {
			t.Fatal("error changed status or lost negotiation", response.Header())
		}
		if accept == "text/html" {
			if !strings.Contains(response.Body.String(), "<h1>forbidden</h1>") ||
				response.Header().Get("Content-Security-Policy") != ContentSecurityPolicy {
				t.Fatal("browser error did not use shared presentation")
			}
		} else if response.Body.String() != "sign-in expired\n" || response.Header().Get("Content-Type") != "text/plain; charset=utf-8" {
			t.Fatal("machine error changed", response.Body.String(), response.Header())
		}
	}
	request := httptest.NewRequest(http.MethodHead, "https://app.example.test/", nil)
	request.Header.Set("Accept", "text/html")
	response := httptest.NewRecorder()
	Error(response, request, "sign-in expired", http.StatusForbidden)
	if response.Code != http.StatusForbidden || response.Body.Len() != 0 {
		t.Fatal("HEAD error sent a body")
	}
}

type failedWriter struct{ err error }

func (w failedWriter) Write([]byte) (int, error) { return 0, w.err }

func TestTemplateReportsWriteFailure(t *testing.T) {
	cause := errors.New("connection closed")
	if err := messagePage.Write(failedWriter{cause}, Page{}); !errors.Is(err, cause) {
		t.Fatalf("write failure = %v", err)
	}
}

package browserpage

import (
	"encoding/base64"
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
		`aria-label="tnl home"`, `--background: #0d1117`, `--foreground: #ffffff`, `--primary: #86ead4`,
		`font-family:"JetBrains Mono"`, `@media (max-width: 480px)`,
		`outline: 2px dashed`, `<h1>target unavailable</h1>`,
		`data:font/woff2;base64,` + base64.StdEncoding.EncodeToString(browserfonts.Latin),
		FaviconLink(),
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

func TestFixedPagesEscapeTextAndURLs(t *testing.T) {
	message := MessageHTML(Message{
		Title:     `<script>payload</script>`,
		Summary:   `" onload="payload`,
		Code:      "<code>",
		RequestID: "x&y",
		HelpURL:   "javascript:alert(1)",
	})
	for _, want := range []string{"&lt;script&gt;payload&lt;/script&gt;", "&#34; onload=&#34;payload", "&lt;code&gt;", "x&amp;y", `href="#ZgotmplZ"`} {
		if !strings.Contains(message, want) {
			t.Errorf("message missing %q", want)
		}
	}
	for _, test := range []struct{ url, want string }{
		{`/app?one=1&two="x"`, `/app?one=1&amp;two=&#34;x&#34;`},
		{"https://preview.example.test/a b", "https://preview.example.test/a%20b"},
		{"javascript:alert(1)", "#ZgotmplZ"},
		{"//other.example.test", "#ZgotmplZ"},
		{"/%2Fother.example.test", "#ZgotmplZ"},
		{`/\other.example.test`, "#ZgotmplZ"},
		{"/%5Cother.example.test", "#ZgotmplZ"},
		{"https://user@preview.example.test", "#ZgotmplZ"},
	} {
		w := httptest.NewRecorder()
		Redirect(w, test.url)
		body := w.Body.String()
		if w.Code != http.StatusOK || w.Header().Get("Content-Security-Policy") != ContentSecurityPolicy ||
			!strings.Contains(body, `href="`+test.want+`"`) ||
			strings.Contains(body, `<meta http-equiv="refresh"`) != (test.want != "#ZgotmplZ") {
			t.Errorf("unexpected handoff for %q", test.url)
		}
	}
}

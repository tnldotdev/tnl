// package browserpage owns tnl's standalone browser presentation.
// it depends only on bundled fonts and the standard library; callers retain
// routing, authentication, status codes, and page-specific security policy.
package browserpage

import (
	_ "embed"
	"encoding/base64"
	"html"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/tnldotdev/tnl/internal/browserfonts"
)

// the bundled font needs no asset endpoint, third-party request, or live app.
const ContentSecurityPolicy = "default-src 'none'; style-src 'unsafe-inline'; font-src data:; base-uri 'none'; frame-ancestors 'none'; form-action 'none'"
const FormSecurityPolicy = "default-src 'none'; style-src 'unsafe-inline'; font-src data:; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"

//go:embed page.css
var stylesheet string

// only authored css and the bundled font enter the style element.
var styles = `@font-face{font-family:"Fira Code";font-style:normal;font-weight:300 700;font-display:swap;src:url("data:font/woff2;base64,` + base64.StdEncoding.EncodeToString(browserfonts.Latin) + `") format("woff2")}` + stylesheet

func Headers(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Security-Policy", ContentSecurityPolicy)
}

// AcceptsHTML requires an explicit html preference; api clients and callers
// accepting only */* keep their original machine-readable response.
func AcceptsHTML(accept string) bool {
	for part := range strings.SplitSeq(accept, ",") {
		mediaType, parameters, err := mime.ParseMediaType(strings.TrimSpace(part))
		if err != nil || mediaType != "text/html" {
			continue
		}
		quality, found := parameters["q"]
		if !found {
			return true
		}
		value, err := strconv.ParseFloat(quality, 64)
		if err == nil && value > 0 {
			return true
		}
	}
	return false
}

type Message struct {
	Title, Summary, Code, RequestID, HelpURL string
	Paragraphs                               []string
}

func MessageHTML(message Message) string {
	var page strings.Builder
	writeShell(&page, message.Title, "")
	page.WriteString("<h1>" + html.EscapeString(message.Title) + "</h1>\n")
	if message.Summary != "" {
		page.WriteString(`<p class="intro">` + html.EscapeString(message.Summary) + "</p>")
	}
	page.WriteByte('\n')
	for _, paragraph := range message.Paragraphs {
		page.WriteString("<p>" + html.EscapeString(paragraph) + "</p>")
	}
	page.WriteByte('\n')
	if message.Code != "" || message.RequestID != "" || message.HelpURL != "" {
		page.WriteString("<div class=\"details\">\n")
		if message.Code != "" {
			page.WriteString("<p><code>" + html.EscapeString(message.Code) + "</code></p>")
		}
		page.WriteByte('\n')
		if message.RequestID != "" {
			page.WriteString(`<p class="muted">request <code>` + html.EscapeString(message.RequestID) + "</code></p>")
		}
		page.WriteByte('\n')
		if message.HelpURL != "" {
			page.WriteString(`<p><a href="` + urlAttribute(message.HelpURL, false) + `">help with this error</a></p>`)
		}
		page.WriteString("\n</div>")
	}
	page.WriteString(shellEnd)
	return page.String()
}

func WriteMessage(w http.ResponseWriter, status int, message Message) {
	Headers(w)
	w.WriteHeader(status)
	_, _ = io.WriteString(w, MessageHTML(message))
}

func Error(w http.ResponseWriter, r *http.Request, message string, status int) {
	w.Header().Add("Vary", "Accept")
	if !AcceptsHTML(r.Header.Get("Accept")) {
		http.Error(w, message, status)
		return
	}
	Headers(w)
	w.WriteHeader(status)
	if r.Method != http.MethodHead {
		_, _ = io.WriteString(w, MessageHTML(Message{Title: strings.ToLower(http.StatusText(status)), Summary: message}))
	}
}

const redirectBody = `<p class="eyebrow">[ browser handoff ]</p>
<h1>continue to the preview</h1>
<p class="intro muted">Your browser should continue automatically.</p>
<p><a class="button" href="`

func Redirect(w http.ResponseWriter, location string) {
	Headers(w)
	w.WriteHeader(http.StatusOK)
	location = urlAttribute(location, true)
	refresh := location
	if refresh == "#ZgotmplZ" {
		refresh = ""
	}
	var page strings.Builder
	writeShell(&page, "continue to the preview", refresh)
	page.WriteString(redirectBody + location + `">continue to the preview</a></p>` + shellEnd)
	_, _ = io.WriteString(w, page.String())
}

// these pages have fixed markup. using typed fields instead of template method
// lookup lets the Go linker drop unrelated methods from the portable builds.
func writeShell(page *strings.Builder, title, escapedRefresh string) {
	page.WriteString(shellHead)
	if escapedRefresh != "" {
		page.WriteString(`<meta http-equiv="refresh" content="0;url=` + escapedRefresh + `">`)
	}
	page.WriteString("\n<title>" + html.EscapeString(title) + " - tnl</title>\n<style>" + styles + "</style>" + shellBody)
}

func urlAttribute(value string, redirect bool) string {
	// allow same-origin paths and absolute web URLs. reject ambiguous paths
	// that a browser could reinterpret as a protocol-relative URL.
	if value == "" || strings.ContainsAny(value, "\\\t\r\n") || strings.TrimSpace(value) != value {
		return "#ZgotmplZ"
	}
	target, err := url.Parse(value)
	if err != nil || target.User != nil {
		return "#ZgotmplZ"
	}
	if target.IsAbs() {
		if (target.Scheme != "https" && (redirect || target.Scheme != "http")) || target.Hostname() == "" {
			return "#ZgotmplZ"
		}
	} else if target.Host != "" || !strings.HasPrefix(target.Path, "/") || strings.HasPrefix(target.Path, "//") ||
		strings.ContainsAny(target.Path, "\\\t\r\n\x00") {
		return "#ZgotmplZ"
	}
	return html.EscapeString(strings.ReplaceAll(target.String(), " ", "%20"))
}

const shellHead = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="dark">
`
const shellBody = `
</head>
<body>
<div class="site">
<header>
<a class="brand" href="https://tnl.dev/" aria-label="tnl home">
<svg viewBox="0 0 3569 2508" aria-hidden="true" focusable="false"><g fill="currentColor">
<path transform="translate(0 1980) scale(1 -1)" d="M1075 59Q1016 20 932-5Q848-30 750-30Q556-30 458 70.5Q360 171 360 338V872H130V1059H360V1292L624 1324V1059H974L947 872H624V339Q624 257 664 219Q704 181 793 181Q850 181 897.5 194.5Q945 208 984 229Z"/>
<path transform="translate(1200 1980) scale(1 -1)" d="M161 0V1059H391L410 928Q478 1008 563 1048.5Q648 1089 746 1089Q889 1089 964 1006.5Q1039 924 1039 775V0H775V672Q775 752 765 800.5Q755 849 727 870.5Q699 892 646 892Q603 892 563.5 873Q524 854 489.5 822Q455 790 425 751V0Z"/>
<path transform="translate(2400 1980) scale(1 -1)" d="M665 1482V308Q665 239 705.5 210Q746 181 815 181Q858 181 898 190.5Q938 200 974 214L1039 34Q989 9 917.5-10.5Q846-30 752-30Q579-30 490 69Q401 168 401 336V1295H84V1482Z"/>
</g></svg>
</a>
<a href="https://tnl.dev/docs">[ docs ]</a>
</header>
<main>`
const shellEnd = `</main>
</div>
</body>
</html>`

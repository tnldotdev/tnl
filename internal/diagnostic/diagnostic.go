// Package diagnostic defines stable, user-facing diagnostics for tnl failures.
package diagnostic

import (
	"errors"
	"html"
	"mime"
	"net/http"
	"strconv"
	"strings"

	"github.com/tnldotdev/tnl/internal/clioutput"
)

type Code string

const (
	TargetUnavailable Code = "TNL_TARGET_UNAVAILABLE"
	TargetInvalid     Code = "TNL_TARGET_INVALID"
	RouteInvalid      Code = "TNL_ROUTE_INVALID"
	RequestRejected   Code = "TNL_REQUEST_REJECTED"
)

const helpOrigin = "https://tnl.dev"

type definition struct {
	code    Code
	title   string
	summary string
	path    string
	flow    []clioutput.FlowNode
}

var definitions = []definition{
	{
		code:    TargetUnavailable,
		title:   "local service unavailable",
		summary: "the request reached the publisher, but the publisher could not connect to the target. start the local service, then try again.",
		path:    "/e/target",
		flow: []clioutput.FlowNode{
			{Label: "visitor"},
			{Label: "tnl server"},
			{Label: "publisher", Detail: "target unavailable", Failure: true},
			{Label: "local service"},
		},
	},
	{
		code:    TargetInvalid,
		title:   "invalid target",
		summary: "tnl could not use the target configured for the local service.",
		path:    "/e/config",
		flow: []clioutput.FlowNode{
			{Label: "tnl publish / tnl dev"},
			{Label: "target configuration", Detail: "invalid host or port", Failure: true},
			{Label: "local service (not contacted)"},
		},
	},
	{
		code:    RouteInvalid,
		title:   "invalid route",
		summary: "the publisher could not use the hostname assigned to the route.",
		path:    "/e/route",
		flow: []clioutput.FlowNode{
			{Label: "tnl server", Detail: "invalid hostname", Failure: true},
			{Label: "publisher (not started)"},
		},
	},
	{
		code:    RequestRejected,
		title:   "request rejected",
		summary: "the publisher rejected the request before contacting the local service.",
		path:    "/e/request",
		flow: []clioutput.FlowNode{
			{Label: "visitor"},
			{Label: "tnl server"},
			{Label: "publisher", Detail: "request rejected", Failure: true},
			{Label: "local service (not contacted)"},
		},
	},
}

type Error struct {
	code    Code
	message string
	cause   error
}

func (e *Error) Error() string { return e.message }

func (e *Error) Unwrap() error { return e.cause }

func Wrap(code Code, cause error) error {
	if cause == nil {
		return nil
	}
	return &Error{code: code, message: cause.Error(), cause: cause}
}

func WrapMessage(code Code, message string, cause error) error {
	return &Error{code: code, message: message, cause: cause}
}

func CodeOf(err error) (Code, bool) {
	var diagnosticErr *Error
	if !errors.As(err, &diagnosticErr) {
		return "", false
	}
	return diagnosticErr.code, true
}

func HelpURL(code Code) string {
	return helpOrigin + definitionFor(code).path
}

func Codes() []Code {
	codes := make([]Code, 0, len(definitions))
	for _, definition := range definitions {
		codes = append(codes, definition.code)
	}
	return codes
}

func Text(code Code) string {
	definition := definitionFor(code)
	return renderText("tnl", code, definition.summary)
}

func TextForError(err error) (string, bool) {
	return TextForCommandError("tnl", err)
}

// TextForCommandError renders a classified error for one canonical command.
func TextForCommandError(command string, err error) (string, bool) {
	code, ok := CodeOf(err)
	if !ok {
		return "", false
	}
	definition := definitionFor(code)
	detail := err.Error()
	details := []string{definition.summary}
	if detail == "" || detail == definition.summary || detail == definition.title {
		details = details[:1]
	} else {
		details = append(details, detail)
	}
	return renderText(command, code, details...), true
}

func WriteHTTP(response http.ResponseWriter, request *http.Request, status int, code Code) {
	body := Text(code)
	contentType := "text/plain; charset=utf-8"
	if acceptsHTML(request.Header.Get("Accept")) {
		body = renderHTML(code)
		contentType = "text/html; charset=utf-8"
		response.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'")
		response.Header().Set("Referrer-Policy", "no-referrer")
	}
	response.Header().Set("Cache-Control", "no-store")
	response.Header().Set("Content-Length", strconv.Itoa(len(body)))
	response.Header().Set("Content-Type", contentType)
	response.Header().Set("Tnl-Error-Code", string(code))
	response.Header().Set("Vary", "Accept")
	response.Header().Set("X-Content-Type-Options", "nosniff")
	response.WriteHeader(status)
	if request.Method != http.MethodHead {
		_, _ = response.Write([]byte(body))
	}
}

func renderText(command string, code Code, details ...string) string {
	definition := definitionFor(code)
	blocks := make([]clioutput.Block, 0, len(details)+2)
	for _, detail := range details {
		blocks = append(blocks, clioutput.Text(detail))
	}
	blocks = append(blocks,
		clioutput.Flow(definition.flow...),
		clioutput.Fields(clioutput.Field{Label: "help", Value: HelpURL(code)}),
	)
	text, err := clioutput.Render(clioutput.Frame{
		Command: command,
		State:   definition.title,
		Blocks:  blocks,
		Footer:  string(code),
	})
	if err != nil {
		panic(err)
	}
	return text
}

func renderHTML(code Code) string {
	text := Text(code)
	url := HelpURL(code)
	prefix := strings.TrimSuffix(text, url+"\n")
	return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light">
<title>` + html.EscapeString(definitionFor(code).title) + ` - tnl</title>
<style>
html{background:#fff;color:#111;font-family:"Fira Code","SFMono-Regular",Consolas,"Liberation Mono",Menlo,monospace;font-variant-ligatures:none}
body{margin:0;padding:clamp(1.25rem,6vw,4rem)}
pre{margin:0;max-width:64ch;overflow-wrap:break-word;white-space:pre-wrap;font:inherit;line-height:1.55}
a{color:inherit;text-underline-offset:.2em}
a:focus-visible{outline:1px dashed #111;outline-offset:4px}
</style>
</head>
<body>
<pre>` + html.EscapeString(prefix) + `<a href="` + html.EscapeString(url) + `">` + html.EscapeString(url) + `</a>
</pre>
</body>
</html>
`
}

func acceptsHTML(accept string) bool {
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

func definitionFor(code Code) definition {
	for _, definition := range definitions {
		if definition.code == code {
			return definition
		}
	}
	panic("diagnostic: unknown code " + code)
}

// Package diagnostic defines stable, user-facing diagnostics for tnl failures.
package diagnostic

import (
	_ "embed"
	"encoding/json"
	"errors"
	"html"
	"io"
	"mime"
	"net/http"
	"strconv"
	"strings"

	"github.com/tnldotdev/tnl/internal/clioutput"
)

type Code string

const helpOrigin = "https://tnl.dev"

type definition struct {
	Code         Code                 `json:"code"`
	Slug         string               `json:"slug"`
	Category     string               `json:"category"`
	Title        string               `json:"title"`
	Summary      string               `json:"summary"`
	Description  string               `json:"description"`
	DiagramLabel string               `json:"diagram_label"`
	Surfaces     []string             `json:"surfaces"`
	HTTPStatus   int                  `json:"http_status"`
	Flow         []clioutput.FlowNode `json:"flow"`
	Causes       []string             `json:"causes"`
	Actions      struct {
		Visitor   []string `json:"visitor"`
		Publisher []string `json:"publisher"`
	} `json:"actions"`
}

//go:embed catalog.json
var catalogData []byte

var definitions = loadCatalog()

func loadCatalog() []definition {
	var catalog struct {
		SchemaVersion int          `json:"schema_version"`
		Diagnostics   []definition `json:"diagnostics"`
	}
	if err := json.Unmarshal(catalogData, &catalog); err != nil || catalog.SchemaVersion != 1 {
		panic("diagnostic: invalid embedded catalog")
	}
	seenCodes := map[Code]bool{}
	seenSlugs := map[string]bool{}
	for _, entry := range catalog.Diagnostics {
		if entry.Code == "" || entry.Slug == "" || entry.Title == "" || entry.Summary == "" || entry.Category == "" ||
			len(entry.Flow) == 0 || len(entry.Causes) == 0 || len(entry.Actions.Visitor)+len(entry.Actions.Publisher) == 0 ||
			seenCodes[entry.Code] || seenSlugs[entry.Slug] {
			panic("diagnostic: incomplete or duplicate catalog entry " + entry.Code)
		}
		seenCodes[entry.Code], seenSlugs[entry.Slug] = true, true
	}
	return catalog.Diagnostics
}

type Error struct {
	code       Code
	message    string
	cause      error
	showDetail bool
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
	return &Error{code: code, message: message, cause: cause, showDetail: true}
}

func CodeOf(err error) (Code, bool) {
	var diagnosticErr *Error
	if !errors.As(err, &diagnosticErr) {
		return "", false
	}
	return diagnosticErr.code, true
}

func HelpURL(code Code) string {
	return helpOrigin + "/e/" + definitionFor(code).Slug
}

func Summary(code Code) string { return definitionFor(code).Summary }

func Codes() []Code {
	codes := make([]Code, 0, len(definitions))
	for _, definition := range definitions {
		codes = append(codes, definition.Code)
	}
	return codes
}

func Text(code Code) string {
	definition := definitionFor(code)
	return renderText("tnl", code, definition.Summary)
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
	var classified *Error
	_ = errors.As(err, &classified)
	detail := ""
	if classified.showDetail {
		detail = classified.message
	}
	details := []string{definition.Summary}
	if detail == "" || detail == definition.Summary || detail == definition.Title {
		details = details[:1]
	} else {
		details = append(details, detail)
	}
	return renderText(command, code, details...), true
}

// WriteWarning renders a non-terminal diagnostic through the shared diagram renderer.
func WriteWarning(output io.Writer, command string, code Code) error {
	text := renderText(command, code, definitionFor(code).Summary)
	written, err := io.WriteString(output, text)
	if err == nil && written != len(text) {
		err = io.ErrShortWrite
	}
	return err
}

// WritePolicyDenial reports aggregate IP policy denials without visitor addresses.
func WritePolicyDenial(output io.Writer, command string, newlyBlocked, total uint64) error {
	text := renderText(command, IPPolicyDenied,
		"IP policy blocked visitor connections before they reached the local service.",
		"newly blocked: "+strconv.FormatUint(newlyBlocked, 10)+"; total blocked: "+strconv.FormatUint(total, 10),
	)
	written, err := io.WriteString(output, text)
	if err == nil && written != len(text) {
		return io.ErrShortWrite
	}
	return err
}

func WriteHTTP(response http.ResponseWriter, request *http.Request, code Code) {
	status := definitionFor(code).HTTPStatus
	if status < 400 || status > 599 {
		panic("diagnostic: code is not an HTTP failure " + code)
	}
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
		clioutput.Flow(definition.Flow...),
		clioutput.Fields(clioutput.Field{Label: "help", Value: HelpURL(code)}),
	)
	text, err := clioutput.Render(clioutput.Frame{
		Command: command,
		State:   definition.Title,
		Blocks:  blocks,
		Footer:  string(code),
	})
	if err != nil {
		panic(err)
	}
	return text
}

func renderHTML(code Code) string {
	definition := definitionFor(code)
	url := HelpURL(code)
	action := ""
	if len(definition.Actions.Visitor) != 0 {
		action = "<p>" + html.EscapeString(definition.Actions.Visitor[0]) + "</p>"
	}
	return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light">
<title>` + html.EscapeString(definition.Title) + ` - tnl</title>
<style>
html{background:#fff;color:#111;font-family:"Fira Code","SFMono-Regular",Consolas,"Liberation Mono",Menlo,monospace;font-variant-ligatures:none}
body{margin:0;padding:clamp(1.25rem,6vw,4rem);max-width:64ch;line-height:1.6}
h1{font-size:1.35rem;line-height:1.3}code{font:inherit}
a{color:inherit;text-underline-offset:.2em}
a:focus-visible{outline:1px dashed #111;outline-offset:4px}
</style>
</head>
<body>
<main><h1>` + html.EscapeString(definition.Title) + `</h1>
<p>` + html.EscapeString(definition.Summary) + `</p>
` + action + `<p><code>` + html.EscapeString(string(code)) + `</code> · <a href="` + html.EscapeString(url) + `">help with this error</a></p></main>
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
		if definition.Code == code {
			return definition
		}
	}
	panic("diagnostic: unknown code " + code)
}

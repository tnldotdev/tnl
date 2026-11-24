// Package diagnostic defines stable, user-facing diagnostics for tnl failures.
package diagnostic

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"syscall"

	"github.com/tnldotdev/tnl/internal/browserpage"
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
	Cases        []caseDefinition     `json:"cases"`
	Actions      struct {
		Visitor   []string `json:"visitor"`
		Publisher []string `json:"publisher"`
	} `json:"actions"`
}

type caseDefinition struct {
	ID            string `json:"id"`
	Description   string `json:"description"`
	Action        string `json:"action"`
	DiagramDetail string `json:"diagram_detail"`
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
		seenCases := map[string]bool{}
		for _, variant := range entry.Cases {
			if variant.ID == "" || variant.Description == "" || variant.Action == "" || variant.DiagramDetail == "" || seenCases[variant.ID] {
				panic("diagnostic: invalid case for " + entry.Code)
			}
			seenCases[variant.ID] = true
		}
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

// CodeOf reports a diagnostic only when extraction yields a non-nil Error.
func CodeOf(err error) (Code, bool) {
	diagnosticErr, ok := errors.AsType[*Error](err)
	if !ok || diagnosticErr == nil {
		return "", false
	}
	return diagnosticErr.code, true
}

func HelpURL(code Code, caseID string) string {
	result := helpOrigin + "/e/" + definitionFor(code).Slug
	if caseFor(code, caseID) != nil {
		result += "?case=" + caseID
	}
	return result
}

func HelpURLForError(err error) string {
	code, ok := CodeOf(err)
	if !ok {
		return ""
	}
	return HelpURL(code, KnownCase(err))
}

// KnownCase selects typed error context rather than reading error messages.
func KnownCase(err error) string {
	classified, ok := errors.AsType[*Error](err)
	if !ok || classified == nil {
		return ""
	}
	if classified.code == TargetUnavailable {
		if errors.Is(err, context.DeadlineExceeded) {
			return "timeout"
		}
		if errors.Is(err, syscall.ECONNREFUSED) {
			return "connection-refused"
		}
	}
	return ""
}

func caseFor(code Code, id string) *caseDefinition {
	for _, entry := range definitionFor(code).Cases {
		if entry.ID == id {
			return &entry
		}
	}
	return nil
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
	return renderText(textFrame("tnl", code, "", definitionFor(code).Summary))
}

func TextForError(err error) (string, bool) {
	f, ok := FrameForCommandError("tnl", err)
	if !ok {
		return "", false
	}
	return renderText(f), true
}

// FrameForCommandError describes a classified error for one canonical command.
func FrameForCommandError(command string, err error) (clioutput.Frame, bool) {
	classified, ok := errors.AsType[*Error](err)
	if !ok || classified == nil {
		return clioutput.Frame{}, false
	}
	code := classified.code
	definition := definitionFor(code)
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
	return textFrame(command, code, KnownCase(err), details...), true
}

// WriteWarning renders a non-terminal diagnostic through the shared diagram renderer.
func WriteWarning(output io.Writer, command string, code Code) error {
	return clioutput.Write(output, textFrame(command, code, "", definitionFor(code).Summary))
}

func WriteHTTP(response http.ResponseWriter, request *http.Request, code Code, caseID string) {
	status := definitionFor(code).HTTPStatus
	if status < 400 || status > 599 {
		panic("diagnostic: code is not an HTTP failure " + code)
	}
	variant := ""
	if caseFor(code, caseID) != nil {
		variant = caseID
	}
	body := renderText(textFrame("tnl", code, variant, definitionFor(code).Summary))
	contentType := "text/plain; charset=utf-8"
	if browserpage.AcceptsHTML(request.Header.Get("Accept")) {
		body = renderHTML(code, variant)
		contentType = "text/html; charset=utf-8"
		browserpage.Headers(response)
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

func textFrame(command string, code Code, caseID string, details ...string) clioutput.Frame {
	definition := definitionFor(code)
	blocks := make([]clioutput.Block, 0, len(details)+2)
	for _, detail := range details {
		blocks = append(blocks, clioutput.Text(detail))
	}
	flow := append([]clioutput.FlowNode(nil), definition.Flow...)
	if variant := caseFor(code, caseID); variant != nil {
		blocks = append(blocks, clioutput.Text(variant.Description), clioutput.Text(variant.Action))
		for index := range flow {
			if flow[index].Failure {
				flow[index].Detail = variant.DiagramDetail
				break
			}
		}
	}
	blocks = append(blocks, clioutput.Flow(flow...),
		clioutput.Fields(clioutput.Field{Label: "help", Value: HelpURL(code, caseID)}))
	return clioutput.Frame{
		Command: command,
		State:   definition.Title,
		Blocks:  blocks,
		Footer:  string(code),
	}
}

func renderText(frame clioutput.Frame) string {
	text, err := clioutput.Render(frame)
	if err != nil {
		panic(err)
	}
	return text
}

func renderHTML(code Code, caseID string) string {
	definition := definitionFor(code)
	var paragraphs []string
	if len(definition.Actions.Visitor) != 0 {
		paragraphs = append(paragraphs, definition.Actions.Visitor[0])
	}
	if variant := caseFor(code, caseID); variant != nil {
		paragraphs = append(paragraphs, variant.Description+" "+variant.Action)
	}
	return browserpage.MessageHTML(browserpage.Message{
		Title: definition.Title, Summary: definition.Summary,
		Paragraphs: paragraphs, Code: string(code), HelpURL: HelpURL(code, caseID),
	})
}

func definitionFor(code Code) definition {
	for _, definition := range definitions {
		if definition.Code == code {
			return definition
		}
	}
	panic("diagnostic: unknown code " + code)
}

package controlstate

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"html"
	"io"
	"path/filepath"
	"strings"

	xhtml "golang.org/x/net/html"
	"golang.org/x/net/html/atom"
)

type FeedbackElement struct {
	Kind   string `json:"kind"`
	Role   string `json:"role,omitempty"`
	Label  string `json:"label,omitempty"`
	TestID string `json:"test_id,omitempty"`
	HTML   string `json:"html,omitempty"`
}

type FeedbackAction struct {
	Type   string `json:"type"`
	Path   string `json:"path,omitempty"`
	Label  string `json:"label,omitempty"`
	TestID string `json:"test_id,omitempty"`
}

type FeedbackFailedRequest struct {
	Method     string `json:"method"`
	Path       string `json:"path"`
	Status     int    `json:"status"`
	DurationMS int    `json:"duration_ms"`
}

type FeedbackEvidence struct {
	Actions        []FeedbackAction        `json:"actions"`
	FailedRequests []FeedbackFailedRequest `json:"failed_requests"`
}

type FeedbackChangedFile struct {
	Path          string `json:"path"`
	Status        string `json:"status"`
	ContentSHA256 string `json:"content_sha256,omitempty"`
}

type CheckoutMarker struct {
	HeadCommit   string                `json:"head_commit"`
	Branch       string                `json:"branch"`
	ChangedFiles []FeedbackChangedFile `json:"changed_files"`
	Fingerprint  string                `json:"fingerprint"`
	Complete     *bool                 `json:"complete"`
}

func decodeFeedbackObject[T any](value json.RawMessage, maxBytes int) (T, error) {
	var result T
	if !validFeedbackJSON(value, maxBytes) {
		return result, ErrFeedbackInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(value))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&result); err != nil {
		return result, ErrFeedbackInvalid
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		return result, ErrFeedbackInvalid
	}
	return result, nil
}

func normalizeFeedbackElement(value json.RawMessage) (json.RawMessage, error) {
	element, err := decodeFeedbackObject[FeedbackElement](value, 4096)
	if err != nil || element.Kind != "page" && element.Kind != "element" ||
		len(element.Role) > 128 || len(element.Label) > 256 || len(element.TestID) > 128 {
		return nil, ErrFeedbackInvalid
	}
	if element.Kind == "element" {
		element.HTML, err = sanitizeElementHTML(element.HTML)
		if err != nil || element.HTML == "" {
			return nil, ErrFeedbackInvalid
		}
	} else if element.HTML != "" {
		return nil, ErrFeedbackInvalid
	}
	result, err := json.Marshal(element)
	if err != nil || len(result) > 4096 {
		return nil, ErrFeedbackInvalid
	}
	return result, nil
}

func normalizeFeedbackEvidence(value json.RawMessage) (json.RawMessage, error) {
	evidence, err := decodeFeedbackObject[FeedbackEvidence](value, 16384)
	if err != nil || len(evidence.Actions) > 20 || len(evidence.FailedRequests) > 20 {
		return nil, ErrFeedbackInvalid
	}
	for _, action := range evidence.Actions {
		if action.Type != "navigation" && action.Type != "click" && action.Type != "submit" ||
			len(action.Path) > 2048 || len(action.Label) > 256 || len(action.TestID) > 128 ||
			action.Path != "" && !validFeedbackPath(action.Path) {
			return nil, ErrFeedbackInvalid
		}
	}
	for _, failed := range evidence.FailedRequests {
		if failed.Method == "" || len(failed.Method) > 12 || !validFeedbackPath(failed.Path) ||
			strings.Contains(failed.Path, "?") || failed.Status != 0 && (failed.Status < 400 || failed.Status > 599) ||
			failed.DurationMS < 0 || failed.DurationMS > 600000 {
			return nil, ErrFeedbackInvalid
		}
	}
	result, err := json.Marshal(evidence)
	if err != nil || len(result) > 16384 {
		return nil, ErrFeedbackInvalid
	}
	return result, nil
}

func normalizeCheckoutMarker(value json.RawMessage) (json.RawMessage, error) {
	marker, err := decodeFeedbackObject[CheckoutMarker](value, 16384)
	if err != nil || marker.Complete == nil || len(marker.Branch) > 128 || strings.ContainsAny(marker.Branch, "\x00\r\n") || len(marker.ChangedFiles) > 64 ||
		!validSHA256Text(marker.Fingerprint) || marker.HeadCommit != "" && !validGitCommit(marker.HeadCommit) ||
		*marker.Complete && marker.HeadCommit == "" {
		return nil, ErrFeedbackInvalid
	}
	for _, changed := range marker.ChangedFiles {
		if changed.Path == "" || len(changed.Path) > 512 || filepath.IsAbs(changed.Path) || !filepath.IsLocal(changed.Path) ||
			strings.ContainsRune(changed.Path, '\x00') || strings.Contains(changed.Path, "\\") ||
			changed.Status != "added" && changed.Status != "modified" && changed.Status != "deleted" && changed.Status != "renamed" && changed.Status != "untracked" ||
			changed.ContentSHA256 != "" && !validSHA256Text(changed.ContentSHA256) {
			return nil, ErrFeedbackInvalid
		}
	}
	result, err := json.Marshal(marker)
	if err != nil || len(result) > 16384 {
		return nil, ErrFeedbackInvalid
	}
	return result, nil
}

func validSHA256Text(value string) bool {
	if !strings.HasPrefix(value, "sha256:") || len(value) != len("sha256:")+64 {
		return false
	}
	decoded, err := hex.DecodeString(value[len("sha256:"):])
	return err == nil && len(decoded) == 32 && hex.EncodeToString(decoded) == value[len("sha256:"):]
}

func validGitCommit(value string) bool {
	if len(value) != 40 && len(value) != 64 {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && hex.EncodeToString(decoded) == value
}

func sanitizeElementHTML(value string) (string, error) {
	if len(value) == 0 || len(value) > 4096 {
		return "", ErrFeedbackInvalid
	}
	context := &xhtml.Node{Type: xhtml.ElementNode, Data: "div", DataAtom: atom.Div}
	nodes, err := xhtml.ParseFragment(strings.NewReader(value), context)
	if err != nil {
		return "", ErrFeedbackInvalid
	}
	var output strings.Builder
	var render func(*xhtml.Node)
	render = func(node *xhtml.Node) {
		if output.Len() > 4096 {
			return
		}
		switch node.Type {
		case xhtml.TextNode:
			output.WriteString(html.EscapeString(node.Data))
		case xhtml.ElementNode:
			if node.Data == "script" || node.Data == "style" || node.Data == "template" || node.Data == "iframe" || node.Data == "svg" || node.Data == "math" {
				return
			}
			allowed := false
			switch node.Data {
			case "a", "button", "div", "span", "p", "label", "form", "input", "textarea", "select", "option", "ul", "li", "strong", "em", "h1", "h2", "h3":
				allowed = true
			}
			if allowed {
				output.WriteByte('<')
				output.WriteString(node.Data)
				for _, attribute := range node.Attr {
					switch attribute.Key {
					case "id", "class", "role", "aria-label", "data-testid", "title", "name", "type":
						if len(attribute.Val) <= 256 {
							output.WriteByte(' ')
							output.WriteString(attribute.Key)
							output.WriteString(`="`)
							output.WriteString(html.EscapeString(attribute.Val))
							output.WriteByte('"')
						}
					}
				}
				output.WriteByte('>')
			}
			if node.Data != "textarea" && node.Data != "option" {
				for child := node.FirstChild; child != nil; child = child.NextSibling {
					render(child)
				}
			}
			if allowed && node.Data != "input" {
				output.WriteString("</")
				output.WriteString(node.Data)
				output.WriteByte('>')
			}
		default:
			return
		}
	}
	for _, node := range nodes {
		render(node)
	}
	if output.Len() > 4096 {
		return "", ErrFeedbackInvalid
	}
	return output.String(), nil
}

package failure

import (
	"context"
	"errors"
	"io/fs"
	"strings"
	"syscall"
)

// ClientEntry is the public, code-owned description of one client failure.
type ClientEntry struct {
	Code    Reason `json:"code"`
	Slug    string `json:"slug"`
	Class   Class  `json:"class"`
	Message string `json:"message"`
	Action  string `json:"action"`
	Cases   []Case `json:"cases,omitempty"`
}

// ClientReasons returns every client failure in stable code order.
func ClientReasons() []ClientEntry {
	var entries []ClientEntry
	for _, reason := range Reasons() {
		if !strings.HasPrefix(string(reason), "TNL_CLIENT_") {
			continue
		}
		definition, _ := DefinitionFor(reason)
		entries = append(entries, ClientEntry{
			Code: reason, Slug: strings.ToLower(strings.ReplaceAll(strings.TrimPrefix(string(reason), "TNL_CLIENT_"), "_", "-")),
			Class: definition.Class, Message: definition.Message, Action: definition.Action, Cases: definition.Cases,
		})
	}
	return entries
}

// HelpURL keeps the failure identity in its path and accepts only authored cases.
func HelpURL(reason Reason, caseID string) string {
	if !strings.HasPrefix(string(reason), "TNL_CLIENT_") {
		return ""
	}
	if _, ok := DefinitionFor(reason); !ok {
		return ""
	}
	slug := strings.ToLower(strings.ReplaceAll(strings.TrimPrefix(string(reason), "TNL_CLIENT_"), "_", "-"))
	result := "https://tnl.dev/c/" + slug
	if CaseFor(reason, caseID) != nil {
		result += "?case=" + caseID
	}
	return result
}

func CaseFor(reason Reason, id string) *Case {
	definition, ok := DefinitionFor(reason)
	if !ok {
		return nil
	}
	for _, entry := range definition.Cases {
		if entry.ID == id {
			return &entry
		}
	}
	return nil
}

// KnownCase selects context from typed causes; it never reads error messages.
func KnownCase(err error) string {
	reason, ok := ReasonOf(err)
	if !ok {
		return ""
	}
	switch reason {
	case ClientStateUnavailable:
		if errors.Is(err, fs.ErrPermission) {
			return "permission-denied"
		}
	case ServerUnavailable:
		if errors.Is(err, context.DeadlineExceeded) {
			return "timeout"
		}
		if errors.Is(err, syscall.ECONNREFUSED) {
			return "connection-refused"
		}
	}
	return ""
}

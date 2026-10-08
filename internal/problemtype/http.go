package problemtype

import (
	"net/http"

	"github.com/tnldotdev/tnl/internal/httpjson"
	"github.com/tnldotdev/tnl/internal/opaqueid"
)

// Problem is the shared HTTP error envelope. an API owns its allowed codes,
// while this writer owns the fields and request correlation across services.
type Problem struct {
	Type      string         `json:"type"`
	Title     string         `json:"title"`
	Status    int            `json:"status"`
	Code      string         `json:"code"`
	Detail    string         `json:"detail"`
	RequestID string         `json:"request_id"`
	Details   map[string]any `json:"details"`
}

func NewRequestID() string {
	value, err := opaqueid.New(opaqueid.RequestPrefix)
	if err != nil {
		return "request_unavailable"
	}
	return value
}

// Write sends an authored problem once and returns the ID for operational logs.
func Write(response http.ResponseWriter, status int, code, title, detail string, caseID ...string) string {
	requestID := NewRequestID()
	variant := ""
	if len(caseID) > 0 {
		variant = caseID[0]
	}
	response.Header().Set("Link", "<"+HelpURL(code, variant)+">; rel=\"help\"")
	httpjson.WriteProblem(response, status, Problem{
		Type: URL(code), Title: title, Status: status, Code: code, Detail: detail,
		RequestID: requestID, Details: map[string]any{},
	})
	return requestID
}

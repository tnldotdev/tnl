package tunnelv1

import (
	"errors"
	"strings"
)

// TraceContext carries untrusted telemetry only. it must never select an
// identity, tenant, authorization decision, or local process resource. only
// canonical W3C version 00 traceparent is supported; no baggage is carried.
type TraceContext struct {
	TraceParent string `json:"traceparent,omitempty"`
}

func (t TraceContext) Validate() error {
	p := t.TraceParent
	if p == "" {
		return nil
	}
	if len(p) != 55 || p[:3] != "00-" || p[35] != '-' || p[52] != '-' || (p[53:] != "00" && p[53:] != "01") ||
		!traceHex(p[3:35]) || !traceHex(p[36:52]) || strings.Trim(p[3:35], "0") == "" || strings.Trim(p[36:52], "0") == "" {
		return errors.New("tunnelv1: invalid trace context")
	}
	return nil
}

func traceHex(s string) bool {
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

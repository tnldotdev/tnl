package operatorlog

import (
	"errors"
	"strings"
	"testing"

	"github.com/tnldotdev/tnl/internal/failure"
)

func TestFormatDoesNotExposeCauseOrMultilineContext(t *testing.T) {
	cause := errors.New("Authorization: Bearer secret-do-not-log")
	err := failure.Wrap("read client session", failure.ClientStateUnavailable, cause)
	if !errors.Is(err, cause) {
		t.Fatal("failure lost its original cause")
	}
	got := Format("read client session", failure.ClientStateUnavailable, "request_1\nspoofed")
	if strings.Contains(got, "secret-do-not-log") || strings.ContainsRune(got, '\n') ||
		!strings.Contains(got, "reason=client.state_unavailable") || !strings.Contains(got, "request_id=request_1?spoofed") {
		t.Fatalf("operator log = %q", got)
	}
}

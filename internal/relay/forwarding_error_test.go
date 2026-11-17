package relay

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"

	quic "github.com/quic-go/quic-go"
	"github.com/tnldotdev/tnl/internal/failure"
)

func TestForwardingErrorPreservesAllCausesAndSafePresentation(t *testing.T) {
	reset := &quic.StreamError{StreamID: 41, ErrorCode: 17, Remote: true}
	cleanup := errors.New("secret physical cleanup material")
	operation := failure.Wrap("forward through relay", failure.TargetUnavailable, errors.Join(reset, net.ErrClosed))
	diagnostic := ForwardingError{service: "service", run: "run", visitor: "visitor", number: 3, phase: "copy", copyResult: operation, cleanup: cleanup}
	reported := diagnostic.finish(operation)
	var got *quic.StreamError
	if !errors.Is(reported, operation) || !errors.Is(reported, cleanup) || !errors.Is(reported, net.ErrClosed) ||
		!errors.As(reported, &got) || got != reset || diagnostic.ForwardingCopyResult() != operation || diagnostic.ForwardingCleanup() != cleanup {
		t.Fatal("diagnostic wrapper lost original cause identities")
	}
	if reason, ok := failure.ReasonOf(reported); !ok || reason != failure.TargetUnavailable ||
		failure.Only(reported, net.ErrClosed) != failure.Only(errors.Join(operation, cleanup), net.ErrClosed) {
		t.Fatal("diagnostic wrapper changed operational classification")
	}
	encoded, err := json.Marshal(reported)
	if err != nil || string(encoded) != "{}" {
		t.Fatal("diagnostic error serialized its raw cause")
	}
	for _, format := range []string{"%s", "%v", "%+v", "%#v"} {
		if text := fmt.Sprintf(format, reported); strings.Contains(text, "secret") || strings.Contains(text, "stream 41") {
			t.Fatal("diagnostic presentation formatted a raw cause")
		}
	}
	if err := (&ForwardingError{}).finish(nil); err != nil {
		t.Fatal("diagnostic wrapper invented a failure")
	}
}

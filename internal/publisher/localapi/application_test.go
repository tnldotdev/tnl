package localapi

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	publisherprotocol "github.com/tnldotdev/tnl/internal/publisher/localapi/protocol"
)

func TestApplicationEndpointsRejectForgedZeroAndOwnerCapabilities(t *testing.T) {
	server := httptest.NewUnstartedServer(nil)
	capabilities, err := publisherprotocol.NewCapabilities("http://" + server.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	server.Config.Handler = (&Server{Capabilities: capabilities, PublishApplication: func(context.Context, publisherprotocol.ApplicationPublication) (publisherprotocol.AcceptedPublication, error) {
		calls.Add(1)
		return publisherprotocol.AcceptedPublication{}, nil
	}}).Handler()
	server.Start()
	defer server.Close()
	if err := publisherprotocol.Call(t.Context(), publisherprotocol.Endpoint{}, "POST", "/v1/publications", map[string]any{}, nil); !errors.Is(err, publisherprotocol.ErrUnauthorized) {
		t.Fatal("zero endpoint passed typed validation", err)
	}
	for _, id := range []*string{nil, new(string)} {
		if _, err := capabilities.Issue(publisherprotocol.CapabilityRequest{Scope: "invocation", InvocationId: id}); !errors.Is(err, publisherprotocol.ErrForbidden) {
			t.Fatal("nil or empty invocation selector was issued", err)
		}
	}
	owner := capabilities.Owner()
	for _, path := range []string{"/v1/publications", "/v1/capability"} {
		method := http.MethodPost
		if path == "/v1/capability" {
			method = http.MethodDelete
		}
		if err := publisherprotocol.Call(t.Context(), owner, method, path, map[string]any{}, nil); !errors.Is(err, publisherprotocol.ErrForbidden) {
			t.Fatal("owner grant with nil invocation selector reached an application operation", err)
		}
	}
	// changing a descriptor's scope cannot change the immutable server grant.
	forged := owner
	forged.Scope = "invocation"
	if err := publisherprotocol.Call(t.Context(), forged, "POST", "/v1/publications", map[string]any{}, nil); !errors.Is(err, publisherprotocol.ErrUnauthorized) {
		t.Fatal("forged nil invocation passed typed validation", err)
	}
	id := "ivk_0123456789ABCDEFGHIJKL"
	forged.InvocationId = &id
	if err := publisherprotocol.Call(t.Context(), forged, "POST", "/v1/publications", map[string]any{"invocation_id": id}, nil); !errors.Is(err, publisherprotocol.ErrForbidden) {
		t.Fatal("forged descriptor changed its authenticated owner scope", err)
	}
	request, err := http.NewRequestWithContext(t.Context(), "POST", owner.Url+"/v1/publications", bytes.NewBufferString(`{"invocation_id":null}`))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+strings.Repeat("0", 64))
	response, err := server.Client().Do(request)
	if err != nil {
		t.Fatal("forged raw request panicked or closed the server connection", err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized || calls.Load() != 0 {
		t.Fatalf("forged raw request reached publication work: status=%d calls=%d", response.StatusCode, calls.Load())
	}
}

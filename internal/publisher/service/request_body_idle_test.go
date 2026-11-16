package service

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/policy/applicationlimits"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestServiceRequestBodyIdleTimeoutApproval(t *testing.T) {
	cfg, control := lifecycleFixture(t)
	approved, err := control.GetPublisherService(t.Context(), cfg.ServiceID, "")
	if err != nil {
		t.Fatal(err)
	}
	approved.Protocol, approved.Endpoint.Port = controlv1.ServiceProtocolHTTP, 443
	for _, timeout := range []*string{nil, new("45s"), new("0s"), new("-1s"), new("2562048h")} {
		approved.HttpRequestBodyIdleTimeout = timeout
		prepared, err := newManagedPrepared(control.prep, approved, cfg)
		if timeout != nil && *timeout != "45s" {
			if err == nil {
				t.Fatal("publisher accepted invalid approved HTTP timeout", *timeout)
			}
			continue
		}
		want := applicationlimits.DefaultRequestBodyIdleTimeout
		if timeout != nil {
			want = 45 * time.Second
		}
		if err != nil || prepared.requestBodyIdleTimeout != want {
			t.Fatal("publisher lost approved HTTP timeout", timeout, err)
		}
	}
}

func TestServiceFirstHTTP1AdmissionPreservesBodyIdleTimeout(t *testing.T) {
	ended := make(chan error, 1)
	f := newPendingHTTPFixture(t, 1, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err := io.Copy(io.Discard, r.Body)
		ended <- err
		if err != nil {
			w.WriteHeader(http.StatusRequestTimeout)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	// configure the approved serving fact before opening any visitor.
	f.source.prepared.requestBodyIdleTimeout = 100 * time.Millisecond
	client := newCompositionHTTPClient(t, f, 0, false)
	defer client.visitor.close()
	request := fmt.Sprintf("POST /upload HTTP/1.1\r\nHost: %s\r\nAuthorization: Bearer unchanged-application\r\nContent-Length: 2\r\n\r\na",
		f.source.prepared.managedHostname)
	if _, err := io.WriteString(client.visitor.secure, request); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-ended:
		var timeout net.Error
		if !errors.As(err, &timeout) || !timeout.Timeout() {
			t.Fatal("stalled first upload did not fail at its body-read deadline", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("first HTTP/1 capacity admission cleared the body idle timeout")
	}
	if f.capacity.Load() != 1 || f.calls.Load() != 1 {
		t.Fatal("upload did not cross the real first-admission boundary", f.capacity.Load(), f.calls.Load())
	}
	response, err := http.ReadResponse(client.visitor.reader, &http.Request{Method: http.MethodPost})
	if err == nil {
		if response.StatusCode < 400 {
			t.Fatal("timed-out first upload reported success", response.Status)
		}
		if err := response.Body.Close(); err != nil {
			t.Fatal("close timed-out upload response", err)
		}
	}
	// the stream retires after its response and HTTP workers join. let that
	// observed retirement finish before the fixture stops its shared relay.
	client.visitor.join(t)
}

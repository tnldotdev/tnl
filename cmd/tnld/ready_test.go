package main

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/tnldotdev/tnl/internal/failure"
)

func TestReadyRequiresLocal204(t *testing.T) {
	for _, status := range []int{204, 200, 302, 503} {
		s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != "GET" || r.URL.Path != "/ready" {
				t.Errorf("unexpected probe request")
			}
			w.Header().Set("Location", "/private")
			w.WriteHeader(status)
			if status != 204 {
				_, _ = w.Write([]byte("private diagnostic"))
			}
		}))
		err := checkReady(t.Context(), s.Listener.Addr().(*net.TCPAddr).Port)
		s.Close()
		if status == 204 {
			if err != nil {
				t.Fatal(err)
			}
			continue
		}
		reason, def, ok := failure.Describe(err)
		var out bytes.Buffer
		writeTerminalError(&out, err)
		if !ok || reason != failure.ServerNotReady || def.Retry != failure.RetryLater || strings.Contains(out.String(), "private") {
			t.Fatalf("unexpected readiness classification at status %d", status)
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := checkReady(ctx, 9090); !errors.Is(err, context.Canceled) {
		t.Fatal("probe lost original transport cause")
	}
}

package httpstream_test

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/transport/httpstream"
)

func TestTargetPoolReleasesClosedUpgradeWithoutReplayingIt(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/upgrade" {
			_, _ = io.WriteString(w, "later request")
			return
		}
		conn, buffered, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		defer conn.Close()
		_, _ = io.WriteString(buffered, "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n")
		if err := buffered.Flush(); err != nil {
			t.Error(err)
			return
		}
		_, _ = io.Copy(conn, buffered)
	}))
	defer server.Close()
	pool, err := httpstream.NewTargetTransport(ctx, func(ctx context.Context) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", server.Listener.Addr().String())
	}, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := pool.Close(); err != nil {
			t.Error(err)
		}
	}()
	request, _ := http.NewRequestWithContext(ctx, http.MethodGet, server.URL+"/upgrade", nil)
	request.Header.Set("Connection", "Upgrade")
	request.Header.Set("Upgrade", "websocket")
	response, err := pool.RoundTrip(request)
	if err != nil || response.StatusCode != http.StatusSwitchingProtocols {
		t.Fatal("target upgrade failed", err)
	}
	body, ok := response.Body.(io.ReadWriteCloser)
	if !ok {
		t.Fatal("pooled upgrade lost its write direction")
	}
	if _, err := io.WriteString(body, "echo"); err != nil {
		t.Fatal(err)
	}
	var echoed [4]byte
	if _, err := io.ReadFull(body, echoed[:]); err != nil || string(echoed[:]) != "echo" {
		t.Fatal("target upgrade did not preserve its bidirectional bytes", err)
	}
	if err := body.Close(); err != nil {
		t.Fatal(err)
	}
	if err := body.Close(); err != nil {
		t.Fatal("upgrade close was not idempotent", err)
	}
	request, _ = http.NewRequestWithContext(ctx, http.MethodGet, server.URL+"/later", nil)
	response, err = pool.RoundTrip(request)
	if err != nil {
		t.Fatal("closed upgrade retained the pool's only target slot", err)
	}
	defer response.Body.Close()
	data, err := io.ReadAll(response.Body)
	if err != nil || string(data) != "later request" {
		t.Fatal("independent request did not use the retired upgrade's capacity", err)
	}
}

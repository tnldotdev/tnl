package publisher

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/proxyproto"
	"github.com/tnldotdev/tnl/pkg/api/publisherv1"
)

func TestBrowserAccessStatusSharesTheForwardingDecision(t *testing.T) {
	forwarded := 0
	upstream := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		forwarded++
		response.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()
	route, err := NewPublicURLServer(PublicURLServerConfig{
		Hostname: "route.example", Target: upstream.URL, Certificate: publicURLTestCertificate(t, "route.example"),
		PreviewID: "pv_0123456789abcdefghijkl", PublicURLID: "url_0123456789abcdefghijkl", PublishRunNumber: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := route.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = route.Close() })
	for _, denied := range []bool{true, false} {
		name := "allowed"
		if denied {
			name = "denied"
		}
		t.Run(name, func(t *testing.T) {
			ingress, publisher := net.Pipe()
			_ = ingress.SetDeadline(time.Now().Add(5 * time.Second))
			finished := make(chan struct{})
			go func() { route.handleVisitor(publisher, denied); close(finished) }()
			t.Cleanup(func() { _ = ingress.Close(); awaitPublisherTest(t, finished) })
			header, err := proxyproto.Encode(proxyproto.Header{
				Source: netip.MustParseAddrPort("192.0.2.10:1234"), Destination: netip.MustParseAddrPort("127.0.0.1:443"),
			})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := ingress.Write(header); err != nil {
				t.Fatal(err)
			}
			visitor := tls.Client(ingress, &tls.Config{ServerName: "route.example", InsecureSkipVerify: true}) // test certificate is self-signed.
			if err := visitor.Handshake(); err != nil {
				t.Fatal(err)
			}
			reader := bufio.NewReader(visitor)
			for _, path := range []string{"/__tnl/access", "/"} {
				if _, err := fmt.Fprintf(visitor, "GET %s HTTP/1.1\r\nHost: route.example\r\n\r\n", path); err != nil {
					t.Fatal(err)
				}
				response, err := http.ReadResponse(reader, &http.Request{Method: http.MethodGet})
				if err != nil {
					t.Fatal(err)
				}
				body, err := io.ReadAll(response.Body)
				_ = response.Body.Close()
				if err != nil {
					t.Fatal(err)
				}
				if path == "/__tnl/access" {
					var result publisherv1.BrowserAccessStatus
					if err := json.Unmarshal(body, &result); err != nil {
						t.Fatal(err)
					}
					if result.Allowed == denied || response.StatusCode != map[bool]int{true: 403, false: 200}[denied] ||
						result.PublishRunNumber != 2 || response.Header.Get("Cache-Control") != "no-store" {
						t.Fatalf("access status=%d, %+v", response.StatusCode, result)
					}
				} else if response.StatusCode != map[bool]int{true: 403, false: 204}[denied] {
					t.Fatalf("forwarding status=%d", response.StatusCode)
				}
			}
			_ = visitor.Close()
		})
	}
	if forwarded != 1 {
		t.Fatalf("local service saw %d requests; access status must not reach it", forwarded)
	}
}

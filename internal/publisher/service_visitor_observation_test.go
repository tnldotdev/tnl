package publisher_test

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/publisher"
)

func TestManagedVisitorRepresentationsDispatchAfterTLS(t *testing.T) {
	certificates := serviceCertificates(t)
	const host = "web.production.storefront.example.test"
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "target") }))
	defer target.Close()
	for _, kind := range []string{"HTTP", "native", "certificate"} {
		for _, pointer := range []bool{false, true} {
			name := kind + "/value"
			if pointer {
				name = kind + "/pointer"
			}
			t.Run(name, func(t *testing.T) {
				called := make(chan struct{}, 8)
				allowed := func() (publisher.ServiceVisitorDecision, error) {
					select {
					case called <- struct{}{}:
					default:
					}
					return publisher.ServiceVisitorDecision{Allowed: true, ValidUntil: time.Now().Add(time.Minute)}, nil
				}
				var visitor publisher.ServiceVisitorAuthentication
				want := "target"
				switch kind {
				case "HTTP":
					want = "frontend"
					v := publisher.PublicHTTPVisitor{Frontend: httpFrontendFunc(func(_ context.Context, conn *tls.Conn, _ publisher.ServiceHTTPTarget) error {
						if !conn.ConnectionState().HandshakeComplete {
							t.Error("frontend preceded TLS")
						}
						request, err := http.ReadRequest(bufio.NewReader(conn))
						if err != nil {
							return err
						}
						defer request.Body.Close()
						called <- struct{}{}
						_, err = io.WriteString(conn, "HTTP/1.1 200 OK\r\nContent-Length: 8\r\nConnection: close\r\n\r\nfrontend")
						return err
					})}
					visitor = v
					if pointer {
						visitor = &v
					}
				case "native":
					v := publisher.ConnectorVisitor{Admission: publisher.NativeAdmissionFixture{Check: func(context.Context) (publisher.ServiceVisitorDecision, error) { return allowed() }}}
					visitor = v
					if pointer {
						visitor = &v
					}
				case "certificate":
					v := publisher.CertificateVisitor{Check: func(_ context.Context, leaf *x509.Certificate) (publisher.ServiceVisitorDecision, error) {
						if leaf == nil {
							t.Error("certificate admission omitted the TLS leaf")
						}
						return allowed()
					}}
					visitor = v
					if pointer {
						visitor = &v
					}
				}
				stream := publisher.ServiceStream{Protocol: config.ProtocolHTTP, Hostname: host, Target: strings.TrimPrefix(target.URL, "http://"), TLS: &tls.Config{Certificates: []tls.Certificate{certificates.server}}, Visitor: visitor}
				address := managedPublisherListener(t, stream)
				clientTLS := &tls.Config{RootCAs: certificates.roots, ServerName: host}
				if kind == "certificate" {
					clientTLS.Certificates = []tls.Certificate{certificates.client}
				}
				transport := &http.Transport{TLSClientConfig: clientTLS}
				defer transport.CloseIdleConnections()
				client := &http.Client{Transport: transport, Timeout: 3 * time.Second}
				response, err := client.Get("https://" + address)
				if err != nil {
					t.Fatal(err)
				}
				defer response.Body.Close()
				body, err := io.ReadAll(response.Body)
				if err != nil || string(body) != want {
					t.Fatal("visitor dispatched to the wrong frontend", string(body), err)
				}
				select {
				case <-called:
				default:
					t.Fatal("visitor authentication or frontend was skipped")
				}
			})
		}
	}
}

package service

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/publisher/httpaccess"
	"github.com/tnldotdev/tnl/internal/publisher/requestlimit"
	servicestream "github.com/tnldotdev/tnl/internal/publisher/service/stream"
	"github.com/tnldotdev/tnl/internal/testutil/visitorfixture"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestServiceHTTPCaseInsensitiveSNIKeepsAuthorityAndAccessFences(t *testing.T) {
	const hostname = "preview.example.test"
	const sibling = "other.example.test"
	const body = "one authorized service HTTP request"
	certificate := visitorfixture.Certificate(t, "*.example.test")
	roots := visitorfixture.Roots(t, certificate)
	for _, name := range []string{hostname, strings.ToUpper(hostname), sibling} {
		if _, err := certificate.Leaf.Verify(x509.VerifyOptions{
			DNSName: name, Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		}); err != nil {
			t.Fatal("shared wildcard certificate does not verify a contrasted name", name, err)
		}
	}
	for _, inline := range []bool{false, true} {
		for _, h2 := range []bool{false, true} {
			for _, test := range []struct {
				name, sni, host, credential string
				status, target, owner       int
			}{
				{"exact", hostname, hostname, "valid", http.StatusOK, 1, 1},
				{"uppercase_same_name", strings.ToUpper(hostname), hostname, "valid", http.StatusOK, 1, 1},
				{"covered_sibling_sni", sibling, hostname, "valid", http.StatusMisdirectedRequest, 0, 0},
				{"wrong_host", hostname, sibling, "valid", http.StatusMisdirectedRequest, 0, 0},
				{"missing_permission", hostname, hostname, "", http.StatusForbidden, 0, 1},
				{"invalid_permission", hostname, hostname, "invalid", http.StatusForbidden, 0, 1},
			} {
				t.Run(fmt.Sprintf("inline=%t/http2=%t/%s", inline, h2, test.name), func(t *testing.T) {
					var targets, ownerChecks, capacity atomic.Int32
					var frontend HTTP
					var application servicestream.HTTPTarget
					var budget *requestlimit.HTTP
					client, _, _, token := serviceHTTPConfiguredFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						targets.Add(1)
						if r.Host != hostname || r.URL.Path != "/sni" || r.Header.Get(httpaccess.VisitorTokenHeader) != "" {
							t.Error("authorized request changed its service authority, path, or credential stripping")
						}
						if _, err := io.WriteString(w, body); err != nil {
							t.Error(err)
						}
					}), h2, inline, func(f *HTTP) {
						var err error
						f.Requests, err = requestlimit.NewHTTP(&controlv1.ProjectHTTPApplicationLimits{Total: new(1), Concurrency: new(1)})
						if err != nil {
							t.Fatal(err)
						}
						budget = f.Requests
						f.AdmitRequest = func(*http.Request) error { ownerChecks.Add(1); return nil }
						f.ReserveCapacity = func(context.Context) error { capacity.Add(1); return nil }
						frontend = *f
					}, func(target *servicestream.HTTPTarget) { application = *target })

					// keep the existing fixture's actual frontend, policy, token and
					// inline/proxy target. only its visitor TLS driver needs a wildcard
					// certificate so sibling rejection cannot be certificate rejection.
					transport := client.Transport.(*http.Transport)
					transport.TLSClientConfig = transport.TLSClientConfig.Clone()
					transport.TLSClientConfig.RootCAs = roots
					transport.TLSClientConfig.ServerName = test.sni
					transport.TLSClientConfig.MinVersion = tls.VersionTLS13
					transport.MaxConnsPerHost = 1
					hellos := make(chan string, 4)
					dials := serviceHTTPSNIVisitorDriver(t, transport, certificate, frontend, application, hellos)
					client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
					request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://"+hostname+"/sni", nil)
					if err != nil {
						t.Fatal(err)
					}
					request.Host = test.host
					if test.credential == "valid" {
						request.Header.Set(httpaccess.VisitorTokenHeader, token.Reveal())
					} else if test.credential != "" {
						request.Header.Set(httpaccess.VisitorTokenHeader, test.credential)
					}
					response, err := client.Do(request)
					if err != nil {
						t.Fatal("real TLS HTTP request failed before its service decision", err)
					}
					payload, readErr := io.ReadAll(response.Body)
					readErr = errors.Join(readErr, response.Body.Close())
					if readErr != nil {
						t.Fatal("read and close service response", readErr)
					}
					protocol := 1
					if h2 {
						protocol = 2
					}
					if response.ProtoMajor != protocol || response.TLS == nil || response.TLS.Version != tls.VersionTLS13 ||
						len(response.TLS.VerifiedChains) == 0 || transport.TLSClientConfig.InsecureSkipVerify {
						t.Fatal("SNI contrast lost verified TLS 1.3 or its selected HTTP protocol", response.Proto)
					}
					if got := serviceHTTPAwait(t, hellos); got != test.sni || dials.Load() != 1 {
						t.Error("visitor did not send its exact original SNI on one TLS connection", got, dials.Load())
					}
					if response.StatusCode != test.status {
						t.Errorf("service HTTP status=%d, want %d", response.StatusCode, test.status)
					}
					if test.target == 1 {
						if string(payload) != body {
							t.Error("authorized SNI did not receive the exact application response")
						}
						if response.StatusCode == http.StatusOK {
							serviceHTTPAwait(t, budget.Completed())
						}
					} else {
						select {
						case <-budget.Completed():
							t.Error("rejected SNI, authority or permission spent the application budget")
						default:
						}
					}
					if targets.Load() != int32(test.target) || ownerChecks.Load() != int32(test.owner) || capacity.Load() != int32(test.target) {
						t.Error("SNI, authority or access gate changed exact target/owner/capacity work", targets.Load(), ownerChecks.Load(), capacity.Load())
					}
				})
			}
		}
	}
}

// serviceHTTPSNIVisitorDriver changes only the existing fixture's TLS socket
// driver. every connection still calls its actual HTTP.Forward and captured target.
func serviceHTTPSNIVisitorDriver(t *testing.T, transport *http.Transport, certificate tls.Certificate, frontend HTTP, target servicestream.HTTPTarget, hellos chan<- string) *atomic.Int32 {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	type visitor struct {
		client, raw net.Conn
		done        chan error
	}
	var mu sync.Mutex
	var visitors []visitor
	var dials atomic.Int32
	closed := false
	transport.DialContext = func(call context.Context, _, _ string) (net.Conn, error) {
		mu.Lock()
		defer mu.Unlock()
		if closed {
			return nil, net.ErrClosed
		}
		if err := call.Err(); err != nil {
			return nil, err
		}
		client, raw := net.Pipe()
		if err := raw.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
			return nil, errors.Join(err, client.Close(), raw.Close())
		}
		server := tls.Server(raw, &tls.Config{
			Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS13,
			NextProtos: []string{"h2", "http/1.1"},
			GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
				select {
				case hellos <- hello.ServerName:
					return nil, nil
				default:
					return nil, errors.New("SNI fixture received unexpected additional ClientHello")
				}
			},
		})
		done := make(chan error, 1)
		visitors = append(visitors, visitor{client, raw, done})
		dials.Add(1)
		go func() {
			err := frontend.Forward(ctx, server, target)
			done <- errors.Join(err, server.Close())
		}()
		return client, nil
	}
	t.Cleanup(func() {
		mu.Lock()
		closed = true
		owned := append([]visitor(nil), visitors...)
		mu.Unlock()
		cancel()
		for _, visitor := range owned {
			if err := errors.Join(visitor.client.Close(), visitor.raw.Close()); err != nil {
				t.Error("close SNI fixture sockets", err)
			}
		}
		transport.CloseIdleConnections()
		for _, visitor := range owned {
			select {
			case err := <-visitor.done:
				// inspect every joined cause; cancellation alone must not hide
				// an independent forwarding or physical-cleanup failure.
				if !httpAdmissionRoutineError(err) {
					t.Error("join SNI frontend", err)
				}
			case <-time.After(5 * time.Second):
				t.Error("SNI frontend did not join within the existing HTTP fixture bound")
			}
		}
	})
	return &dials
}

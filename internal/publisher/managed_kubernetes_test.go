package publisher_test

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/publisher"
)

const kubeHostname = "cluster.production.storefront.example.test"

func kubeFrontend(t *testing.T, target, targetName string, targetRoots *x509.CertPool, public bool, revoked *atomic.Bool, limits publisher.KubernetesLimits, expires ...time.Time) (string, *http.Client, managedTLSFixture) {
	t.Helper()
	certificates := managedCertificates(t)
	check := func(context.Context) (publisher.ManagedVisitorDecision, error) {
		until := time.Now().Add(300 * time.Millisecond)
		if len(expires) != 0 {
			until = expires[0]
		}
		return publisher.ManagedVisitorDecision{Allowed: !revoked.Load(), ValidUntil: until}, nil
	}
	var auth publisher.ManagedVisitorAuthentication = publisher.ConnectorVisitor{Check: check}
	if public {
		auth = publisher.CertificateVisitor{Check: func(ctx context.Context, _ *x509.Certificate) (publisher.ManagedVisitorDecision, error) {
			return check(ctx)
		}}
	}
	budget, err := publisher.NewManagedHTTPRequestLimits(nil)
	if err != nil {
		t.Fatal(err)
	}
	stream := publisher.ManagedStream{Protocol: config.ProtocolKubernetes, Public: public, Hostname: kubeHostname, Target: target, TargetTLS: &tls.Config{ServerName: targetName, RootCAs: targetRoots}, TLS: &tls.Config{Certificates: []tls.Certificate{certificates.server}}, Visitor: auth, HTTPRequests: budget, Kubernetes: limits}
	address := managedPublisherListener(t, stream)
	verification := &tls.Config{ServerName: kubeHostname, RootCAs: certificates.roots}
	if public {
		verification.Certificates = []tls.Certificate{certificates.client}
	}
	transport := &http.Transport{TLSClientConfig: verification, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", address)
	}}
	t.Cleanup(transport.CloseIdleConnections)
	return address, &http.Client{Transport: transport}, certificates
}

func TestKubernetesDecisionExpiryClosesWatchBothAccessPaths(t *testing.T) {
	for _, public := range []bool{false, true} {
		t.Run(fmt.Sprintf("public=%v", public), func(t *testing.T) {
			var revoked atomic.Bool
			target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = io.WriteString(w, "ready\n")
				_ = http.NewResponseController(w).Flush()
				<-r.Context().Done()
			}))
			defer target.Close()
			roots := x509.NewCertPool()
			roots.AddCert(target.Certificate())
			_, client, _ := kubeFrontend(t, target.Listener.Addr().String(), target.Certificate().DNSNames[0], roots, public, &revoked, publisher.KubernetesLimits{}, time.Now().Add(500*time.Millisecond))
			request, _ := http.NewRequestWithContext(t.Context(), "GET", "https://"+kubeHostname+"/api/v1/pods?watch=true", nil)
			response, err := client.Do(request)
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			if line, err := bufio.NewReader(response.Body).ReadString('\n'); err != nil || line != "ready\n" {
				t.Fatal("watch did not start before expiry", err)
			}
			done := make(chan struct{})
			go func() { _, _ = io.Copy(io.Discard, response.Body); close(done) }()
			select {
			case <-done:
			case <-time.After(2 * time.Second):
				t.Fatal("expired decision left an active watch")
			}
		})
	}
}

func TestKubernetesWatchAndUpgradesRevokeBothAccessPaths(t *testing.T) {
	for _, public := range []bool{false, true} {
		t.Run(fmt.Sprintf("public=%v", public), func(t *testing.T) {
			var revoked atomic.Bool
			target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Authorization") != "Bearer cluster-only" || r.Header.Get("Tnl-Access-Token") != "" || r.Header.Get("Cookie") != "" {
					http.Error(w, "credential boundary changed", http.StatusUnauthorized)
					return
				}
				if r.Header.Get("Upgrade") != "" {
					conn, rw, err := http.NewResponseController(w).Hijack()
					if err != nil {
						return
					}
					defer conn.Close()
					fmt.Fprintf(rw, "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: %s\r\n\r\n", r.Header.Get("Upgrade"))
					if rw.Flush() != nil {
						return
					}
					_, _ = io.Copy(conn, rw)
					return
				}
				if r.URL.Query().Get("watch") == "true" {
					w.Header().Set("Content-Type", "application/json")
					_, _ = io.WriteString(w, "{\"type\":\"ADDED\"}\n")
					_ = http.NewResponseController(w).Flush()
					<-r.Context().Done()
					return
				}
				w.WriteHeader(204)
			}))
			defer target.Close()
			roots := x509.NewCertPool()
			roots.AddCert(target.Certificate())
			address, client, certificates := kubeFrontend(t, target.Listener.Addr().String(), target.Certificate().DNSNames[0], roots, public, &revoked, publisher.KubernetesLimits{})
			request, _ := http.NewRequestWithContext(t.Context(), "GET", "https://"+kubeHostname+"/api/v1/pods?watch=true", nil)
			request.Header.Set("Authorization", "Bearer cluster-only")
			request.Header.Set("Tnl-Access-Token", "strip-this")
			request.Header.Set("Cookie", "tnl-browser=strip-this")
			response, err := client.Do(request)
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			line, err := bufio.NewReader(response.Body).ReadString('\n')
			if err != nil || !strings.Contains(line, "ADDED") {
				t.Fatal("watch did not stream")
			}
			var upgrades []net.Conn
			for _, protocol := range []string{"websocket", "SPDY/3.1"} {
				verification := &tls.Config{ServerName: kubeHostname, RootCAs: certificates.roots}
				if public {
					verification.Certificates = []tls.Certificate{certificates.client}
				}
				conn, err := tls.Dial("tcp", address, verification)
				if err != nil {
					t.Fatal(err)
				}
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
				fmt.Fprintf(conn, "GET /api/v1/namespaces/default/pods/pod/exec?command=not-observed HTTP/1.1\r\nHost: %s\r\nAuthorization: Bearer cluster-only\r\nConnection: Upgrade\r\nUpgrade: %s\r\n\r\n", kubeHostname, protocol)
				reader := bufio.NewReader(conn)
				response, err := http.ReadResponse(reader, nil)
				if err != nil || response.StatusCode != 101 {
					t.Fatal("upgrade did not succeed", err)
				}
				if _, err := io.WriteString(conn, "opaque"); err != nil {
					t.Fatal(err)
				}
				var echo [6]byte
				if _, err := io.ReadFull(reader, echo[:]); err != nil || string(echo[:]) != "opaque" {
					t.Fatal("upgraded bytes changed", err)
				}
				upgrades = append(upgrades, conn)
			}
			revoked.Store(true)
			watchDone := make(chan error, 1)
			go func() { _, err := io.Copy(io.Discard, response.Body); watchDone <- err }()
			select {
			case <-watchDone:
			case <-time.After(2 * time.Second):
				t.Fatal("revoked watch remained active")
			}
			for _, conn := range upgrades {
				var one [1]byte
				if _, err := conn.Read(one[:]); err == nil {
					t.Fatal("revoked upgrade remained active")
				}
			}
		})
	}
}

func TestKubernetesRejectsTargetTrustAndBoundsLongWatch(t *testing.T) {
	var revoked atomic.Bool
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		_ = http.NewResponseController(w).Flush()
		<-r.Context().Done()
	}))
	defer target.Close()
	roots := x509.NewCertPool()
	roots.AddCert(target.Certificate())
	_, client, _ := kubeFrontend(t, target.Listener.Addr().String(), target.Certificate().DNSNames[0], roots, false, &revoked, publisher.KubernetesLimits{StreamDuration: 150 * time.Millisecond})
	request, _ := http.NewRequestWithContext(t.Context(), "GET", "https://"+kubeHostname+"/api/v1/pods?watch=true", nil)
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { _, _ = io.Copy(io.Discard, response.Body); response.Body.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("long watch limit was not applied")
	}
	_, untrusted, _ := kubeFrontend(t, target.Listener.Addr().String(), "wrong.example.test", roots, false, &revoked, publisher.KubernetesLimits{})
	response, err = untrusted.Get("https://" + kubeHostname + "/api")
	if err == nil {
		defer response.Body.Close()
		if response.StatusCode != 502 {
			t.Fatal("cluster hostname mismatch was not rejected")
		}
	}
}

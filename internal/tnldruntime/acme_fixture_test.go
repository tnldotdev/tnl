package tnldruntime

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/miekg/dns"
)

type integrationCertificate struct {
	certificateFile string
	privateKeyFile  string
}

type splitACMERoundTripFunc func(*http.Request) (*http.Response, error)

func (f splitACMERoundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func newIntegrationTestCA(t *testing.T) *testCertificateAuthority {
	t.Helper()
	return newTestCertificateAuthority(t)
}

func (c *testCertificateAuthority) issueServer(t *testing.T, hostname string) integrationCertificate {
	t.Helper()
	material := c.issue(t, hostname)
	directory := t.TempDir()
	certificate := integrationCertificate{filepath.Join(directory, "certificate.pem"), filepath.Join(directory, "private-key.pem")}
	if err := errors.Join(
		os.WriteFile(certificate.certificateFile, material.certificatePEM, 0o600),
		os.WriteFile(certificate.privateKeyFile, material.privateKeyPEM, 0o600),
	); err != nil {
		t.Fatal(err)
	}
	return certificate
}

type integrationPebble struct {
	directoryURL string
	httpClient   *http.Client
	roots        *x509.CertPool
	apiRootPEM   []byte
	rootPEM      []byte
	logPath      string
}

func startIntegrationPebble(t *testing.T, validationPort int, dnsAddress string) integrationPebble {
	t.Helper()
	pebblePath, err := exec.LookPath("pebble")
	if err != nil {
		t.Fatal("Pebble is required; run mise install")
	}
	apiAddress, managementAddress := unusedTCPAddress(t), unusedTCPAddress(t)
	apiCA := newIntegrationTestCA(t)
	apiCertificate := apiCA.issueServer(t, "localhost")
	configuration := map[string]any{"pebble": map[string]any{
		"listenAddress": apiAddress, "managementListenAddress": managementAddress,
		"certificate": apiCertificate.certificateFile, "privateKey": apiCertificate.privateKeyFile,
		"httpPort": integrationPort(t, unusedTCPAddress(t)), "tlsPort": validationPort,
		"ocspResponderURL": "", "externalAccountBindingRequired": false,
		"domainBlocklist": []string{}, "retryAfter": map[string]int{"authz": 0, "order": 0},
		"keyAlgorithm": "ecdsa", "profiles": map[string]any{
			"default":   map[string]any{"description": "integration", "validityPeriod": 3600},
			"tlsserver": map[string]any{"description": "tnl visitor TLS", "validityPeriod": 3600},
		},
	}}
	encoded, err := json.Marshal(configuration)
	if err != nil {
		t.Fatal(err)
	}
	configurationFile := filepath.Join(t.TempDir(), "pebble.json")
	if err := os.WriteFile(configurationFile, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(t.TempDir(), "pebble.log")
	logFile, err := os.Create(logPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = logFile.Close() })
	command := exec.Command(pebblePath, "-config", configurationFile, "-strict=false", "-dnsserver", dnsAddress)
	command.Env = append(os.Environ(), "PEBBLE_AUTHZREUSE=0", "PEBBLE_VA_ALWAYS_VALID=0", "PEBBLE_VA_NOSLEEP=1", "PEBBLE_WFE_NONCEREJECT=0")
	command.Stdout, command.Stderr = logFile, logFile
	owner, err := startOwnedCommand(command, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := owner.shutdown(5*time.Second, 5*time.Second); err != nil {
			t.Errorf("Pebble shutdown: %v", err)
		}
	})
	_, apiPort, err := net.SplitHostPort(apiAddress)
	if err != nil {
		t.Fatal(err)
	}
	_, managementPort, err := net.SplitHostPort(managementAddress)
	if err != nil {
		t.Fatal(err)
	}
	directoryURL := "https://localhost:" + apiPort + "/dir"
	rootURL := "https://localhost:" + managementPort + "/roots/0"
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: apiCA.roots, MinVersion: tls.VersionTLS12}}
	httpClient := &http.Client{Transport: transport, Timeout: time.Second}
	t.Cleanup(transport.CloseIdleConnections)
	var roots *x509.CertPool
	var rootPEM []byte
	waitForIntegrationCondition(t, 10*time.Second, func(ctx context.Context) (bool, error) {
		select {
		case <-owner.done:
			output, _ := os.ReadFile(logPath)
			t.Fatalf("Pebble exited during startup: %v\n%s", owner.result(), output)
		default:
		}
		var ready bool
		roots, rootPEM, ready = integrationPebbleRoots(ctx, httpClient, directoryURL, rootURL)
		if !ready {
			output, _ := os.ReadFile(logPath)
			return false, fmt.Errorf("Pebble not ready\n%s", output)
		}
		return true, nil
	})
	return integrationPebble{directoryURL: directoryURL, httpClient: httpClient, roots: roots,
		apiRootPEM: append([]byte(nil), apiCA.certificatePEM...), rootPEM: rootPEM, logPath: logPath}
}

func integrationPebbleRoots(ctx context.Context, client *http.Client, directoryURL, rootURL string) (*x509.CertPool, []byte, bool) {
	directory, err := integrationGET(ctx, client, directoryURL)
	if err != nil {
		return nil, nil, false
	}
	_, readErr := io.Copy(io.Discard, io.LimitReader(directory.Body, 64<<10))
	_ = directory.Body.Close()
	if readErr != nil || directory.StatusCode != http.StatusOK {
		return nil, nil, false
	}
	response, err := integrationGET(ctx, client, rootURL)
	if err != nil {
		return nil, nil, false
	}
	rootPEM, readErr := io.ReadAll(io.LimitReader(response.Body, 64<<10))
	_ = response.Body.Close()
	if readErr != nil || response.StatusCode != http.StatusOK {
		return nil, nil, false
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(rootPEM) {
		return nil, nil, false
	}
	return roots, rootPEM, true
}

func startIntegrationDNS(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	handler := dns.HandlerFunc(func(response dns.ResponseWriter, request *dns.Msg) {
		message := new(dns.Msg)
		message.SetReply(request)
		message.Authoritative = true
		for _, question := range request.Question {
			if question.Qtype == dns.TypeA {
				message.Answer = append(message.Answer, &dns.A{
					Hdr: dns.RR_Header{Name: question.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 1}, A: net.IPv4(127, 0, 0, 1),
				})
			}
		}
		_ = response.WriteMsg(message)
	})
	startOwnedDNSServer(t, &dns.Server{Listener: listener, Handler: handler})
	return listener.Addr().String()
}

func startOwnedDNSServer(t *testing.T, server *dns.Server) {
	t.Helper()
	started := make(chan struct{})
	server.NotifyStartedFunc = func() { close(started) }
	done := make(chan struct{})
	var serveErr error
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		select {
		case <-started:
			if err := server.ShutdownContext(ctx); err != nil {
				t.Errorf("DNS shutdown: %v", err)
			}
		case <-done:
		case <-ctx.Done():
			t.Error("DNS server never started")
		}
		if err := waitForDoneWithin(done, time.Second); err != nil {
			t.Errorf("DNS output join: %v", err)
		} else if serveErr != nil {
			t.Errorf("DNS server: %v", serveErr)
		}
	})
	go func() { serveErr = server.ActivateAndServe(); close(done) }()
	select {
	case <-started:
	case <-done:
		t.Fatalf("DNS startup: %v", serveErr)
	case <-time.After(time.Second):
		t.Fatal("DNS server did not start")
	}
}

func standaloneTestACMEServer(t *testing.T) *httptest.Server {
	t.Helper()
	var server *httptest.Server
	server = httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Replay-Nonce", "test-nonce")
		switch request.URL.Path {
		case "/directory":
			_ = json.NewEncoder(response).Encode(map[string]any{
				"newNonce": server.URL + "/nonce", "newAccount": server.URL + "/account",
				"newOrder": server.URL + "/order", "meta": map[string]any{"termsOfService": server.URL + "/terms"},
			})
		case "/nonce":
			response.WriteHeader(http.StatusNoContent)
		case "/account":
			response.Header().Set("Location", server.URL+"/account/1")
			response.WriteHeader(http.StatusCreated)
			_, _ = io.WriteString(response, `{"status":"valid","contact":["mailto:operator@example.test"]}`)
		case "/account/1":
			_, _ = io.WriteString(response, `{"status":"valid","contact":["mailto:operator@example.test"]}`)
		default:
			http.NotFound(response, request)
		}
	}))
	cleanupIntegrationHTTPServer(t, server, nil)
	return server
}

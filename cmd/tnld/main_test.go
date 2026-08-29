package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/0xcadams/tnl/internal/config"
	"github.com/0xcadams/tnl/internal/coreclient"
	"github.com/0xcadams/tnl/internal/credentials"
	"github.com/0xcadams/tnl/internal/observability"
	"github.com/0xcadams/tnl/internal/state"
	"github.com/0xcadams/tnl/internal/worker"
	"github.com/0xcadams/tnl/internal/workersession"
	"github.com/0xcadams/tnl/pkg/protocol/corev1"
	"tailscale.com/tailcfg"
)

func TestStandaloneControlLifecycle(t *testing.T) {
	directory := t.TempDir()
	certificateFile, keyFile, roots := writeControlCertificate(t, directory)
	relayFile := filepath.Join(directory, "relay.json")
	relayData, err := json.Marshal(tailcfg.DERPMap{Regions: map[int]*tailcfg.DERPRegion{1: {
		RegionID: 1, RegionCode: "test", Nodes: []*tailcfg.DERPNode{{
			Name: "test", RegionID: 1, HostName: "derp.invalid", DERPPort: 443,
		}},
	}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(relayFile, relayData, 0o600); err != nil {
		t.Fatal(err)
	}
	bootstrap, err := credentials.NewBootstrapToken()
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.TNLD{
		Mode: config.TNLDModeStandalone, StateDir: filepath.Join(directory, "state"),
		ControlListen: "127.0.0.1:0", ControlCertFile: certificateFile, ControlKeyFile: keyFile,
		BootstrapToken: bootstrap.String(), RelayMapFile: relayFile, RelayProfile: "test",
		WorkerCapacity: 10, WorkerStreamLimit: 10, PublicConnLimit: 10, RouteConnLimit: 5, DrainTimeout: time.Second,
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	db, err := state.Open(context.Background(), cfg.StateDir)
	if err != nil {
		t.Fatal(err)
	}
	running := &daemon{db: db}
	t.Cleanup(func() { _ = running.shutdown(time.Second) })
	controlDone, _, err := running.startCore(context.Background(), cfg, observability.New("standalone"))
	if err != nil {
		t.Fatal(err)
	}
	httpClient := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
		RootCAs: roots, MinVersion: tls.VersionTLS13,
	}}, Timeout: 5 * time.Second}
	baseURL := "https://" + running.controlListener.Addr().String()
	anonymous, err := coreclient.New(baseURL, httpClient, "")
	if err != nil {
		t.Fatal(err)
	}
	issued, err := anonymous.Exchange(context.Background(), bootstrap)
	if err != nil {
		t.Fatal(err)
	}
	client, err := coreclient.New(baseURL, httpClient, credentials.AccessToken(issued.AccessToken))
	if err != nil {
		t.Fatal(err)
	}
	capabilities, err := client.Capabilities(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if capabilities.Transport.RelayProfile != "test" || capabilities.Transport.Type != corev1.Tailcat {
		t.Fatalf("capabilities = %#v", capabilities)
	}
	routeToken, _, _, err := credentials.NewRouteToken()
	if err != nil {
		t.Fatal(err)
	}
	setup, err := client.CreateRoute(context.Background(), corev1.CreateRouteRequest{
		Hostname: "route.example", DisplayTarget: "http://127.0.0.1:3000", RouteToken: routeToken.String(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if setup.Route.Generation != 1 || setup.LeaseToken == "" {
		t.Fatalf("setup = %#v", setup)
	}
	if err := client.DeleteRoute(context.Background(), setup.Route.Id); err != nil {
		t.Fatal(err)
	}
	if err := running.shutdown(time.Second); err != nil {
		t.Fatal(err)
	}
	if err := <-controlDone; err != nil {
		t.Fatal(err)
	}
	running = new(daemon)
}

func TestWorkerReconnectsWithFreshOwner(t *testing.T) {
	previousMin, previousMax := workerReconnectMin, workerReconnectMax
	workerReconnectMin, workerReconnectMax = time.Millisecond, 2*time.Millisecond
	t.Cleanup(func() { workerReconnectMin, workerReconnectMax = previousMin, previousMax })

	token, verifier, err := credentials.NewWorkerToken()
	if err != nil {
		t.Fatal(err)
	}
	registry := &reconnectRegistry{added: make(chan struct{}, 2)}
	hub, err := workersession.NewHub(workersession.HubConfig{
		Tokens: []credentials.WorkerVerifier{verifier}, Registry: registry,
	})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(hub)
	defer server.Close()
	defer hub.Close()

	directory := t.TempDir()
	relayFile := filepath.Join(directory, "relay.json")
	relayData, err := json.Marshal(tailcfg.DERPMap{Regions: map[int]*tailcfg.DERPRegion{1: {
		RegionID: 1, RegionCode: "test", Nodes: []*tailcfg.DERPNode{{
			Name: "test", RegionID: 1, HostName: "derp.invalid", DERPPort: 443,
		}},
	}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(relayFile, relayData, 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done, err := startWorker(ctx, config.TNLD{
		Mode: config.TNLDModeWorker, WorkerURL: "ws" + strings.TrimPrefix(server.URL, "http"),
		WorkerToken: token.String(), WorkerCapacity: 2, WorkerStreamLimit: 10,
		RelayMapFile: relayFile, DrainTimeout: time.Second,
	}, observability.New("worker"))
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	for range 2 {
		select {
		case <-registry.added:
		case <-time.After(5 * time.Second):
			cancel()
			t.Fatal("worker did not reconnect")
		}
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("worker did not stop")
	}
}

type reconnectRegistry struct {
	connections atomic.Int32
	added       chan struct{}
}

func (r *reconnectRegistry) AddOwner(_ string, owner worker.RouteOwner) error {
	connection := r.connections.Add(1)
	r.added <- struct{}{}
	if connection == 1 {
		go owner.Close()
	}
	return nil
}

func (*reconnectRegistry) DrainOwner(context.Context, string) error { return nil }

func (*reconnectRegistry) RemoveOwner(string) {}

func writeControlCertificate(t *testing.T, directory string) (string, string, *x509.CertPool) {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"},
		DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	certificate, err := x509.CreateCertificate(rand.Reader, template, template, privateKey.Public(), privateKey)
	if err != nil {
		t.Fatal(err)
	}
	encodedKey, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	certificateFile := filepath.Join(directory, "control.crt")
	keyFile := filepath.Join(directory, "control.key")
	if err := os.WriteFile(certificateFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: encodedKey}), 0o600); err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(certificate)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(leaf)
	return certificateFile, keyFile, roots
}

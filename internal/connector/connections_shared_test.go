package connector

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"flag"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	clientproject "github.com/tnldotdev/tnl/internal/client/project"
	"github.com/tnldotdev/tnl/internal/config"
	connectorruntime "github.com/tnldotdev/tnl/internal/connector/runtime"
	"github.com/tnldotdev/tnl/internal/testutil"
	"github.com/tnldotdev/tnl/internal/testutil/connectorfixture"
	"github.com/tnldotdev/tnl/internal/transport/streamcopy"
	"github.com/tnldotdev/tnl/internal/transport/targettransport"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

var sharedOwnerFixture = flag.String("tnl-shared-owner-fixture", "", "private local shared-owner fixture path")

type sharedOwnerInput struct {
	Scope     connectorruntime.Context
	Directory string
	ParentPID int
}

// re-exec gives the real native TLS verifier a fresh process and fixture root,
// without changing the host trust store or the process-global system root cache.
func TestConnectionSharedOwnerSubprocess(t *testing.T) {
	if *sharedOwnerFixture == "" {
		t.Skip("requires the shared-owner fixture")
	}
	data, err := os.ReadFile(*sharedOwnerFixture)
	if err != nil {
		t.Fatal(err)
	}
	var input sharedOwnerInput
	if err := json.Unmarshal(data, &input); err != nil {
		t.Fatal(err)
	}
	b := &nativeConnectionBackend{scope: input.Scope, assertion: "first", parentPID: input.ParentPID, project: projectConfiguration{Project: clientproject.Project{Config: config.TNL{Services: config.Services{"api": {Protocol: new("http")}, "db": {Protocol: new("postgres")}}, Workloads: map[string]config.Workload{"worker": {Provider: "vercel", Services: []string{"api", "db"}}}}}}}
	if err := connectorruntime.Serve(t.Context(), input.Scope, input.Directory, "/fixture/tnl", b, os.Stdout); err != nil {
		t.Fatal(err)
	}
}

func TestIntegrationConnectionSharedOwnerStalledSibling(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	databaseURL := testutil.NewDisposablePostgresDatabaseURL(t, "shared_owner")
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	caPublic, caKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, ca, ca, caPublic, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	public, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), DNSNames: []string{"localhost", "api.example.test", "db.example.test"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err = x509.CreateCertificate(rand.Reader, leaf, ca, public, caKey)
	if err != nil {
		t.Fatal(err)
	}
	tlsServer := &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(caPEM)
	application := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "http sibling is live") }))
	application.TLS = tlsServer.Clone()
	application.StartTLS()
	defer application.Close()
	dbListener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var dbWorkers sync.WaitGroup
	dbStop := context.AfterFunc(ctx, func() { _ = dbListener.Close() })
	defer func() { dbStop(); _ = dbListener.Close(); cancel(); dbWorkers.Wait() }()
	backend, _ := url.Parse(databaseURL)
	dbWorkers.Go(func() {
		for {
			local, err := dbListener.Accept()
			if err != nil {
				return
			}
			dbWorkers.Go(func() {
				defer local.Close()
				stop := context.AfterFunc(ctx, func() { _ = local.Close() })
				defer stop()
				var request [8]byte
				if _, err := io.ReadFull(local, request[:]); err != nil || request != targettransport.PostgresSSLRequest {
					return
				}
				if _, err := local.Write([]byte{'S'}); err != nil {
					return
				}
				secure := tls.Server(local, tlsServer.Clone())
				if err := secure.HandshakeContext(ctx); err != nil {
					return
				}
				upstream, err := (&net.Dialer{}).DialContext(ctx, "tcp", backend.Host)
				if err != nil {
					return
				}
				defer upstream.Close()
				_, _ = streamcopy.Copy(secure, upstream)
			})
		}
	})
	team, id := "tm_"+strings.Repeat("t", 22), "wls_"+strings.Repeat("s", 22)
	ids := []string{"svc_" + strings.Repeat("a", 22), "svc_" + strings.Repeat("b", 22)}
	serviceNames := []string{"api", "db"}
	protocols := []string{"http", "postgres"}
	session := authorityv1.WorkloadSession{Id: id, Credential: "wlc_" + strings.Repeat("x", 43), TeamId: team, ProjectKey: "project", Workload: "worker", Provider: controlv1.WorkloadVercel, Binding: strings.Repeat("a", 64), Subject: controlv1.VisitorSubject{Kind: "workload_session", WorkloadSessionId: &id}, ServiceIds: ids, ExpiresAt: now.Add(time.Hour), LeaseExpiresAt: now.Add(90 * time.Second), RenewAfter: now.Add(30 * time.Second)}
	assignments := map[string][]map[string]any{}
	trusts := map[string]controlv1.IngressTransportTrust{}
	for i, target := range []string{application.Listener.Addr().String(), dbListener.Addr().String()} {
		set, trust := connectorfixture.Ingress(t, ca, caKey, caPEM, ids[i], id, target)
		assignments[ids[i]] = set
		for key, value := range trust {
			trusts[key] = value
		}
	}
	entered, release := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	defer releaseOnce.Do(func() { close(release) })
	authority := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(r.URL.Path, "/identity"):
			_ = json.NewEncoder(w).Encode(authorityv1.WorkloadIdentity{Binding: session.Binding, Services: serviceNames, AssertionExpiresAt: now.Add(time.Minute)})
		case strings.HasSuffix(r.URL.Path, "/exchange"):
			_ = json.NewEncoder(w).Encode(session)
		case strings.HasSuffix(r.URL.Path, "/assertions"):
			_, _ = io.Copy(io.Discard, r.Body)
			close(entered)
			select {
			case <-release:
			case <-r.Context().Done():
			}
			w.WriteHeader(503)
			_, _ = io.WriteString(w, `{"status":503,"code":"unavailable","detail":"fixture stall"}`)
		case r.URL.Path == "/v1/workload/services":
			services := []any{}
			for i, name := range serviceNames {
				services = append(services, map[string]any{"id": ids[i], "service": name, "protocol": protocols[i], "endpoint": controlv1.ServiceEndpoint{Hostname: name + ".example.test", Port: 15443 + i}})
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"services": services})
		case strings.HasSuffix(r.URL.Path, "/authorization"):
			parts := strings.Split(r.URL.Path, "/")
			_ = json.NewEncoder(w).Encode(controlv1.WorkloadServiceAuthorization{Subject: session.Subject, ServiceId: parts[len(parts)-2], ValidUntil: session.LeaseExpiresAt, PolicyRevision: 1})
		case strings.HasSuffix(r.URL.Path, "/run"):
			parts := strings.Split(r.URL.Path, "/")
			service := parts[len(parts)-2]
			i := 0
			if service == ids[1] {
				i = 1
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"service_id": service, "service_run_id": "srun_" + strings.Repeat("r", 22), "run_number": 1, "protocol": protocols[i], "trust_revision": 1, "expires_at": now.Add(time.Minute), "subject": session.Subject, "endpoint": controlv1.ServiceEndpoint{Hostname: serviceNames[i] + ".example.test", Port: 15443 + i}})
		case strings.HasSuffix(r.URL.Path, "/ingress-assignments"):
			parts := strings.Split(r.URL.Path, "/")
			_ = json.NewEncoder(w).Encode(map[string]any{"subject": session.Subject, "assignments": assignments[parts[len(parts)-2]]})
		case strings.HasSuffix(r.URL.Path, "/transport-trust"):
			parts := strings.Split(r.URL.Path, "/")
			_ = json.NewEncoder(w).Encode(trusts[parts[len(parts)-2]])
		case r.Method == http.MethodDelete:
			w.WriteHeader(204)
		default:
			t.Error("unexpected shared-owner request", r.URL.Path)
			w.WriteHeader(404)
		}
	}))
	authority.TLS = tlsServer.Clone()
	authority.StartTLS()
	defer authority.Close()
	directory, err := connectorruntime.NewDirectory(root)
	if err != nil {
		t.Fatal(err)
	}
	scope := connectorruntime.Context{Schema: 1, Directory: root, ConfigDigest: strings.Repeat("a", 64), Server: authority.URL, Audience: authority.URL, TeamID: team, ProjectKey: "project", SourceID: strings.Repeat("a", 64), WorktreeKey: "worktree", Workload: "worker", Services: serviceNames}
	input, _ := json.Marshal(sharedOwnerInput{Scope: scope, Directory: directory, ParentPID: os.Getpid()})
	path := filepath.Join(root, "fixture.json")
	if err := os.WriteFile(path, input, 0o600); err != nil {
		t.Fatal(err)
	}
	caPath := filepath.Join(root, "ca.pem")
	if err := os.WriteFile(caPath, caPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	command := exec.CommandContext(ctx, executable, "-test.run=^TestConnectionSharedOwnerSubprocess$", "-tnl-shared-owner-fixture="+path)
	command.Env = append(os.Environ(), "SSL_CERT_FILE="+caPath)
	command.Stderr = os.Stderr
	output, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { cancel(); _ = command.Wait() }()
	var status connectorruntime.Status
	if err := json.NewDecoder(output).Decode(&status); err != nil {
		t.Fatal(err)
	}
	request := connectorruntime.Request{Schema: 1, Directory: root, ConfigDigest: scope.ConfigDigest}
	prepared := map[string]connectorruntime.Prepared{}
	for _, name := range serviceNames {
		request.Service = name
		var value connectorruntime.Prepared
		if err := connectorruntime.Call(ctx, status.ConnectionHandle, "prepare", request, &value); err != nil {
			t.Fatal(name, err)
		}
		prepared[name] = value
	}
	dbConfig, err := pgx.ParseConfig(databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	dbConfig.Host, dbConfig.Port = prepared["db"].Connection.Host, uint16(prepared["db"].Connection.Port)
	dbConfig.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, ServerName: "db.example.test"}
	dbConfig.Fallbacks = nil
	database, err := pgx.ConnectConfig(ctx, dbConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close(context.Background())
	var one int
	if err := database.QueryRow(ctx, "select 1").Scan(&one); err != nil || one != 1 {
		t.Fatal("real PostgreSQL through shared owner", err)
	}
	stalled := request
	stalled.Service, stalled.Assertion = "db", "stall"
	done := make(chan error, 1)
	go func() {
		done <- connectorruntime.Call(ctx, status.ConnectionHandle, "prepare", stalled, new(connectorruntime.Prepared))
	}()
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal("sibling did not enter its network stall")
	}
	request.Service = "api"
	bounded, stop := context.WithTimeout(ctx, time.Second)
	var warm connectorruntime.Prepared
	err = connectorruntime.Call(bounded, status.ConnectionHandle, "prepared", request, &warm)
	stop()
	if err != nil {
		t.Fatal("prepared HTTP sibling blocked", err)
	}
	if warm.Connection.TransportID != prepared["api"].Connection.TransportID {
		t.Fatal("prepared read restarted its transport")
	}
	request.Assertion = "first"
	bounded, stop = context.WithTimeout(ctx, time.Second)
	err = connectorruntime.Call(bounded, status.ConnectionHandle, "prepare", request, &warm)
	stop()
	if err != nil || warm.Verification == nil {
		t.Fatal("verified warm preparation joined the stalled assertion", err)
	}
	request.Assertion = ""
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: "api.example.test"}, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", net.JoinHostPort(warm.Connection.Host, strconv.Itoa(warm.Connection.Port)))
	}}
	defer transport.CloseIdleConnections()
	httpRequest, _ := http.NewRequestWithContext(ctx, "GET", warm.Connection.URL, nil)
	response, err := (&http.Client{Transport: transport}).Do(httpRequest)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(response.Body)
	response.Body.Close()
	if string(body) != "http sibling is live" {
		t.Fatal("HTTP sibling did not forward real traffic")
	}
	releaseOnce.Do(func() { close(release) })
	if err := <-done; err == nil {
		t.Fatal("stalled assertion failure was hidden")
	}
	if err := database.QueryRow(ctx, "select 1").Scan(&one); err != nil {
		t.Fatal("failed sibling assertion canceled an existing database stream", err)
	}
	if err := connectorruntime.Call(ctx, status.ConnectionHandle, "stop", request, nil); err != nil {
		t.Fatal(err)
	}
	if err := command.Wait(); err != nil {
		t.Fatal(err)
	}
}

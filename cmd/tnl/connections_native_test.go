package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
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
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/connectionruntime"
	"github.com/tnldotdev/tnl/internal/opaqueid"
	"github.com/tnldotdev/tnl/internal/streamcopy"
	"github.com/tnldotdev/tnl/internal/targettransport"
	"github.com/tnldotdev/tnl/internal/testutil"
	"github.com/tnldotdev/tnl/pkg/api/authorityv1"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
	credentialv1 "k8s.io/client-go/pkg/apis/clientauthentication/v1"
)

// this runs the built native owner, real TLS with client authentication, and the
// built npm root in separate processes. no saved human state or network service
// outside these local fixtures participates.
func TestIntegrationConnectionNativeSDKHTTP(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	runConnectionNativeSDK(t, "", "http")
}

func TestIntegrationConnectionNativeSDKKubernetes(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	runConnectionNativeSDK(t, "", "kubernetes")
}

func TestIntegrationConnectionDrizzleKit(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	runConnectionNativeSDK(t, testutil.NewDisposablePostgresDatabaseURL(t, "connection_drizzle"), "postgres")
}

func runConnectionNativeSDK(t *testing.T, databaseURL, protocol string) {
	t.Helper()
	serviceName := "api"
	if databaseURL != "" {
		serviceName = "database"
	}
	if protocol == "kubernetes" {
		serviceName = "cluster"
	}
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	caPublic, caKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca := &x509.Certificate{Subject: pkix.Name{CommonName: "connection fixture root"}, SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(2 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, caPublic, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(caPEM)
	serverPublic, serverKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serverLeaf := &x509.Certificate{SerialNumber: big.NewInt(2), NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), DNSNames: []string{"localhost"}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	serverDER, err := x509.CreateCertificate(rand.Reader, serverLeaf, ca, serverPublic, caKey)
	if err != nil {
		t.Fatal(err)
	}
	pair := tls.Certificate{Certificate: [][]byte{serverDER, caDER}, PrivateKey: serverKey}
	var visits atomic.Int32
	application := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if len(r.TLS.PeerCertificates) == 0 {
			t.Error("no workload client certificate")
			return
		}
		if r.URL.Path == "/hang" {
			<-r.Context().Done()
			return
		}
		data, _ := io.ReadAll(r.Body)
		if r.Method != "POST" || string(data) != "streamed-body" || r.Header.Get("Authorization") != "Bearer application-only" {
			t.Error("fetch changed the application request")
		}
		visits.Add(1)
		w.Header().Set("X-Certificate-Serial", r.TLS.PeerCertificates[0].SerialNumber.String())
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(201)
		_, _ = w.Write(data)
	}))
	application.TLS = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{pair}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots}
	application.StartTLS()
	defer application.Close()
	_, portString, _ := net.SplitHostPort(application.Listener.Addr().String())
	port, _ := strconv.Atoi(portString)
	if databaseURL != "" {
		listener, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer listener.Close()
		port = listener.Addr().(*net.TCPAddr).Port
		backend, err := url.Parse(databaseURL)
		if err != nil {
			t.Fatal(err)
		}
		go func() {
			for {
				connection, err := listener.Accept()
				if err != nil {
					return
				}
				go func() {
					defer connection.Close()
					_ = connection.SetDeadline(time.Now().Add(20 * time.Second))
					var sslRequest [8]byte
					if _, err := io.ReadFull(connection, sslRequest[:]); err != nil {
						return
					}
					if sslRequest != targettransport.PostgresSSLRequest {
						return
					}
					if _, err := connection.Write([]byte{'S'}); err != nil {
						return
					}
					secured := tls.Server(connection, application.TLS)
					if err := secured.HandshakeContext(t.Context()); err != nil {
						return
					}
					provider, err := net.DialTimeout("tcp", backend.Host, 3*time.Second)
					if err != nil {
						return
					}
					defer provider.Close()
					_, _ = streamcopy.Copy(secured, provider)
				}()
			}
		}()
	}
	team, _ := opaqueid.New(opaqueid.TeamPrefix)
	service, _ := opaqueid.New(opaqueid.PrivateServicePrefix)
	sessionID, _ := opaqueid.New("wls_")
	var revoked atomic.Bool
	var certificateSerial atomic.Int64
	var current authorityv1.WorkloadSession
	var clientPublic ed25519.PublicKey
	var exchangeAttempts atomic.Int32
	var authorityMu sync.Mutex
	authority := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authorityMu.Lock()
		defer authorityMu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/v1/workload-sessions/github":
			var exchange authorityv1.GitHubWorkloadExchange
			if json.NewDecoder(r.Body).Decode(&exchange) != nil || exchange.Assertion != "fixture-assertion" {
				w.WriteHeader(400)
				return
			}
			public, err := base64.RawURLEncoding.DecodeString(exchange.PublicKey)
			if err != nil {
				w.WriteHeader(400)
				return
			}
			if current.Id == "" {
				clientPublic = ed25519.PublicKey(public)
				current = authorityv1.WorkloadSession{Id: sessionID, TeamId: team, ProjectKey: exchange.ProjectKey, Ci: exchange.Ci, Credential: "wlc_" + strings.Repeat("x", 43), ExpiresAt: time.Now().Add(time.Hour), LeaseExpiresAt: time.Now().Add(90 * time.Second), RenewAfter: time.Now().Add(30 * time.Second), ServiceIds: []string{service}, Subject: controlv1.VisitorSubject{Kind: "workload_session", WorkloadSessionId: &sessionID}}
			} else if !ed25519.PublicKey(public).Equal(clientPublic) {
				t.Error("exchange retried with another owner key")
				w.WriteHeader(403)
				return
			}
			if exchangeAttempts.Add(1) == 1 {
				connection, _, err := w.(http.Hijacker).Hijack()
				if err != nil {
					t.Error(err)
					return
				}
				_ = connection.Close()
				return
			}
			_ = json.NewEncoder(w).Encode(current)
		case r.URL.Path == "/v1/workload/services":
			_ = json.NewEncoder(w).Encode(map[string]any{"services": []any{map[string]any{"id": service, "service": serviceName, "protocol": protocol, "managed_tls": map[string]any{"hostname": "localhost", "port": port, "public": true}}}})
		case strings.HasSuffix(r.URL.Path, "/client-certificate"):
			var request controlv1.IssueWorkloadServiceClientCertificateJSONBody
			if json.NewDecoder(r.Body).Decode(&request) != nil {
				w.WriteHeader(400)
				return
			}
			csr, err := x509.ParseCertificateRequest(request.Csr)
			if err != nil || csr.CheckSignature() != nil || !csr.PublicKey.(ed25519.PublicKey).Equal(clientPublic) {
				w.WriteHeader(400)
				return
			}
			expires := time.Now().Add(35 * time.Second).Truncate(time.Second)
			identity, _ := url.Parse("tnl://workload-client/" + service + "/" + sessionID)
			leaf := &x509.Certificate{SerialNumber: big.NewInt(certificateSerial.Add(1) + 3), NotBefore: time.Now().Add(-time.Second), NotAfter: expires, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, URIs: []*url.URL{identity}}
			der, err := x509.CreateCertificate(rand.Reader, leaf, ca, csr.PublicKey, caKey)
			if err != nil {
				t.Error(err)
				w.WriteHeader(500)
				return
			}
			_ = json.NewEncoder(w).Encode(controlv1.ServiceClientCertificate{PrivateServiceId: service, CertificatePem: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), ExpiresAt: expires})
		case r.Method == "DELETE":
			revoked.Store(true)
			w.WriteHeader(204)
		default:
			w.WriteHeader(404)
		}
	}))
	authority.TLS = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{pair}}
	authority.StartTLS()
	defer authority.Close()
	server := strings.Replace(authority.URL, "127.0.0.1", "localhost", 1)
	target := "http://unused.invalid:3000"
	if protocol == "postgres" {
		target = "unused.invalid:5432"
	}
	targetDefinition := map[string]any{"type": "address", "address": target}
	if protocol == "kubernetes" {
		targetDefinition = map[string]any{"type": "eks", "cluster": "fixture", "region": "us-east-1"}
	}
	config := map[string]any{"version": 1, "tnl": map[string]any{"server": server, "team": team, "publishers": map[string]any{"remote": map[string]any{"public": true}}, "services": map[string]any{serviceName: map[string]any{"publisher": "remote", "protocol": protocol, "target": targetDefinition}}, "ci": map[string]any{"test": map[string]any{"github": map[string]any{"workflow": ".github/workflows/test.yml", "ref": "refs/heads/main", "events": []string{"push"}}, "services": []string{serviceName}}}}}
	data, _ := json.Marshal(config)
	if err := os.WriteFile(filepath.Join(root, "tnl.json"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"init", "--quiet", root}, {"-C", root, "remote", "add", "origin", "https://github.com/fixture/shop.git"}} {
		if output, err := exec.CommandContext(t.Context(), "git", args...).CombinedOutput(); err != nil {
			t.Fatalf("git fixture: %v %s", err, output)
		}
	}
	binary := filepath.Join(root, "tnl")
	build := exec.CommandContext(t.Context(), "go", "build", "-race", "-o", binary, "./cmd/tnl")
	build.Dir = "../.."
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("native build: %v %s", err, output)
	}
	caPath := filepath.Join(root, "root.pem")
	if err := os.WriteFile(caPath, caPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	var env []string
	for _, value := range os.Environ() {
		if !strings.HasPrefix(value, "TNL_") {
			env = append(env, value)
		}
	}
	env = append(env, "SSL_CERT_FILE="+caPath, "NODE_EXTRA_CA_CERTS="+caPath)
	call := func(input []byte, args ...string) []byte {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
		defer cancel()
		command := exec.CommandContext(ctx, binary, append([]string{"--no-telemetry", "runtime", "connections"}, args...)...)
		command.Env = env
		command.Stdin = bytes.NewReader(input)
		var output, diagnostics bytes.Buffer
		command.Stdout = &output
		command.Stderr = &diagnostics
		if err := command.Run(); err != nil {
			t.Fatalf("native call: %v %s", err, diagnostics.Bytes())
		}
		return output.Bytes()
	}
	var scope connectionruntime.Context
	if err := json.Unmarshal(call(nil, "context", "--directory", root, "--ci", "test"), &scope); err != nil {
		t.Fatal(err)
	}
	request, _ := json.Marshal(connectionruntime.StartRequest{Schema: 1, Context: scope, Assertion: "fixture-assertion"})
	var state connectionruntime.Status
	startArgs := []string{"start", "--directory", root, "--ci", "test", "--runner-temp", root}
	if protocol == "kubernetes" {
		path := filepath.Join(root, "cluster-token")
		if err := os.WriteFile(path, []byte("fixture-cluster-token"), 0o600); err != nil {
			t.Fatal(err)
		}
		startArgs = append(startArgs, "--kube-token-file", path, "--namespace", "runtime-test")
	}
	if err := json.Unmarshal(call(request, startArgs...), &state); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if state.PrivateHandle != "" {
			call(nil, "stop", "--handle", state.PrivateHandle)
		}
	}()
	if state.PID == os.Getpid() || state.State != "ready" {
		t.Fatal("no detached native owner")
	}
	encoded, _ := json.Marshal(state)
	if bytes.Contains(encoded, []byte("BEGIN")) || bytes.Contains(encoded, []byte("fixture-assertion")) {
		t.Fatal("startup disclosed credentials")
	}
	module, err := filepath.Abs("../../packages/ts/dist/index.js")
	if err != nil {
		t.Fatal(err)
	}
	script := `const {tnl}=await import(process.argv[1]); const c=await tnl.connect('api'); const response=await c.fetch(new Request(c.url+'/echo',{method:'POST',headers:{Authorization:'Bearer application-only'},body:'streamed-body'})); if(response.status!==201||await response.text()!=='streamed-body'||!response.url.endsWith('/echo'))throw Error('fetch contract'); const abort=new AbortController();const pending=c.fetch(c.url+'/hang',{signal:abort.signal});setTimeout(()=>abort.abort(),50);try{await pending;throw Error('abort ignored')}catch(e){if(!abort.signal.aborted)throw e} if(tnl.services.api.hostname!=='localhost'||JSON.stringify({api:tnl.services.api}).includes('PRIVATE KEY'))throw Error('metadata boundary');`
	script += `await new Promise(resolve=>setTimeout(resolve,6000));const rotated=await c.fetch(new Request(c.url+'/echo',{method:'POST',headers:{Authorization:'Bearer application-only'},body:'streamed-body'}));if(await rotated.text()!=='streamed-body'||rotated.headers.get('X-Certificate-Serial')===response.headers.get('X-Certificate-Serial'))throw Error('client certificate did not rotate');`
	script += `if(tnl.services.web.hostname!=='web.member.example')throw Error('browser snapshot was replaced');`
	args := []string{"--input-type=module", "-e", script, "file://" + module}
	var privateInput []byte
	if protocol == "kubernetes" {
		script = `const {tnl}=await import(process.argv[1]);const connection=await tnl.connect('cluster');if(!connection.server.startsWith('https://localhost:')||connection.context!=='tnl:shop/cluster'||!connection.kubeconfig)throw Error('kubernetes connection shape');`
		args = []string{"--input-type=module", "-e", script, "file://" + module}
		var credential credentialv1.ExecCredential
		if err := json.Unmarshal(call(nil, "kube-credential", "--handle", state.PrivateHandle, "--service", serviceName), &credential); err != nil {
			t.Fatal(err)
		}
		if credential.APIVersion != "client.authentication.k8s.io/v1" || credential.Status == nil || credential.Status.Token != "fixture-cluster-token" || credential.Status.ClientCertificateData == "" || credential.Status.ClientKeyData == "" || credential.Status.ExpirationTimestamp == nil {
			t.Fatal("native Kubernetes helper did not compose its credentials")
		}
		data, err := os.ReadFile(state.Kubeconfig)
		if err != nil || bytes.Contains(data, []byte("PRIVATE KEY")) || bytes.Contains(data, []byte("fixture-cluster-token")) {
			t.Fatal("session kubeconfig persisted credential material")
		}
	}
	if databaseURL != "" {
		backend, err := url.Parse(databaseURL)
		if err != nil {
			t.Fatal(err)
		}
		password, _ := backend.User.Password()
		credentials, _ := json.Marshal(map[string]string{"user": backend.User.Username(), "password": password, "database": strings.TrimPrefix(backend.Path, "/")})
		// drizzle-kit's current config loader is synchronous CommonJS. preload its
		// exact config module in this process after awaiting the SDK; TLS material
		// stays in memory rather than being serialized into a temporary config.
		marker := filepath.Join(root, "drizzle.config.cjs")
		if err := os.WriteFile(marker, []byte("module.exports = {};\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Join(root, "migrations/meta"), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, "migrations/meta/_journal.json"), []byte(`{"version":"7","dialect":"postgresql","entries":[{"idx":0,"version":"7","when":1700000000000,"tag":"0000_sdk","breakpoints":true}]}`), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, "migrations/0000_sdk.sql"), []byte("CREATE TABLE sdk_migration (id integer PRIMARY KEY);"), 0o600); err != nil {
			t.Fatal(err)
		}
		kit, err := filepath.Abs("../../node_modules/drizzle-kit/bin.cjs")
		if err != nil {
			t.Fatal(err)
		}
		script = `const {tnl}=await import(process.argv[1]);const {createRequire,Module}=await import('node:module');const {readFileSync}=await import('node:fs');const require=createRequire(process.argv[3]);const config=new Module(process.argv[2]);config.exports={dialect:'postgresql',out:process.cwd()+'/migrations',dbCredentials:{...await tnl.connect('database'),...JSON.parse(readFileSync(0,'utf8'))}};require.cache[process.argv[2]]=config;const kit=process.argv[3];process.argv=[process.execPath,kit,'migrate','--config',process.argv[2]];require(kit);`
		args = []string{"--input-type=module", "-e", script, "file://" + module, marker, kit}
		privateInput = credentials
	}
	node := exec.CommandContext(t.Context(), "node", args...)
	node.Dir = root
	node.Env = append(env, "TNL_CONNECTION_HANDLE="+state.PrivateHandle)
	if protocol == "http" {
		node.Env = append(node.Env, `TNL_PROJECT_RUNTIME={"dev":true,"namespace":"member.example","services":{"web":{"namespace":"member.example","hostname":"web.member.example","url":"https://web.member.example","protocol":"http","port":443,"public":true}}}`)
	}
	node.Stdin = bytes.NewReader(privateInput)
	if output, err := node.CombinedOutput(); err != nil {
		t.Fatalf("real SDK: %v %s", err, output)
	}
	if protocol == "http" && visits.Load() != 2 {
		t.Fatal("SDK requests were not delivered exactly once")
	}
	if databaseURL != "" {
		database, err := pgx.Connect(t.Context(), databaseURL)
		if err != nil {
			t.Fatal(err)
		}
		defer database.Close(context.Background())
		var table string
		if err := database.QueryRow(t.Context(), "SELECT to_regclass('public.sdk_migration')::text").Scan(&table); err != nil || table != "sdk_migration" {
			t.Fatalf("Drizzle Kit did not apply migration: %v", err)
		}
	}
	call(nil, "stop", "--handle", state.PrivateHandle)
	if state.Kubeconfig != "" {
		if _, err := os.Stat(state.Kubeconfig); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("session kubeconfig survived owner cleanup")
		}
	}
	if !revoked.Load() {
		t.Fatal("owner stop did not revoke workload")
	}
	if exchangeAttempts.Load() != 2 {
		t.Fatal("lost exchange response was not recovered by the same owner")
	}
	// cleanup is already joined; avoid a second stop with an expired handle.
	state.PrivateHandle = ""
}

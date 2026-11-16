package connector

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	clientproject "github.com/tnldotdev/tnl/internal/client/project"
	connectorruntime "github.com/tnldotdev/tnl/internal/connector/runtime"
)

type localResolverFunc func(context.Context, clientproject.Project, string) (string, string, error)

func (f localResolverFunc) ResolveTargetIdentity(ctx context.Context, p clientproject.Project, name string) (string, string, error) {
	return f(ctx, p, name)
}

func localProject(t *testing.T, protocol, binding string) string {
	t.Helper()
	t.Setenv("TNL_CONFIG", "")
	root := t.TempDir()
	for name, content := range map[string]string{
		"tnl.json":     `{"version":1,"tnl":{"services":{"db":{"protocol":"` + protocol + `"}},"deployments":{"local":{"targets":{"db":` + binding + `}}}}}`,
		"compose.yaml": "services: {}\n",
	} {
		if err := os.WriteFile(filepath.Join(root, name), []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func TestConnectLocalComposeWithoutControlState(t *testing.T) {
	root := localProject(t, "postgres", `{"type":"compose","service":"postgres","port":5432}`)
	state := filepath.Join(t.TempDir(), "absent-client-state")
	t.Setenv("TNL_STATE_DIR", state)
	t.Setenv("TNL_SERVER", "https://unreachable.invalid")
	identity := "container-one"
	resolver := localResolverFunc(func(ctx context.Context, p clientproject.Project, name string) (string, string, error) {
		if name != "db" || p.Config.Services[name].Target.Service == nil || *p.Config.Services[name].Target.Service != "postgres" {
			t.Fatal("lost exact Compose service selection")
		}
		if file, err := p.ComposeFile(name); err != nil || filepath.Base(file) != "compose.yaml" {
			t.Fatal("lost selected Compose file", err)
		}
		return "127.0.0.1:15432", identity, ctx.Err()
	})
	first, err := ConnectLocal(t.Context(), root, "db", "postgres", resolver)
	if err != nil || first.Host != "127.0.0.1" || first.Port != 15432 || first.SSL != nil || len(first.Binding) != 64 {
		t.Fatalf("local result: %+v %v", first, err)
	}
	second, err := ConnectLocal(t.Context(), root, "db", "postgres", resolver)
	if err != nil || second.Binding != first.Binding {
		t.Fatal("identical target changed binding", err)
	}
	identity = "container-two"
	second, err = ConnectLocal(t.Context(), root, "db", "postgres", resolver)
	if err != nil || second.Binding == first.Binding {
		t.Fatal("container replacement reused its driver binding", err)
	}
	if _, err := os.Stat(state); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("local connection created client state", err)
	}
}

func TestConnectLocalKeepsConfiguredTargetTLS(t *testing.T) {
	root := localProject(t, "postgres", `{"address":"127.0.0.1:5432","tls":{"hostname":"database.local"}}`)
	connection, err := ConnectLocal(t.Context(), root, "db", "postgres", nil)
	if err != nil || connection.SSL == nil || connection.SSL.ServerName != "database.local" || !connection.SSL.RejectUnauthorized {
		t.Fatalf("lost target TLS: %+v %v", connection, err)
	}
}

func TestConnectLocalProtocolTargets(t *testing.T) {
	for _, test := range []struct {
		name, service, protocol, url string
		tls                          bool
	}{
		{"http address", `{"address":"127.0.0.1:3000"}`, "http", "http://127.0.0.1:3000", false},
		{"http compose tls", `{"type":"compose","service":"web","port":443,"tls":{"hostname":"web.local"}}`, "http", "https://web.local:15443", true},
		{"tcp address", `{"address":6379}`, "tcp", "", false},
		{"tcp tls", `{"address":"127.0.0.1:6379","tls":{"hostname":"redis.local"}}`, "tcp", "", true},
		{"mysql docker", `{"type":"docker","container":"db","port":3306}`, "mysql", "", false},
		{"mysql tls", `{"address":"localhost:3306","tls":{}}`, "mysql", "", true},
		{"postgres compose", `{"type":"compose","service":"db","port":5432}`, "postgres", "", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := localProject(t, test.protocol, test.service)
			canonicalRoot, err := filepath.EvalSymlinks(root)
			if err != nil {
				t.Fatal(err)
			}
			resolver := localResolverFunc(func(_ context.Context, project clientproject.Project, name string) (string, string, error) {
				if name != "db" || project.Root != canonicalRoot {
					t.Fatal("lost exact project selection")
				}
				return "127.0.0.1:15443", "container-in-this-worktree", nil
			})
			connection, err := ConnectLocal(t.Context(), root, "db", test.protocol, resolver)
			if err != nil {
				t.Fatal(err)
			}
			if connection.Protocol != test.protocol || connection.URL != test.url || (connection.SSL != nil) != test.tls || len(connection.Binding) != 64 {
				t.Fatalf("local %s: %+v", test.protocol, connection)
			}
			if test.protocol == "mysql" && test.name == "mysql docker" && connection.Port != 15443 {
				t.Fatal("lost discovered container port")
			}
		})
	}
}

func TestConnectLocalKubernetesRequiresMatchingKubeconfig(t *testing.T) {
	root := localProject(t, "kubernetes", `{"address":"https://127.0.0.1:6443","tls":{"hostname":"cluster.local"}}`)
	file := filepath.Join(t.TempDir(), "kubeconfig")
	t.Setenv("KUBECONFIG", file)
	write := func(server, tlsName string) {
		t.Helper()
		content := "apiVersion: v1\nkind: Config\ncurrent-context: local\nclusters:\n- name: local\n  cluster:\n    server: " + server + "\n    tls-server-name: " + tlsName + "\ncontexts:\n- name: local\n  context:\n    cluster: local\n    user: my-credentials\nusers:\n- name: my-credentials\n  user:\n    token: customer-owned\n"
		if err := os.WriteFile(file, []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	write("https://127.0.0.1:6443", "cluster.local")
	connection, err := ConnectLocal(t.Context(), root, "db", "kubernetes", nil)
	if err != nil || connection.Server != "https://127.0.0.1:6443" || connection.Kubeconfig != file || connection.Context != "local" || connection.SSL.ServerName != "cluster.local" {
		t.Fatalf("local kubeconfig: %+v %v", connection, err)
	}
	for _, mismatch := range []struct{ server, tlsName string }{
		{"https://192.0.2.1:6443", "cluster.local"},
		{"https://127.0.0.1:6443", "wrong.local"},
	} {
		write(mismatch.server, mismatch.tlsName)
		if _, err := ConnectLocal(t.Context(), root, "db", "kubernetes", nil); err == nil {
			t.Fatal("accepted unrelated kubeconfig context", mismatch)
		}
	}
}

func TestLocalKubeconfigAcceptsMatchingCAFile(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	certificate := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "local cluster root"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, certificate, certificate, public, private)
	if err != nil {
		t.Fatal(err)
	}
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	root := t.TempDir()
	caFile := filepath.Join(root, "cluster-ca.pem")
	if err := os.WriteFile(caFile, ca, 0600); err != nil {
		t.Fatal(err)
	}
	configFile := filepath.Join(root, "config")
	t.Setenv("KUBECONFIG", configFile)
	content := "apiVersion: v1\nkind: Config\ncurrent-context: local\nclusters:\n- name: local\n  cluster:\n    server: https://127.0.0.1:6443\n    tls-server-name: cluster.local\n    certificate-authority: cluster-ca.pem\ncontexts:\n- name: local\n  context:\n    cluster: local\n    user: my-credentials\nusers:\n- name: my-credentials\n  user:\n    token: customer-owned\n"
	if err := os.WriteFile(configFile, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	trust := &connectorruntime.TLSOptions{ServerName: "cluster.local", RejectUnauthorized: true, CA: string(ca)}
	file, contextName, err := localKubeconfig("https://127.0.0.1:6443", trust)
	if err != nil || file != configFile || contextName != "local" {
		t.Fatalf("matching CA file: %q %q %v", file, contextName, err)
	}
	trust.CA = "another CA"
	if _, _, err := localKubeconfig("https://127.0.0.1:6443", trust); err == nil {
		t.Fatal("accepted a different target CA")
	}
}

func TestConnectLocalNormalizesConfiguredBarePort(t *testing.T) {
	for _, address := range []string{"5432", `5432`} {
		t.Run(address, func(t *testing.T) {
			root := localProject(t, "postgres", `{"address":`+address+`,"tls":{"hostname":"database.local"}}`)
			connection, err := ConnectLocal(t.Context(), root, "db", "postgres", nil)
			if err != nil || connection.Host != "127.0.0.1" || connection.Port != 5432 ||
				connection.SSL == nil || connection.SSL.ServerName != "database.local" || !connection.SSL.RejectUnauthorized {
				t.Fatalf("bare port connection: %+v %v", connection, err)
			}
		})
	}
}

func TestConnectLocalResolvesLocalhostWithoutDNS(t *testing.T) {
	root := localProject(t, "postgres", `{"address":"localhost:5432"}`)
	connection, err := ConnectLocal(t.Context(), root, "db", "postgres", nil)
	if err != nil || connection.Host != "127.0.0.1" {
		t.Fatalf("localhost connection: %+v %v", connection, err)
	}
	root = localProject(t, "postgres", `{"address":"localhost:5432","tls":{}}`)
	connection, err = ConnectLocal(t.Context(), root, "db", "postgres", nil)
	if err != nil || connection.Host != "127.0.0.1" || connection.SSL == nil || connection.SSL.ServerName != "localhost" {
		t.Fatalf("localhost TLS identity: %+v %v", connection, err)
	}
}

func TestConnectLocalNeverFallsBackFromInvalidDiscovery(t *testing.T) {
	root := localProject(t, "postgres", `{"type":"compose","service":"postgres","port":5432}`)
	for _, address := range []string{"db.internal:5432", "192.0.2.1:5432", "0.0.0.0:5432", "127.0.0.1:0", "[::1%lo0]:5432", "not-an-address"} {
		t.Run(address, func(t *testing.T) {
			resolver := localResolverFunc(func(context.Context, clientproject.Project, string) (string, string, error) {
				return address, "container", nil
			})
			if _, err := ConnectLocal(t.Context(), root, "db", "postgres", resolver); err == nil {
				t.Fatal("accepted nonlocal or invalid discovered listener")
			}
		})
	}
	want := errors.New("container belongs to another worktree")
	resolver := localResolverFunc(func(context.Context, clientproject.Project, string) (string, string, error) { return "", "", want })
	if _, err := ConnectLocal(t.Context(), root, "db", "postgres", resolver); !errors.Is(err, want) {
		t.Fatal("lost exact discovery failure", err)
	}
	if _, err := ConnectLocal(t.Context(), root, "db", "postgres", nil); err == nil {
		t.Fatal("accepted missing discovery capability")
	}
}

func TestConnectLocalRejectsRemoteAndProtocolSelections(t *testing.T) {
	for _, service := range []struct{ protocol, binding string }{
		{"postgres", `{"type":"rds","region":"us-east-1","instance":"orders"}`},
		{"postgres", `{"address":"db.internal:5432"}`},
		{"mysql", `{"address":"192.0.2.1:3306"}`},
		{"tcp", `{"address":"0.0.0.0:6379"}`},
		{"http", `{"address":"https://remote.invalid:3000","tls":{}}`},
		{"kubernetes", `{"address":"https://remote.invalid:6443","tls":{}}`},
		{"http", `{"type":"app","public_url":{}}`},
	} {
		root := localProject(t, service.protocol, service.binding)
		if _, err := ConnectLocal(t.Context(), root, "db", "postgres", nil); err == nil {
			t.Fatal("local selection accepted", service)
		}
	}
	for _, protocol := range []string{"mysql", "tcp", "http", "kubernetes", "invalid"} {
		root := localProject(t, "postgres", `{"address":"127.0.0.1:5432"}`)
		if _, err := ConnectLocal(t.Context(), root, "db", protocol, nil); err == nil {
			t.Fatal("accepted mismatched protocol", protocol)
		}
	}
	root := localProject(t, "postgres", `{"address":"127.0.0.1:5432"}`)
	for _, name := range []string{"missing", "../db"} {
		if _, err := ConnectLocal(t.Context(), root, name, "postgres", nil); err == nil {
			t.Fatal("accepted undeclared service", name)
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := ConnectLocal(ctx, root, "db", "postgres", nil); !errors.Is(err, context.Canceled) {
		t.Fatal("lost cancellation", err)
	}
	// a configured CA path cannot silently downgrade to plaintext.
	root = localProject(t, "postgres", `{"address":"127.0.0.1:5432","tls":{"ca":"missing.pem"}}`)
	if _, err := ConnectLocal(t.Context(), root, "db", "postgres", nil); err == nil || !strings.Contains(err.Error(), "tls.ca") {
		t.Fatal("invalid TLS configuration was ignored", err)
	}
}

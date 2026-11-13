package connector

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	clientproject "github.com/tnldotdev/tnl/internal/client/project"
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
		{"mysql", `{"address":"127.0.0.1:3306"}`},
		{"http", `{"type":"app","public_url":{}}`},
	} {
		root := localProject(t, service.protocol, service.binding)
		if _, err := ConnectLocal(t.Context(), root, "db", "postgres", nil); err == nil {
			t.Fatal("local selection accepted", service)
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

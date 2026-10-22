package oidc_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/testutil"
)

func TestIntegrationLocalOIDCPrivateKeyMount(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	root, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	leaf := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{"identity.127.0.0.1.nip.io"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, leaf, leaf, public, private)
	if err != nil {
		t.Fatal(err)
	}
	key, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string][]byte{"local.key": pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}), "local.crt": pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})} {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	override := filepath.Join(dir, "compose.yaml")
	if err := os.WriteFile(override, []byte("services:\n  oidc:\n    ports: !override [\"127.0.0.1::8444\"]\n"), 0600); err != nil {
		t.Fatal(err)
	}
	project := fmt.Sprintf("tnl-oidc-proof-%d", time.Now().UnixNano())
	// docker desktop may make bind-mounted host files readable regardless of
	// their mode. seed a Linux-native filesystem with a different owner's 0600
	// key so this proof exercises Linux permissions on macOS too.
	volume := project + "-host"
	docker := func(ctx context.Context, args ...string) ([]byte, error) {
		return exec.CommandContext(ctx, "docker", args...).CombinedOutput()
	}
	if out, err := docker(t.Context(), "volume", "create", volume); err != nil {
		t.Fatalf("create Linux host fixture: %v %s", err, out)
	}
	t.Cleanup(func() {
		out, err := docker(context.Background(), "volume", "rm", volume)
		if err != nil {
			t.Errorf("remove Linux host fixture: %v %s", err, out)
		}
	})
	if out, err := docker(t.Context(), "run", "--rm", "--user", "0:0", "--entrypoint", "/bin/sh", "--mount", "type=bind,source="+dir+",target=/source,readonly", "--mount", "type=volume,source="+volume+",target=/linux-host", "caddy:2.10.2-alpine@sha256:4c6e91c6ed0e2fa03efd5b44747b625fec79bc9cd06ac5235a779726618e530d", "-ec", "cp /source/local.crt /source/local.key /linux-host/; chown 1000:1000 /linux-host/local.*; chmod 0644 /linux-host/local.crt; chmod 0600 /linux-host/local.key"); err != nil {
		t.Fatalf("seed private Linux key: %v %s", err, out)
	}
	mountpoint, err := docker(t.Context(), "volume", "inspect", "--format", "{{.Mountpoint}}", volume)
	if err != nil {
		t.Fatal(err)
	}
	compose := func(ctx context.Context, args ...string) ([]byte, error) {
		base := []string{"compose", "--project-name", project, "--file", filepath.Join(root, "development/local/compose.yaml"), "--file", override}
		cmd := exec.CommandContext(ctx, "docker", append(base, args...)...)
		cmd.Dir, cmd.Env = root, append(os.Environ(), "TNL_LOCAL_CERTS_DIR="+strings.TrimSpace(string(mountpoint)))
		return cmd.CombinedOutput()
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if out, err := compose(ctx, "down", "--volumes", "--remove-orphans", "--rmi", "local"); err != nil {
			t.Errorf("local OIDC cleanup: %v %s", err, out)
		}
	})
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Minute)
	defer cancel()
	if out, err := compose(ctx, "up", "--build", "--detach", "oidc"); err != nil {
		t.Fatalf("start local OIDC: %v %s", err, out)
	}
	out, err := compose(ctx, "port", "oidc", "8444")
	if err != nil {
		logs, _ := compose(ctx, "logs", "--no-color", "oidc")
		t.Fatalf("OIDC port: %v %s\n%s", err, out, logs)
	}
	address := strings.TrimSpace(string(out))
	cert, _ := x509.ParseCertificate(der)
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: "identity.127.0.0.1.nip.io"}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: time.Second}
	deadline := time.Now().Add(10 * time.Second)
	for {
		response, err := client.Get("https://" + address + "/.well-known/openid-configuration")
		if err == nil {
			_ = response.Body.Close()
			if response.StatusCode == http.StatusOK {
				break
			}
		}
		if time.Now().After(deadline) {
			logs, _ := compose(ctx, "logs", "--no-color", "oidc")
			t.Fatalf("nonroot OIDC could not read a mode-0600 host key: %v\n%s", err, logs)
		}
		time.Sleep(100 * time.Millisecond)
	}
	keyInfo, err := os.Stat(filepath.Join(dir, "local.key"))
	if err != nil || keyInfo.Mode().Perm() != 0600 {
		t.Fatalf("host key permissions changed: %v %v", keyInfo, err)
	}
	// inspect the actual image/runtime identity, not just the Dockerfile text.
	id, err := compose(ctx, "ps", "--quiet", "oidc")
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(ctx, "docker", "inspect", "--format", "{{.Config.User}}", strings.TrimSpace(string(id)))
	user, err := cmd.CombinedOutput()
	if err != nil || strings.TrimSpace(string(user)) != "65532:65532" {
		t.Fatalf("OIDC runtime user=%q %v", user, err)
	}
	// local:up must also work when the volume already belongs to the provider.
	if out, err := compose(ctx, "run", "--rm", "--no-deps", "oidc-certificates"); err != nil {
		t.Fatalf("refresh existing OIDC certificate volume: %v %s", err, out)
	}
}

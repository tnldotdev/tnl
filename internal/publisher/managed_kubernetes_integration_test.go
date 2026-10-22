package publisher_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/kubeconfig"
	"github.com/tnldotdev/tnl/internal/publisher"
	"github.com/tnldotdev/tnl/internal/testutil"
	kubev1 "k8s.io/client-go/tools/clientcmd/api/v1"
)

var kindBinary = flag.String("tnl-kind-binary", "kind", "kind v0.30.0 executable for disposable Kubernetes integration")

const kindNode = "kindest/node:v1.34.0@sha256:7416a61b42b1662ca6ca89f02028ac133a309a2a30ba309614e8ec94d976dc5a"
const kubeBusybox = "mirror.gcr.io/library/busybox:1.37.0@sha256:bdf57e528e45e4433820e045b29b4597825a1c9e38353532d90a01445013f82e"

// this opt-in fixture owns the entire disposable cluster and uses actual kubectl
// commands through the native frontend. control admission is a narrow callback;
// the parent topology suite must qualify its current-policy backend adapter.
func TestIntegrationKubernetesKubectl(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 6*time.Minute)
	defer cancel()
	kind, err := exec.LookPath(*kindBinary)
	if err != nil {
		t.Fatal("install kind v0.30.0 or pass -tnl-kind-binary")
	}
	version, err := exec.CommandContext(ctx, kind, "version").Output()
	if err != nil || !strings.Contains(string(version), "v0.30.0") {
		t.Fatal("disposable fixture requires kind v0.30.0")
	}
	kubectl, err := exec.LookPath("kubectl")
	if err != nil {
		t.Fatal("kubectl is required")
	}
	name := "tnl-kube-" + strconv.FormatInt(time.Now().UnixNano(), 36)
	admin := filepath.Join(root, "admin.yaml")
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		if err := exec.CommandContext(cleanup, kind, "delete", "cluster", "--name", name).Run(); err != nil {
			t.Error("remove disposable kind cluster:", err)
		}
	})
	create := exec.CommandContext(ctx, kind, "create", "cluster", "--name", name, "--image", kindNode, "--kubeconfig", admin, "--wait", "120s")
	if output, err := create.CombinedOutput(); err != nil {
		t.Fatalf("create disposable cluster: %v\n%s", err, output)
	}
	adminRun := func(args ...string) []byte {
		t.Helper()
		command := exec.CommandContext(ctx, kubectl, append([]string{"--kubeconfig", admin}, args...)...)
		output, err := command.Output()
		if err != nil {
			t.Fatal("disposable cluster setup failed:", args[0], err)
		}
		return output
	}
	adminRun("create", "serviceaccount", "visitor")
	adminRun("create", "clusterrolebinding", "visitor", "--clusterrole=cluster-admin", "--serviceaccount=default:visitor")
	token := adminRun("create", "token", "visitor", "--duration=10m")
	tokenPath := filepath.Join(root, "cluster-token")
	if os.WriteFile(tokenPath, bytes.TrimSpace(token), 0o600) != nil {
		t.Fatal("write fixture token")
	}
	var adminConfig kubev1.Config
	if json.Unmarshal(adminRun("config", "view", "--raw", "--minify", "-o=json"), &adminConfig) != nil || len(adminConfig.Clusters) != 1 {
		t.Fatal("invalid disposable cluster config")
	}
	cluster := adminConfig.Clusters[0].Cluster
	endpoint, err := url.Parse(cluster.Server)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(cluster.CertificateAuthorityData) {
		t.Fatal("missing cluster CA")
	}
	adminRun("run", "kube-fixture", "--image="+kubeBusybox, "--restart=Never", "--command", "--", "sh", "-c", "mkdir -p /www; printf kube-http > /www/index.html; httpd -p 8080 -h /www; nc -ll -p 8081 -e cat & while true; do printf 'kube-tick\\n'; sleep 1; done")
	adminRun("wait", "--for=condition=Ready", "pod/kube-fixture", "--timeout=120s")
	helper := filepath.Join(root, "tnl")
	build := exec.CommandContext(ctx, "go", "build", "-o", helper, "./cmd/tnl")
	build.Dir = "../.."
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build native helper: %v\n%s", err, output)
	}
	for _, public := range []bool{false, true} {
		t.Run(fmt.Sprintf("public=%v", public), func(t *testing.T) {
			var revoked atomic.Bool
			address, _, certificates := kubeFrontend(t, endpoint.Host, endpoint.Hostname(), roots, public, &revoked, publisher.KubernetesLimits{})
			state := filepath.Join(root, fmt.Sprintf("state-%v", public))
			owner := kubeconfig.Owner{ControlURL: "https://control.example.test", TeamID: "team", SourceID: "source", ServiceID: fmt.Sprintf("cluster-%v", public)}
			profile := kubeconfig.Profile{Owner: owner, StateDir: state, Public: public, Source: kubeconfig.Source{TokenFile: tokenPath}}
			if public {
				if os.MkdirAll(state, 0o700) != nil {
					t.Fatal("create fixture state")
				}
				certPath, keyPath := filepath.Join(state, "client.pem"), filepath.Join(state, "client-key.pem")
				var certPEM []byte
				for _, der := range certificates.client.Certificate {
					certPEM = append(certPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
				}
				private, err := x509.MarshalPKCS8PrivateKey(certificates.client.PrivateKey)
				if err != nil {
					t.Fatal(err)
				}
				if os.WriteFile(certPath, certPEM, 0o600) != nil || os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private}), 0o600) != nil {
					t.Fatal("write fixture client key")
				}
				profile.Certificate = &kubeconfig.CertificateFiles{CertificateFile: certPath, KeyFile: keyPath}
			}
			plan, err := kubeconfig.PlanSession(root, fmt.Sprintf("session-%v", public))
			if err != nil {
				t.Fatal(err)
			}
			result, err := kubeconfig.PrepareConnection(ctx, plan, kubeconfig.Options{Owner: owner, ProjectLabel: "shop", Service: "cluster", Server: "https://" + address, TLSServerName: kubeHostname, Helper: helper}, profile)
			if err != nil {
				t.Fatal(err)
			}
			caPath := filepath.Join(root, fmt.Sprintf("tnl-ca-%v.pem", public))
			if os.WriteFile(caPath, certificates.ca, 0o600) != nil {
				t.Fatal("write fixture CA")
			}
			base := []string{"--kubeconfig", result.File, "--context", result.Context, "--certificate-authority", caPath}
			run := func(args ...string) string {
				t.Helper()
				command := exec.CommandContext(ctx, kubectl, append(append([]string{}, base...), args...)...)
				output, err := command.CombinedOutput()
				if err != nil {
					t.Fatalf("kubectl %s failed: %v\n%s", args[0], err, output)
				}
				return string(output)
			}
			if !strings.Contains(run("get", "namespaces", "-o=name"), "namespace/default") {
				t.Fatal("discovery/list failed")
			}
			run("create", "configmap", "kube-test", "--from-literal=value=one")
			manifest := filepath.Join(state, "apply.json")
			if os.WriteFile(manifest, []byte(`{"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"kube-test"},"data":{"value":"applied"}}`), 0o600) != nil {
				t.Fatal("write apply fixture")
			}
			run("apply", "--server-side", "--force-conflicts", "-f", manifest)
			run("patch", "configmap", "kube-test", "--type=merge", "-p", `{"data":{"value":"two"}}`)
			run("delete", "configmap", "kube-test")
			run("create", "deployment", "kube-rollout", "--image="+kubeBusybox, "--", "sleep", "60")
			run("rollout", "status", "deployment/kube-rollout", "--timeout=30s")
			run("delete", "deployment/kube-rollout")
			if run("exec", "kube-fixture", "--", "printf", "kube-exec") != "kube-exec" {
				t.Fatal("exec output changed")
			}
			spdy := exec.CommandContext(ctx, kubectl, append(append([]string{}, base...), "exec", "kube-fixture", "--", "printf", "kube-spdy")...)
			spdy.Env = append(os.Environ(), "KUBECTL_REMOTE_COMMAND_WEBSOCKETS=false")
			if output, err := spdy.CombinedOutput(); err != nil || string(output) != "kube-spdy" {
				t.Fatal("actual kubectl SPDY exec failed", err)
			}
			copySource, copyDestination := filepath.Join(state, "copy-source"), filepath.Join(state, "copy-destination")
			if os.WriteFile(copySource, []byte("kube-copy"), 0o600) != nil {
				t.Fatal("write cp fixture")
			}
			run("cp", copySource, "kube-fixture:/tmp/tnl-copy")
			run("cp", "kube-fixture:/tmp/tnl-copy", copyDestination)
			if copied, err := os.ReadFile(copyDestination); err != nil || string(copied) != "kube-copy" {
				t.Fatal("kubectl cp changed bytes")
			}
			for _, operation := range []struct {
				name   string
				args   []string
				prefix string
			}{
				{"watch", []string{"get", "pod/kube-fixture", "--watch", "-o=name"}, "pod/"},
				{"exec", []string{"exec", "kube-fixture", "--", "sh", "-c", "printf 'kube-ready\\n'; sleep 30"}, "kube-ready"},
				{"logs", []string{"logs", "--follow", "kube-fixture"}, "kube-tick"},
				{"attach", []string{"attach", "kube-fixture"}, "kube-tick"},
			} {
				t.Run(operation.name+"-revocation", func(t *testing.T) {
					revoked.Store(false)
					call, stop := context.WithTimeout(ctx, 10*time.Second)
					defer stop()
					command := exec.CommandContext(call, kubectl, append(append([]string{}, base...), operation.args...)...)
					stdout, err := command.StdoutPipe()
					if err != nil {
						t.Fatal(err)
					}
					command.Stderr = io.Discard
					if command.Start() != nil {
						t.Fatal("start streaming kubectl")
					}
					lines := bufio.NewScanner(stdout)
					if !lines.Scan() || !strings.HasPrefix(lines.Text(), operation.prefix) {
						stop()
						_ = command.Wait()
						t.Fatal("stream produced no initial result")
					}
					revoked.Store(true)
					done := make(chan error, 1)
					go func() { _, _ = io.Copy(io.Discard, stdout); done <- command.Wait() }()
					select {
					case err := <-done:
						if err == nil {
							t.Fatal("revoked streaming command succeeded")
						}
					case <-time.After(3 * time.Second):
						stop()
						<-done
						t.Fatal("revoked stream remained active")
					}
				})
			}
			t.Run("portforward-revocation", func(t *testing.T) {
				revoked.Store(false)
				call, stop := context.WithTimeout(ctx, 10*time.Second)
				defer stop()
				command := exec.CommandContext(call, kubectl, append(append([]string{}, base...), "port-forward", "--address=127.0.0.1", "pod/kube-fixture", ":8081")...)
				stdout, err := command.StdoutPipe()
				if err != nil {
					t.Fatal(err)
				}
				command.Stderr = io.Discard
				if command.Start() != nil {
					t.Fatal("start portforward")
				}
				defer func() { stop(); _ = command.Wait() }()
				lines := bufio.NewScanner(stdout)
				if !lines.Scan() {
					t.Fatal("portforward did not start")
				}
				parts := strings.Fields(lines.Text())
				if len(parts) < 3 || parts[0] != "Forwarding" {
					t.Fatal("invalid portforward response")
				}
				conn, err := net.DialTimeout("tcp", parts[2], time.Second)
				if err != nil {
					t.Fatal(err)
				}
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(4 * time.Second))
				_, _ = io.WriteString(conn, "kube-portforward")
				data := make([]byte, len("kube-portforward"))
				_, err = io.ReadFull(conn, data)
				if err != nil || string(data) != "kube-portforward" {
					t.Fatal("portforward bytes changed")
				}
				revoked.Store(true)
				var one [1]byte
				if _, err := conn.Read(one[:]); err == nil {
					t.Fatal("revoked portforward stayed open")
				}
			})
		})
	}
}

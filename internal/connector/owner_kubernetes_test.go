package connector

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/client/auth"
	connectorruntime "github.com/tnldotdev/tnl/internal/connector/runtime"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
	"k8s.io/client-go/tools/clientcmd"
)

func newDeploymentKubeBackend(t *testing.T, credential auth.DeploymentCredential, selection, projectDirectory, stateDirectory string, client *http.Client) *connectorConnectionBackend {
	t.Helper()
	token, err := credential.Encode()
	if err != nil {
		t.Fatal(err)
	}
	request := connectorruntime.DeploymentRequest{Project: credential.Team + "/" + credential.Approval.ProjectKey, Name: selection, Token: token, Services: []string{"cluster"}}
	project, scope, err := connectionDeployment(ContextOptions{Directory: projectDirectory, Deployment: &request})
	if err != nil {
		t.Fatal(err)
	}
	deployment, err := newDeploymentConnection(request, client)
	if err != nil {
		t.Fatal(err)
	}
	directory, err := connectorruntime.NewDirectory(stateDirectory)
	if err != nil {
		t.Fatal(err)
	}
	b := &connectorConnectionBackend{
		deployment: deployment, project: project, scope: scope, directory: directory,
		stateDir: stateDirectory, executable: "/absolute/tnl", parentPID: os.Getpid(),
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := b.Close(ctx); err != nil {
			t.Error(err)
		}
	})
	return b
}

func TestDeploymentKubeconfigIsPrivateToEachOwner(t *testing.T) {
	home, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	shared := filepath.Join(home, "shared-config")
	t.Setenv("KUBECONFIG", shared)
	original := []byte("apiVersion: v1\nkind: Config\ncurrent-context: user-context\n")
	if err := os.WriteFile(shared, original, 0o600); err != nil {
		t.Fatal(err)
	}
	hostnames := []string{"first.cluster.example.test", "second.cluster.example.test"}
	var selections atomic.Uint32
	f := newDeploymentOwnerFixture(t, 24*time.Hour, func(w http.ResponseWriter, name string, credential auth.DeploymentCredential) {
		index := int(selections.Add(1)) - 1
		if name != "cluster" || index >= len(hostnames) {
			t.Error("unexpected service selection", name)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		selected := deploymentOwnerSelection(credential, name)
		selected.Endpoint.Hostname = hostnames[index]
		selected.TrustRevision = int64(index + 1)
		selected.KubernetesAuth = &controlv1.KubernetesAuth{Provider: controlv1.KubernetesEKS, Cluster: "saved-cluster", Region: "us-east-1"}
		if err := json.NewEncoder(w).Encode(selected); err != nil {
			t.Error(err)
		}
	})
	project, state := t.TempDir(), t.TempDir()
	var backends []*connectorConnectionBackend
	var connections []connectorruntime.Connection
	var contents [][]byte
	for index, hostname := range hostnames {
		b := newDeploymentKubeBackend(t, f.credential, "production", project, state, f.httpClient)
		if _, _, err := b.Start(t.Context()); err != nil {
			t.Fatal(err)
		}
		service := b.services["cluster"]
		listener, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = listener.Close() })
		connection := connectorruntime.Connection{
			Schema: 1, Protocol: "kubernetes", Host: "127.0.0.1", Port: listener.Addr().(*net.TCPAddr).Port,
			URL: "https://" + hostname, ExpiresAt: b.deadline,
		}
		kube, err := b.prepareKube(t.Context(), "cluster", service, connection)
		if err != nil {
			t.Fatal(err)
		}
		connection.Kubeconfig, connection.Context = kube.result.File, kube.result.Context
		owner := &ownedServiceListener{
			listener: connectorruntime.NewListenerSwitch(listener),
			attempt:  &servicePreparation{service: service, state: preparingService{}},
		}
		b.listeners["cluster"] = owner
		if err := b.publishServiceLocked("cluster", owner, owner.attempt, &servingService{connection: connection}, kube, nil); err != nil {
			t.Fatal(err)
		}
		published, err := b.Prepared("cluster")
		if err != nil || published.Kubeconfig != connection.Kubeconfig || published.SSL == nil ||
			published.SSL.ServerName != hostname || !published.SSL.RejectUnauthorized {
			t.Fatal("prepared connection lost its owner artifact or verified TLS identity", err)
		}
		if filepath.Dir(connection.Kubeconfig) != b.directory {
			t.Error("deployment kubeconfig escaped its canonical connector owner directory", connection.Kubeconfig)
		}
		config, err := clientcmd.LoadFromFile(connection.Kubeconfig)
		if err != nil {
			t.Fatal(err)
		}
		selected := config.Contexts[connection.Context]
		if selected == nil {
			t.Fatal("kubeconfig omitted its selected context")
		}
		if config.CurrentContext != connection.Context {
			t.Error("private kubeconfig did not select its exact context")
		}
		cluster, user := config.Clusters[selected.Cluster], config.AuthInfos[selected.AuthInfo]
		args := []string{"runtime", "connections", "kube-credential", "--handle", filepath.Join(b.directory, "handle.json"), "--service", "cluster"}
		if cluster == nil || cluster.Server != "https://127.0.0.1:"+strconv.Itoa(connection.Port) ||
			cluster.TLSServerName != hostname || cluster.InsecureSkipTLSVerify || len(cluster.CertificateAuthorityData) != 0 ||
			user == nil || user.Exec == nil || user.Exec.Command != b.executable || !reflect.DeepEqual(user.Exec.Args, args) {
			t.Fatal("kubeconfig changed its local endpoint, managed TLS trust, or exact owner helper")
		}
		info, err := os.Stat(connection.Kubeconfig)
		if err != nil || info.Mode().Perm() != 0o600 {
			t.Fatal("kubeconfig is not private", err)
		}
		data, err := os.ReadFile(connection.Kubeconfig)
		if err != nil {
			t.Fatal(err)
		}
		backends, connections, contents = append(backends, b), append(connections, connection), append(contents, data)
		if index == 1 && connections[0].Kubeconfig == connection.Kubeconfig {
			t.Error("independent deployment owners overwrote the same kubeconfig")
		}
		if index == 1 {
			data, err := os.ReadFile(connections[0].Kubeconfig)
			if err != nil || !bytes.Equal(data, contents[0]) {
				t.Error("second owner replaced the first owner's endpoint, trust, or credential helper", err)
			}
		}
	}
	for index, b := range backends {
		if _, err := b.Renew(t.Context()); err != nil {
			t.Fatal(err)
		}
		repeated, err := b.prepareKube(t.Context(), "cluster", b.services["cluster"], connections[index])
		if err != nil || repeated.result.File != connections[index].Kubeconfig || repeated.result.Context != connections[index].Context {
			t.Fatal("renewal replaced the owner's kubeconfig binding", err)
		}
		data, err := os.ReadFile(connections[index].Kubeconfig)
		if err != nil || !bytes.Equal(data, contents[index]) {
			t.Error("a sibling or renewal rewrote the captured endpoint and trust", err)
		}
	}
	if err := backends[1].Close(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(connections[1].Kubeconfig); !errors.Is(err, os.ErrNotExist) {
		t.Error("closed owner retained its kubeconfig", err)
	}
	data, err := os.ReadFile(connections[0].Kubeconfig)
	if err != nil || !bytes.Equal(data, contents[0]) {
		t.Fatal("closing a sibling removed or rewrote the first owner's kubeconfig", err)
	}
	if _, err := backends[0].Renew(t.Context()); err != nil {
		t.Fatal("closing a sibling stopped the first owner", err)
	}
	if err := backends[0].Close(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(connections[0].Kubeconfig); !errors.Is(err, os.ErrNotExist) {
		t.Error("first owner retained its kubeconfig", err)
	}
	if data, err := os.ReadFile(shared); err != nil || !bytes.Equal(data, original) {
		t.Error("deployment owners changed the user's kubeconfig", err)
	}
	if entries, err := os.ReadDir(project); err != nil || len(entries) != 0 {
		t.Error("deployment kubeconfig wrote into the project worktree", err)
	}
}

func TestDeploymentKubeconfigArtifactScope(t *testing.T) {
	shared := filepath.Join(t.TempDir(), "must-not-create")
	t.Setenv("KUBECONFIG", shared)
	credential := connectorDeploymentCredential(t, "https://control.example.test")
	project, state := t.TempDir(), t.TempDir()
	service := controlv1.Service{
		Id: "svc_aaaaaaaaaaaaaaaaaaaaaa", Endpoint: &controlv1.ServiceEndpoint{Hostname: "cluster.example.test"},
		KubernetesAuth: &controlv1.KubernetesAuth{Provider: controlv1.KubernetesEKS, Cluster: "saved-cluster", Region: "us-east-1"},
	}
	prepare := func(b *connectorConnectionBackend, port int) (string, []byte) {
		t.Helper()
		b.teamID = b.scope.TeamID
		kube, err := b.prepareKube(t.Context(), "cluster", service, connectorruntime.Connection{Host: "127.0.0.1", Port: port})
		if err != nil {
			t.Fatal(err)
		}
		canonicalState, err := filepath.EvalSymlinks(b.stateDir)
		if err != nil || filepath.Dir(b.directory) != canonicalState || filepath.Dir(kube.result.File) != b.directory {
			t.Fatal("kubeconfig artifact lost its canonical owner and selected state directory", err)
		}
		canonicalProject, err := filepath.EvalSymlinks(b.project.Root)
		if err != nil || b.scope.Directory != canonicalProject {
			t.Fatal("owner selected another project worktree", err)
		}
		data, err := os.ReadFile(kube.result.File)
		if err != nil {
			t.Fatal(err)
		}
		return kube.result.File, data
	}
	first := newDeploymentKubeBackend(t, credential, "production", project, state, nil)
	firstFile, firstData := prepare(first, 25443)
	for _, variant := range []string{"same-selection", "project", "deployment", "credential", "worktree", "state"} {
		t.Run(variant, func(t *testing.T) {
			current, selection, directory, stateDirectory := credential, "production", project, state
			switch variant {
			case "project":
				current.Approval.ProjectKey = "another-project"
			case "deployment":
				selection = "staging"
			case "credential":
				current = connectorDeploymentCredential(t, credential.ControlURL)
			case "worktree":
				directory = t.TempDir()
			case "state":
				stateDirectory = t.TempDir()
			}
			other := newDeploymentKubeBackend(t, current, selection, directory, stateDirectory, nil)
			otherFile, _ := prepare(other, 25444)
			if otherFile == firstFile {
				t.Fatal("independent owner reused another owner's artifact", variant)
			}
			if err := other.Close(t.Context()); err != nil {
				t.Fatal(err)
			}
			if data, err := os.ReadFile(firstFile); err != nil || !bytes.Equal(data, firstData) {
				t.Fatal("another owner overwrote or removed the original artifact", variant, err)
			}
		})
	}
	if _, err := os.Stat(shared); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("deployment owners wrote the global kubeconfig", err)
	}
}

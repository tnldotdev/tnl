package kubeconfig

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"go.yaml.in/yaml/v3"

	kubev1 "k8s.io/client-go/tools/clientcmd/api/v1"
)

func privateTemp(t *testing.T) string {
	t.Helper()
	path, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return path
}

func options() Options {
	return Options{Owner: Owner{ControlURL: "https://control.example.test", TeamID: "team", SourceID: "source", ServiceID: "cluster"}, ProjectLabel: "shop", Service: "cluster", Namespace: "development", Server: "https://cluster.example.test:25443", TLSServerName: "cluster.example.test", Helper: "/opt/tnl", Profile: "/state/profile.json"}
}

func loadConfig(t *testing.T, path string) (kubev1.Config, []byte) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	n, err := parse(data)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := nodeJSON(n)
	if err != nil {
		t.Fatal(err)
	}
	var config kubev1.Config
	if json.Unmarshal(encoded, &config) != nil {
		t.Fatal("invalid official kubeconfig")
	}
	return config, data
}

func TestPreparePreservesExistingConfiguration(t *testing.T) {
	root := privateTemp(t)
	path := filepath.Join(root, "config")
	original := []byte(`# keep the user's current context and relative paths
apiVersion: v1
kind: Config
current-context: original
clusters:
  - name: original
    cluster:
      server: https://original.example.test
      certificate-authority: relative/root.pem # relative to this file
users:
  - name: original
    user:
      exec:
        apiVersion: client.authentication.k8s.io/v1
        command: /never/execute/this
        interactiveMode: Never
contexts:
  - name: original
    context:
      cluster: original
      user: original
      custom-extension: retained
preferences:
  colors: true
`)
	if err := os.WriteFile(path, original, 0o600); err != nil {
		t.Fatal(err)
	}
	p, err := PlanLocal(root, path)
	if err != nil {
		t.Fatal(err)
	}
	result, err := p.Prepare(t.Context(), options())
	if err != nil {
		t.Fatal(err)
	}
	if result.Context != "tnl:shop/cluster" || result.Qualified || result.Namespace != "development" {
		t.Fatalf("unexpected context metadata: %+v", result)
	}
	config, data := loadConfig(t, path)
	if config.CurrentContext != "original" || len(config.Clusters) != 2 || config.Clusters[0].Cluster.CertificateAuthority != "relative/root.pem" || !bytes.Contains(data, []byte("# relative to this file")) || !bytes.Contains(data, []byte("custom-extension: retained")) {
		t.Fatal("existing configuration or comments changed")
	}
	cluster, user := config.Clusters[1].Cluster, config.AuthInfos[1].AuthInfo
	if cluster.TLSServerName != options().TLSServerName || cluster.CertificateAuthority != "" || len(cluster.CertificateAuthorityData) != 0 || cluster.InsecureSkipTLSVerify || user.ClientCertificate != "" || user.ClientKey != "" || user.Token != "" || user.Exec == nil || user.Exec.Command != "/opt/tnl" || user.Exec.InteractiveMode != "Never" || user.Exec.APIVersion != "client.authentication.k8s.io/v1" {
		t.Fatal("native trust or exec composition contract changed")
	}
	if _, err := p.Prepare(t.Context(), options()); err != nil {
		t.Fatal(err)
	}
	_, again := loadConfig(t, path)
	if !bytes.Equal(data, again) {
		t.Fatal("preparation was not idempotent")
	}
}

func TestPrepareQualifiesOtherInstallationAcrossFiles(t *testing.T) {
	root := privateTemp(t)
	first, second := filepath.Join(root, "first"), filepath.Join(root, "second")
	other := options()
	other.Owner.ControlURL = "https://other.example.test"
	if _, err := (Plan{Path: second}).Prepare(t.Context(), other); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(second)
	if err != nil {
		t.Fatal(err)
	}
	p, err := PlanLocal(root, first+string(os.PathListSeparator)+second)
	if err != nil {
		t.Fatal(err)
	}
	result, err := p.Prepare(t.Context(), options())
	if err != nil {
		t.Fatal(err)
	}
	if !result.Qualified || result.Context == "tnl:shop/cluster" {
		t.Fatal("other installation was not qualified")
	}
	after, err := os.ReadFile(second)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("unrelated kubeconfig changed")
	}
	stable, err := p.Prepare(t.Context(), options())
	if err != nil || stable.Context != result.Context {
		t.Fatal("qualified context is unstable")
	}
}

func TestPrepareLocksConcurrentContexts(t *testing.T) {
	path := filepath.Join(privateTemp(t), "config")
	var workers sync.WaitGroup
	for _, name := range []string{"one", "two", "three", "four"} {
		workers.Go(func() {
			o := options()
			o.Service, o.Owner.ServiceID = name, name
			if _, err := (Plan{Path: path}).Prepare(t.Context(), o); err != nil {
				t.Error(err)
			}
		})
	}
	workers.Wait()
	config, _ := loadConfig(t, path)
	if len(config.Contexts) != 4 || config.CurrentContext != "" {
		t.Fatal("lost context or selected a global context")
	}
}

func TestPrepareRejectsUnsafeYAMLAndSymlinks(t *testing.T) {
	for _, input := range []string{
		"apiVersion: v1\nkind: Config\nclusters: &a []\nusers: *a\n",
		"apiVersion: v1\nkind: Config\ncurrent-context: a\ncurrent-context: b\n",
		"apiVersion: v1\nkind: Config\npreferences: {<<: {colors: true}}\n",
		"apiVersion: v1\nkind: Config\n---\napiVersion: v1\nkind: Config\n",
	} {
		t.Run(input, func(t *testing.T) {
			path := filepath.Join(privateTemp(t), "config")
			if os.WriteFile(path, []byte(input), 0o600) != nil {
				t.Fatal("write fixture")
			}
			if _, err := (Plan{Path: path}).Prepare(t.Context(), options()); !errors.Is(err, ErrConfig) {
				t.Fatal("unsafe YAML accepted")
			}
			data, _ := os.ReadFile(path)
			if string(data) != input {
				t.Fatal("rejected file changed")
			}
		})
	}
	root := privateTemp(t)
	target, path := filepath.Join(root, "user"), filepath.Join(root, "config")
	if os.WriteFile(target, []byte("original"), 0o600) != nil || os.Symlink(target, path) != nil {
		t.Fatal("write symlink fixture")
	}
	if _, err := (Plan{Path: path}).Prepare(t.Context(), options()); !errors.Is(err, ErrConfig) {
		t.Fatal("symlink accepted")
	}
	data, _ := os.ReadFile(target)
	if string(data) != "original" {
		t.Fatal("symlink target changed")
	}
}

func TestSessionPlanUsesSameContextAndPrivateExclusiveFile(t *testing.T) {
	p, err := PlanSession(privateTemp(t), "session-1")
	if err != nil {
		t.Fatal(err)
	}
	result, err := p.Prepare(context.Background(), options())
	if err != nil {
		t.Fatal(err)
	}
	config, _ := loadConfig(t, result.File)
	info, err := os.Stat(result.File)
	if err != nil || info.Mode().Perm() != 0o600 || config.CurrentContext != "tnl:shop/cluster" || result.Context != "tnl:shop/cluster" {
		t.Fatal("session kubeconfig contract changed")
	}
	if _, err := p.Prepare(t.Context(), options()); !errors.Is(err, ErrCollision) {
		t.Fatal("existing session file overwritten")
	}
	if err := p.CleanupSession(t.Context(), result); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(result.File); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("session file was not removed")
	}
}

func TestOwnedNamespaceAndExtraFieldsSurviveRefresh(t *testing.T) {
	path := filepath.Join(privateTemp(t), "config")
	p := Plan{Path: path}
	o := options()
	if _, err := p.Prepare(t.Context(), o); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	node, err := parse(data)
	if err != nil {
		t.Fatal(err)
	}
	context := field(sequence(node, "contexts")[0], "context")
	field(context, "namespace").Value, field(context, "namespace").LineComment = "chosen", "# user preference"
	set(context, "retained", text("extra"))
	data, err = yaml.Marshal(node)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	o.Namespace = ""
	result, err := p.Prepare(t.Context(), o)
	if err != nil {
		t.Fatal(err)
	}
	_, data = loadConfig(t, path)
	if result.Namespace != "chosen" || !bytes.Contains(data, []byte("retained: extra")) || !bytes.Contains(data, []byte("# user preference")) {
		t.Fatal("owned context lost user settings")
	}
}

func TestCleanupRetainsChangedSessionFile(t *testing.T) {
	p, err := PlanSession(privateTemp(t), "session")
	if err != nil {
		t.Fatal(err)
	}
	result, err := p.Prepare(t.Context(), options())
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(result.File)
	if err != nil {
		t.Fatal(err)
	}
	data = append(data, []byte("# user work\n")...)
	if err := os.WriteFile(result.File, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := p.CleanupSession(t.Context(), result); !errors.Is(err, ErrConfig) {
		t.Fatal("changed file was removed")
	}
}

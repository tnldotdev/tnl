package publisherdeployment

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/projectconfig"
	"go.yaml.in/yaml/v3"
)

func testBundle(t *testing.T, count int) Bundle {
	t.Helper()
	b, err := Generate(testConfig(count), testSource())
	if err != nil {
		t.Fatal(err)
	}
	return b
}
func testConfig(count int) config.TNL {
	return config.TNL{Publishers: map[string]config.Publisher{"production": {AWS: &config.PublisherAWS{Replicas: &count}}}}
}
func testSource() projectconfig.SourceIdentity {
	return projectconfig.SourceIdentity{Key: "project-example", Fingerprint: strings.Repeat("a", 64)}
}
func testDirectory(t *testing.T) string {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Join(root, "generated")
}
func put(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatal(err)
	}
}

func TestGoldenAndReplicaStability(t *testing.T) {
	two := testBundle(t, 2)
	for name, fixture := range map[string]string{"aws/production.yaml": "fargate.yaml", "aws/production.parameters.example.json": "fargate.parameters.example.json", "aws/production.storage-policy.json": "fargate.storage-policy.json", "manifest.json": "fargate.manifest.example.json"} {
		want, err := os.ReadFile(filepath.Join("..", "..", "deploy", "publishers", fixture))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(two.Files[name], want) {
			t.Fatalf("fixture %s drifted; run task generate", fixture)
		}
	}
	one, eight := testBundle(t, 1), testBundle(t, config.MaxPublisherReplicas)
	if !reflect.DeepEqual(one.Manifest.Publishers[0].Replicas, two.Manifest.Publishers[0].Replicas[:1]) {
		t.Fatal("scaling changed surviving replica contract")
	}
	var first, second awsTemplate
	if err := yaml.Unmarshal(one.Files["aws/production.yaml"], &first); err != nil {
		t.Fatal(err)
	}
	if err := yaml.Unmarshal(eight.Files["aws/production.yaml"], &second); err != nil {
		t.Fatal(err)
	}
	for name, value := range first.Resources {
		if !reflect.DeepEqual(value, second.Resources[name]) {
			t.Fatalf("scaling changed %s", name)
		}
	}
	if len(second.Parameters) > 200 || len(second.Resources) > 500 || len(second.Outputs) > 200 || len(eight.Files["aws/production.yaml"]) > MaxArtifactBytes {
		t.Fatal("maximum stack exceeds quotas")
	}
	t.Logf("eight replicas: %d bytes, %d parameters, %d resources, %d outputs", len(eight.Files["aws/production.yaml"]), len(second.Parameters), len(second.Resources), len(second.Outputs))
	p := two.Manifest.Publishers[0]
	p.Name = "renamed"
	renamed, _, err := RenderAWS(p, "project-example")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(renamed, two.Files["aws/production.yaml"]) {
		t.Fatal("group rename changed template logical IDs or storage paths")
	}
}

func TestReadValidateAndReadOnlyCheck(t *testing.T) {
	b := testBundle(t, 2)
	dir := testDirectory(t)
	if b.Check(dir) == nil {
		t.Fatal("missing outputs accepted")
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatal("check created output directory")
	}
	if err := b.Write(dir); err != nil {
		t.Fatal(err)
	}
	// even a self-consistent edited manifest/template pair must be rejected by
	// bootstrap's fresh-render validation rather than trusted on hashes alone.
	modified := append(bytes.Clone(b.Files["aws/production.yaml"]), []byte("# edited\n")...)
	put(t, filepath.Join(dir, "aws/production.yaml"), modified)
	changed := testBundle(t, 2).Manifest
	changed.Publishers[0].TemplateSHA256 = digest(modified)
	changedData, err := encode(changed)
	if err != nil {
		t.Fatal(err)
	}
	put(t, filepath.Join(dir, ManifestPath), changedData)
	if _, err := Read(dir); err != nil {
		t.Fatal("self-consistent saved hashes", err)
	}
	if _, err := Validate(dir, testConfig(2), testSource()); err == nil {
		t.Fatal("bootstrap accepted an edited template with an updated hash")
	}
	if err := b.Write(dir); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(filepath.Join(dir, ManifestPath))
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Check(dir); err != nil {
		t.Fatal(err)
	}
	if _, err := Validate(dir, testConfig(2), testSource()); err != nil {
		t.Fatal(err)
	}
	if _, err := Validate(dir, testConfig(1), testSource()); err == nil {
		t.Fatal("stale capacity accepted")
	}
	other := testSource()
	other.Fingerprint = strings.Repeat("b", 64)
	if _, err := Validate(dir, testConfig(2), other); err == nil {
		t.Fatal("stale source accepted")
	}
	after, _ := os.Stat(filepath.Join(dir, ManifestPath))
	if !before.ModTime().Equal(after.ModTime()) {
		t.Fatal("read changed manifest")
	}
	put(t, filepath.Join(dir, "aws", "custom.yaml"), []byte("customer custom template"))
	put(t, filepath.Join(dir, "production.parameters.json"), []byte("customer actual parameters"))
	if err := b.Check(dir); err != nil {
		t.Fatal(err)
	}
	put(t, filepath.Join(dir, "aws", "production.yaml"), []byte("stale"))
	if _, err := Read(dir); err == nil {
		t.Fatal("stale template hash accepted")
	}
	if err := b.Check(dir); err == nil {
		t.Fatal("stale template accepted")
	}
	if err := b.Write(dir); err != nil {
		t.Fatal(err)
	}
	empty, err := Generate(config.TNL{}, testSource())
	if err != nil {
		t.Fatal(err)
	}
	if err := empty.Check(dir); err == nil {
		t.Fatal("unexpected manifest-owned files accepted")
	}
	if err := empty.Write(dir); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"aws/custom.yaml", "production.parameters.json"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Fatal("unrelated file removed", err)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "aws/production.yaml")); !os.IsNotExist(err) {
		t.Fatal("retired owned template remains")
	}
}

func TestManifestRejectsUnsafeAndUnboundedInputs(t *testing.T) {
	for _, change := range []func(*Publisher){func(p *Publisher) { p.StoragePolicyPath = "" }, func(p *Publisher) { p.StoragePolicySHA256 = "" }} {
		b := testBundle(t, 2)
		change(&b.Manifest.Publishers[0])
		if b.Manifest.Validate() == nil {
			t.Fatal("required storage policy metadata was omitted")
		}
	}
	for _, change := range []func(*Manifest){func(m *Manifest) { m.SchemaVersion = 2 }, func(m *Manifest) { m.Publishers[0].TemplatePath = "../customer.yaml" }, func(m *Manifest) { m.Publishers[0].Replicas[0].Key = "other" }, func(m *Manifest) { m.Publishers = append(m.Publishers, m.Publishers[0]) }, func(m *Manifest) { m.Publishers[0].TemplateSHA256 = "invalid" }} {
		b := testBundle(t, 2)
		change(&b.Manifest)
		if b.Manifest.Validate() == nil {
			t.Fatal("invalid manifest accepted")
		}
	}
	dir := testDirectory(t)
	b := testBundle(t, 2)
	if err := b.Write(dir); err != nil {
		t.Fatal(err)
	}
	put(t, filepath.Join(dir, ManifestPath), bytes.Repeat([]byte(" "), MaxManifestBytes+1))
	if _, err := Read(dir); err == nil {
		t.Fatal("unbounded manifest accepted")
	}
	for _, count := range []int{-1, 0, config.MaxPublisherReplicas + 1} {
		if _, err := Generate(testConfig(count), testSource()); err == nil {
			t.Fatalf("accepted %d replicas", count)
		}
	}
	defaultConfig := testConfig(1)
	defaultConfig.Publishers["production"] = config.Publisher{AWS: &config.PublisherAWS{}}
	defaultBundle, err := Generate(defaultConfig, testSource())
	if err != nil || len(defaultBundle.Manifest.Publishers[0].Replicas) != 1 {
		t.Fatal("default replica count", err)
	}
}

func TestOutputOwnershipAndSymlinks(t *testing.T) {
	for _, location := range []string{"root", "aws", "file", "manifest"} {
		t.Run(location, func(t *testing.T) {
			dir := testDirectory(t)
			b := testBundle(t, 2)
			outside := t.TempDir()
			if err := os.MkdirAll(dir, 0755); err != nil {
				t.Fatal(err)
			}
			victim := filepath.Join(outside, "victim")
			put(t, victim, []byte("preserve"))
			switch location {
			case "root":
				if err := os.Remove(dir); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(outside, dir); err != nil {
					t.Fatal(err)
				}
			case "aws":
				if err := os.Symlink(outside, filepath.Join(dir, "aws")); err != nil {
					t.Fatal(err)
				}
			case "file":
				if err := os.Mkdir(filepath.Join(dir, "aws"), 0755); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(victim, filepath.Join(dir, "aws/production.yaml")); err != nil {
					t.Fatal(err)
				}
			case "manifest":
				if err := os.Symlink(victim, filepath.Join(dir, ManifestPath)); err != nil {
					t.Fatal(err)
				}
			}
			if err := b.Write(dir); err == nil {
				t.Fatal("symlink accepted")
			}
			if err := b.Check(dir); err == nil {
				t.Fatal("check followed symlink")
			}
			data, err := os.ReadFile(victim)
			if err != nil || string(data) != "preserve" {
				t.Fatal("symlink target changed")
			}
		})
	}
	dir := testDirectory(t)
	b := testBundle(t, 2)
	if err := os.MkdirAll(filepath.Join(dir, "aws"), 0755); err != nil {
		t.Fatal(err)
	}
	put(t, filepath.Join(dir, "aws/production.yaml"), []byte("customer"))
	if err := b.Write(dir); err == nil {
		t.Fatal("overwrote an unowned file")
	}
}

func TestParameterContract(t *testing.T) {
	b := testBundle(t, 2)
	p, err := b.Manifest.FindPublisher("production")
	if err != nil {
		t.Fatal(err)
	}
	var template awsTemplate
	if err := yaml.Unmarshal(b.Files[p.TemplatePath], &template); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{ControlURLParameter, ProjectKeyParameter, GroupParameter, TeamIDParameter, PublisherGroupIDParameter, DeploymentIDParameter, TemplateSHA256Parameter} {
		if _, ok := template.Parameters[name]; !ok {
			t.Fatal("missing bootstrap parameter", name)
		}
	}
	for i, r := range p.Replicas {
		for _, name := range []string{r.InstanceParameter, r.IdentitySecretARNParameter, r.IdentitySecretVersionParameter, r.PublisherIdentityIDParameter} {
			if _, ok := template.Parameters[name]; !ok {
				t.Fatal("missing replica parameter", name)
			}
		}
		if r.Key != fmt.Sprintf("replica-%d", i+1) {
			t.Fatal("unstable key")
		}
	}
	if _, err := b.Manifest.FindPublisher("missing"); err == nil {
		t.Fatal("missing publisher accepted")
	}
}

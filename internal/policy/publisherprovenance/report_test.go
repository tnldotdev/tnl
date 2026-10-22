package publisherprovenance

import (
	"crypto/ed25519"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/security/publisherproof"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func testReport() controlv1.PublisherDeploymentReport {
	return controlv1.PublisherDeploymentReport{DeploymentId: "aws-" + strings.Repeat("a", 40), Provider: "aws", ReplicaKey: "replica-1", Instance: "aws-replica", Image: "ghcr.io/tnldotdev/tnl@sha256:" + strings.Repeat("a", 64), SoftwareVersion: "v1.2.3", TemplateVersion: "2", TemplateSha256: strings.Repeat("b", 64)}
}

func TestPublisherDeploymentEnvironmentIsOptionalAndBounded(t *testing.T) {
	values := map[string]string{}
	lookup := func(key string) (string, bool) { value, ok := values[key]; return value, ok }
	if r, err := ReadEnvironment(lookup, "instance", "devel"); err != nil || r != nil {
		t.Fatal("absent deployment metadata changed runtime", err)
	}
	values[DeploymentIDEnv] = "private-invalid-value"
	if _, err := ReadEnvironment(lookup, "instance", "devel"); !errors.Is(err, ErrInvalid) {
		t.Fatal("partial metadata accepted", err)
	} else {
		reason, _ := failure.ReasonOf(err)
		if reason != failure.PublisherDeploymentMetadataInvalid || strings.Contains(err.Error(), values[DeploymentIDEnv]) {
			t.Fatal("unsafe environment failure")
		}
	}
	expected := testReport()
	values = map[string]string{DeploymentIDEnv: expected.DeploymentId, ProviderEnv: "aws", ReplicaKeyEnv: expected.ReplicaKey, ImageEnv: expected.Image, TemplateVersionEnv: expected.TemplateVersion, TemplateSHA256Env: expected.TemplateSha256}
	r, err := ReadEnvironment(lookup, expected.Instance, expected.SoftwareVersion)
	if err != nil || *r != expected {
		t.Fatal("environment did not retain exact report", err)
	}
	for name := range values {
		original := values[name]
		values[name] = ""
		if _, err := ReadEnvironment(lookup, expected.Instance, expected.SoftwareVersion); err == nil {
			t.Fatal("empty metadata accepted", name)
		}
		values[name] = original
	}
	for _, bad := range []string{"user:password@registry.example/publisher@sha256:" + strings.Repeat("a", 64), "ghcr.io/tnldotdev/tnl:latest", strings.Repeat("x", 513), "secret\nvalue"} {
		copy := expected
		copy.Image = bad
		if Validate(&copy) == nil {
			t.Fatal("unsafe image accepted")
		}
	}
}

func TestPublisherDeploymentProofBindsEveryFieldAndPresence(t *testing.T) {
	public, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	r := testReport()
	now := time.Now()
	scope := func(report *controlv1.PublisherDeploymentReport) string {
		return publisherproof.RuntimeScope("group", "start", strings.Repeat("a", 32), 7, Digest(report))
	}
	proof, err := publisherproof.Sign("publisher", "key", scope(&r), "https://control.example/v1/publisher-runtime", private, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := publisherproof.Verify(proof, "publisher", "key", scope(&r), "https://control.example/v1/publisher-runtime", public, now); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*controlv1.PublisherDeploymentReport){
		func(r *controlv1.PublisherDeploymentReport) { r.DeploymentId = "another" },
		func(r *controlv1.PublisherDeploymentReport) { r.Provider = "other" },
		func(r *controlv1.PublisherDeploymentReport) { r.ReplicaKey = "replica-2" },
		func(r *controlv1.PublisherDeploymentReport) { r.Instance = "another" },
		func(r *controlv1.PublisherDeploymentReport) {
			r.Image = "ghcr.io/tnldotdev/tnl@sha256:" + strings.Repeat("c", 64)
		},
		func(r *controlv1.PublisherDeploymentReport) { r.SoftwareVersion = "v9" },
		func(r *controlv1.PublisherDeploymentReport) { r.TemplateVersion = "3" },
		func(r *controlv1.PublisherDeploymentReport) { r.TemplateSha256 = strings.Repeat("c", 64) },
	} {
		copy := r
		change(&copy)
		if _, err := publisherproof.Verify(proof, "publisher", "key", scope(&copy), "https://control.example/v1/publisher-runtime", public, now); err == nil {
			t.Fatal("unsigned metadata mutation accepted")
		}
	}
	if _, err := publisherproof.Verify(proof, "publisher", "key", scope(nil), "https://control.example/v1/publisher-runtime", public, now); err == nil {
		t.Fatal("metadata stripped from signed proof")
	}
}

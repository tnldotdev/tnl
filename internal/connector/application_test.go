package connector

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/client/credentialfile"
	"github.com/tnldotdev/tnl/internal/client/project/workloadmanifest"
	"github.com/tnldotdev/tnl/internal/config"
	connectorruntime "github.com/tnldotdev/tnl/internal/connector/runtime"
	"github.com/tnldotdev/tnl/internal/testutil/workloadfixture"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func sdkApplicationFixture(t *testing.T, f *sdkFixture) {
	t.Helper()
	documents := map[string]credentialfile.File{}
	f.operations.application = func(ctx context.Context, owner connectorruntime.Status, assertion string) (connectorruntime.PreparedApplication, error) {
		visitor, err := f.operations.prepare(ctx, owner, "db", assertion)
		if err != nil {
			return connectorruntime.PreparedApplication{}, err
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		document, ok := documents[owner.ConnectionHandle]
		if !ok {
			_, key, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				return connectorruntime.PreparedApplication{}, err
			}
			application := workloadfixture.Application("job", "team", []string{"svc_" + strings.Repeat("S", 22)})
			application.Grants[0].Operation = controlv1.ApplicationPublish
			document, err = credentialfile.NewApplication("https://control.example", application, key)
			if err != nil {
				return connectorruntime.PreparedApplication{}, err
			}
			documents[owner.ConnectionHandle] = document
		}
		return connectorruntime.PreparedApplication{Schema: 1, Credential: document, SourceSessionID: "wls_" + sdkDigest(owner.ConnectionHandle)[:22], LeaseExpiresAt: time.Now().Add(90 * time.Second), Verification: visitor.Verification}, nil
	}
}

func TestConnectionSDKApplicationSharesVisitorOwnerAndIsolatesBindings(t *testing.T) {
	f := newSDKFixture(t, true)
	sdkApplicationFixture(t, f)
	options := f.options
	options.Service = ""
	first, err := f.operations.selectSDKApplication(t.Context(), options, "first")
	if err != nil {
		t.Fatal(err)
	}
	visitor, err := f.prepare(t.Context(), "first", "db")
	if err != nil || visitor.Owner.ConnectionHandle != first.Owner.ConnectionHandle || f.started != 1 || f.identified != 1 {
		t.Fatal("visitor and publisher acquired different source owners", err)
	}
	rotated, err := f.operations.selectSDKApplication(t.Context(), options, "rotated")
	if err != nil || rotated.Owner.ConnectionHandle != first.Owner.ConnectionHandle || rotated.Application.Credential.PrivateKey != first.Application.Credential.PrivateKey {
		t.Fatal("proof rotation replaced source signing key", err)
	}
	other, err := f.operations.selectSDKApplication(t.Context(), options, "other")
	if err != nil || other.Owner.ConnectionHandle == first.Owner.ConnectionHandle || other.Application.Credential.PrivateKey == first.Application.Credential.PrivateKey {
		t.Fatal("independent identity inherited source authority", err)
	}
	again, err := f.operations.selectSDKApplication(t.Context(), options, "first")
	if err != nil || again.Owner.ConnectionHandle != first.Owner.ConnectionHandle || f.started != 2 {
		t.Fatal("A/B/A lost retained source ownership", err)
	}
	data, err := os.ReadFile(filepath.Join(options.Registry, "registry.json"))
	if err != nil || strings.Contains(string(data), first.Application.Credential.PrivateKey) || strings.Contains(string(data), `"credential"`) {
		t.Fatal("registry persisted application credentials", err)
	}
	if err := f.operations.stopSDK(t.Context(), options); err != nil {
		t.Fatal(err)
	}
	if _, err := f.operations.selectSDKApplication(t.Context(), options, "first"); !errors.Is(err, connectorruntime.ErrExpired) {
		t.Fatal("closed scope minted new application credentials", err)
	}
}

func TestConnectionSDKApplicationRequiresWorkloadAndRetainsFailureOwner(t *testing.T) {
	f := newSDKFixture(t, false)
	sdkApplicationFixture(t, f)
	options := f.options
	options.Service = ""
	if _, err := f.operations.selectSDKApplication(t.Context(), options, ""); !errors.Is(err, connectorruntime.ErrUnauthorized) || f.started != 0 {
		t.Fatal("application acquisition used personal authority", err)
	}
	f.options.Workload = "job"
	options = f.options
	options.Service = ""
	f.prepareError = connectorruntime.ErrUnavailable
	if _, err := f.operations.selectSDKApplication(t.Context(), options, "first"); !errors.Is(err, connectorruntime.ErrUnavailable) || f.started != 1 || f.stopped != 0 {
		t.Fatal("failed application acquisition lost its cleanup owner", err)
	}
	f.prepareError = nil
	if _, err := f.operations.selectSDKApplication(t.Context(), options, "first"); err != nil || f.started != 1 {
		t.Fatal("application retry replaced retained source", err)
	}
}

func TestConnectionSDKPublishOnlyManifestAcquiresIdentityWithoutAVisitor(t *testing.T) {
	f, write := sdkWorkloadFixture(t, "github", workloadmanifest.Acquisition{Method: "github-actions", Audience: "https://control.example"})
	sdkApplicationFixture(t, f)
	write(workloadmanifest.Workload{Provider: "github", Grants: config.WorkloadGrants{Publish: []config.WorkloadResource{{PublicURL: new("preview.example.test")}}}, Acquisition: workloadmanifest.Acquisition{Method: "github-actions", Audience: "https://control.example"}})
	selected, err := workloadmanifest.Select(f.options.Directory, "job", "", workloadmanifest.Runtime{})
	if err != nil {
		t.Fatal(err)
	}
	options := f.options
	options.Service = ""
	options.WorkloadSelection = &connectorruntime.SDKWorkloadRequest{Name: "job", Callback: true}
	options.WorkloadPolicy = selected.Policy
	prepared, err := f.operations.selectSDKApplication(t.Context(), options, "first")
	if err != nil || prepared.Application.Credential.ClientID == "" || f.started != 1 {
		t.Fatal("publish-only identity required visitor preparation", err)
	}
}

func TestConnectionApplicationBackendPreparesOnlyItsRetainedSource(t *testing.T) {
	b := connectionBackendFixture(t, func(w http.ResponseWriter, r *http.Request, s authorityv1.WorkloadSession) { w.WriteHeader(204) })
	session, err := b.workload.Session()
	if err != nil {
		t.Fatal(err)
	}
	b.rememberAssertion("first", session.IdentityExpiresAt, session)
	first, err := b.PrepareApplication(t.Context(), "first")
	if err != nil || first.SourceSessionID != session.Id || first.Validate() != nil {
		t.Fatal("retained source was not prepared", err)
	}
	key, err := first.Credential.Validate()
	if err != nil || !b.workload.PublicKey().Equal(key.Public()) {
		t.Fatal("prepared source replaced its key", err)
	}
	metadata, err := json.Marshal(b.ProjectRuntime())
	if err != nil || strings.Contains(string(metadata), first.Credential.PrivateKey) {
		t.Fatal("public metadata contains source key", err)
	}
	*first.Credential.Grants[0].ServiceID = "mutated"
	again, err := b.PrepareApplication(t.Context(), "")
	if err != nil || *again.Credential.Grants[0].ServiceID == "mutated" {
		t.Fatal("returned document mutated retained source", err)
	}
	b.mu.Lock()
	b.closed = true
	b.mu.Unlock()
	if _, err := b.PrepareApplication(t.Context(), "first"); !errors.Is(err, connectorruntime.ErrExpired) {
		t.Fatal("closed source minted credentials", err)
	}
}

package credentialfile

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"

	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type deploymentVerifierFunc func(context.Context, controlv1.DeploymentPublisherIdentity, ed25519.PrivateKey) (controlv1.DeploymentPublisherVerification, error)

func (f deploymentVerifierFunc) Verify(ctx context.Context, m controlv1.DeploymentPublisherIdentity, k ed25519.PrivateKey) (controlv1.DeploymentPublisherVerification, error) {
	return f(ctx, m, k)
}

func TestDeploymentIdentityRenameRequiresAuthorityAndKeepsDurableIdentity(t *testing.T) {
	old := deploymentFixture(t)
	key, _ := old.Validate(old.ControlURL, old.Member.ProjectKey, old.Member.DeploymentName, old.Instance)
	current := old.Member
	current.DeploymentName = "live"
	verify := deploymentVerifierFunc(func(_ context.Context, m controlv1.DeploymentPublisherIdentity, k ed25519.PrivateKey) (controlv1.DeploymentPublisherVerification, error) {
		if !SameDeploymentIdentity(m, current) || !bytes.Equal(key, k) {
			return controlv1.DeploymentPublisherVerification{}, ErrInvalid
		}
		return controlv1.DeploymentPublisherVerification{Member: current, DeploymentNames: []string{"production", "live"}}, nil
	})
	durable := filepath.Join(t.TempDir(), "identity")
	for iteration, selector := range []string{"production", "live", "production"} {
		state, err := clientstate.OpenWithOptions(t.Context(), filepath.Join(t.TempDir(), "sqlite"), clientstate.OpenOptions{Protection: clientstate.ProtectionFile})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = state.Close() })
		profile, err := state.Server(t.Context(), old.ControlURL)
		if err != nil {
			t.Fatal(err)
		}
		profile, err = profile.WithIdentityDirectory(durable)
		if err != nil {
			t.Fatal(err)
		}
		if iteration == 0 {
			if err := RetainDeployment(t.Context(), profile, old); err != nil {
				t.Fatal(err)
			}
			if _, err := ImportDeployment(t.Context(), profile, old, old.ControlURL, old.Member.ProjectKey, "production", old.Instance); err != nil {
				t.Fatal(err)
			}
		}
		value, found, err := ResolveSavedDeployment(t.Context(), profile, verify, old.ControlURL, old.Member.ProjectKey, selector, old.Instance)
		if err != nil || !found || value.Member != current {
			t.Fatal("durable identity did not follow authority", found, err)
		}
		if err := RetainDeployment(t.Context(), profile, value); err != nil {
			t.Fatal(err)
		}
		if _, err := ImportDeployment(t.Context(), profile, value, old.ControlURL, old.Member.ProjectKey, selector, old.Instance); err != nil {
			t.Fatal(err)
		}
		saved, found, err := profile.SelectedPublisherIdentity(t.Context(), "project", DeploymentSelection(old.Member.ProjectKey, current.DeploymentId, old.Instance))
		var member controlv1.DeploymentPublisherIdentity
		if err != nil || !found || !bytes.Equal(saved.SigningKey, key) || json.Unmarshal(saved.PublicDocument, &member) != nil || member != current {
			t.Fatal("document and sealed key context were not updated together", err)
		}
		if _, err := ResolveDeployment(t.Context(), verify, old, old.ControlURL, old.Member.ProjectKey, "unrelated", old.Instance); !errors.Is(err, ErrInvalid) {
			t.Fatal("unverified selector accepted", err)
		}
		forged := deploymentFixture(t)
		forged.Member, forged.Instance = current, old.Instance
		if _, err := ImportDeployment(t.Context(), profile, forged, old.ControlURL, old.Member.ProjectKey, selector, old.Instance); !errors.Is(err, clientstate.ErrPublisherStateConflict) {
			t.Fatal("replaced signing key", err)
		}
		if err := RetainDeployment(t.Context(), profile, forged); !errors.Is(err, clientstate.ErrPublisherStateConflict) {
			t.Fatal("replaced durable key", err)
		}
	}
}

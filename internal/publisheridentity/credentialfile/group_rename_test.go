package credentialfile

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"

	"github.com/tnldotdev/tnl/internal/clientstate"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

type groupVerifierFunc func(context.Context, controlv1.PublisherGroupMember, ed25519.PrivateKey) (controlv1.PublisherGroupVerification, error)

func (f groupVerifierFunc) Verify(ctx context.Context, m controlv1.PublisherGroupMember, k ed25519.PrivateKey) (controlv1.PublisherGroupVerification, error) {
	return f(ctx, m, k)
}

func TestGroupIdentityRenameRequiresAuthorityAndKeepsDurableIdentity(t *testing.T) {
	old := groupFixture(t)
	key, _ := old.Validate(old.ControlURL, old.Member.ProjectKey, old.Member.GroupName, old.Instance)
	current := old.Member
	current.GroupName = "live"
	verify := groupVerifierFunc(func(_ context.Context, m controlv1.PublisherGroupMember, k ed25519.PrivateKey) (controlv1.PublisherGroupVerification, error) {
		if !SameGroupIdentity(m, current) || !bytes.Equal(key, k) {
			return controlv1.PublisherGroupVerification{}, ErrInvalid
		}
		return controlv1.PublisherGroupVerification{Member: current, GroupNames: []string{"production", "live"}}, nil
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
			if err := RetainGroup(t.Context(), profile, old); err != nil {
				t.Fatal(err)
			}
			if _, err := ImportGroup(t.Context(), profile, old, old.ControlURL, old.Member.ProjectKey, "production", old.Instance); err != nil {
				t.Fatal(err)
			}
		}
		value, found, err := ResolveSavedGroup(t.Context(), profile, verify, old.ControlURL, old.Member.ProjectKey, selector, old.Instance)
		if err != nil || !found || value.Member != current {
			t.Fatal("durable identity did not follow authority", found, err)
		}
		if err := RetainGroup(t.Context(), profile, value); err != nil {
			t.Fatal(err)
		}
		if _, err := ImportGroup(t.Context(), profile, value, old.ControlURL, old.Member.ProjectKey, selector, old.Instance); err != nil {
			t.Fatal(err)
		}
		saved, found, err := profile.SelectedPublisherIdentity(t.Context(), "project", GroupSelection(old.Member.ProjectKey, current.GroupId, old.Instance))
		var member controlv1.PublisherGroupMember
		if err != nil || !found || !bytes.Equal(saved.SigningKey, key) || json.Unmarshal(saved.PublicDocument, &member) != nil || member != current {
			t.Fatal("document and sealed key context were not updated together", err)
		}
		if _, err := ResolveGroup(t.Context(), verify, old, old.ControlURL, old.Member.ProjectKey, "unrelated", old.Instance); !errors.Is(err, ErrInvalid) {
			t.Fatal("unverified selector accepted", err)
		}
		forged := groupFixture(t)
		forged.Member, forged.Instance = current, old.Instance
		if _, err := ImportGroup(t.Context(), profile, forged, old.ControlURL, old.Member.ProjectKey, selector, old.Instance); !errors.Is(err, clientstate.ErrPublisherStateConflict) {
			t.Fatal("replaced signing key", err)
		}
		if err := RetainGroup(t.Context(), profile, forged); !errors.Is(err, clientstate.ErrPublisherStateConflict) {
			t.Fatal("replaced durable key", err)
		}
	}
}

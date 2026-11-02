package identity

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"

	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/publisher/identity/credentialfile"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
)

var ErrSetupRequired = errors.New("no namespace publisher is set up; run tnl publisher setup --namespace")

func namespaceScope(team, domain string) string {
	digest := sha256.Sum256([]byte(team + "\x00" + domain))
	return "owner-namespace:" + hex.EncodeToString(digest[:])
}

func matchesNamespace(i authorityv1.PublisherEnrollmentResult, team, domain, namespace string) bool {
	return i.Kind == authorityv1.Namespace && i.TeamId == team && i.DomainId != nil && *i.DomainId == domain && i.Namespace != nil && *i.Namespace == namespace && i.PublicUrlId == nil
}

// LoadLocalNamespace never issues grants. it verifies the saved scope and
// checks the live grant before returning an adapter for an ad-hoc worker.
func LoadLocalNamespace(ctx context.Context, state *clientstate.Store, control NativeControl, authority AssertionExchanger, team, domain, namespace string) (*Native, error) {
	if state == nil || team == "" || domain == "" || namespace == "" {
		return nil, ErrScope
	}
	saved, found, err := state.SelectedPublisherIdentity(ctx, "namespace", namespaceScope(team, domain))
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, ErrSetupRequired
	}
	var identity authorityv1.PublisherEnrollmentResult
	if json.Unmarshal(saved.PublicDocument, &identity) != nil || !matchesNamespace(identity, team, domain, namespace) || identity.ClientId != saved.ID {
		return nil, ErrScope
	}
	n, _, err := LoadNative(ctx, state, control, authority, identity.ClientId)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(n.private, saved.SigningKey) {
		return nil, ErrScope
	}
	if _, err := n.Access(ctx); err != nil {
		return nil, err
	}
	return n, nil
}

// LoadDefaultNamespace reads the identity selected by the last explicit local
// setup. publication never consults a person's control session to choose it.
func LoadDefaultNamespace(ctx context.Context, state *clientstate.Store, control NativeControl, authority AssertionExchanger) (*Native, error) {
	if state == nil {
		return nil, ErrScope
	}
	saved, found, err := state.SelectedPublisherIdentity(ctx, "default_namespace", "")
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, ErrSetupRequired
	}
	var identity authorityv1.PublisherEnrollmentResult
	if json.Unmarshal(saved.PublicDocument, &identity) != nil || identity.ClientId != saved.ID || identity.DomainId == nil || identity.Namespace == nil || !matchesNamespace(identity, identity.TeamId, *identity.DomainId, *identity.Namespace) {
		return nil, ErrScope
	}
	n, _, err := LoadNative(ctx, state, control, authority, identity.ClientId)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(n.private, saved.SigningKey) {
		return nil, ErrScope
	}
	if _, err := n.Access(ctx); err != nil {
		return nil, err
	}
	return n, nil
}

func saveDefaultNamespace(ctx context.Context, state *clientstate.Store, identity authorityv1.PublisherEnrollmentResult) error {
	_, found, err := state.PublisherIdentity(ctx, identity.ClientId)
	if err != nil {
		return err
	}
	if !found {
		return ErrScope
	}
	return state.SelectPublisherIdentity(ctx, "default_namespace", "", identity.ClientId)
}

// EnsureNamespace is called only by explicit local setup. a pending enrollment
// survives a lost redemption reply, so a retry uses the same signing key.
func EnsureNamespace(ctx context.Context, state *clientstate.Store, control OwnerControl, authority EnrollmentAuthority, team, domain, namespace string) (*Native, authorityv1.PublisherEnrollmentResult, error) {
	if state == nil || team == "" || domain == "" || namespace == "" {
		return nil, authorityv1.PublisherEnrollmentResult{}, ErrScope
	}
	return ensureSelectedEnrollment(ctx, state, control, authority, enrollmentSelection{kind: "namespace", team: team, id: domain, namespace: namespace})
}

// LoadFile uses only a portable signing key. an explicit server must match the
// exact recorded control URL; invalid files never fall back to a login session.
func LoadFile(path, server string, control NativeControl, authority AssertionExchanger) (*Native, error) {
	f, err := credentialfile.Read(path)
	if err != nil {
		return nil, err
	}
	if server == "" || f.ControlURL != server {
		return nil, ErrScope
	}
	if selected, ok := control.(interface{ ControlURL() string }); ok && selected.ControlURL() != f.ControlURL {
		return nil, ErrScope
	}
	i, key, err := f.Validate()
	if err != nil {
		return nil, err
	}
	return NewNative(control, authority, i, key)
}

// ResolveAdHoc selects one scoped identity for tnl.open and app-owned HTTP
// publication. explicit selection wins over the local developer default; a
// configured file always wins over that default and fails closed on errors.
func ResolveAdHoc(ctx context.Context, state *clientstate.Store, control NativeControl, authority EnrollmentAuthority, server, team, domain, namespace, publisherCredentialFile, enrollmentKey, publisherIdentityID string, adapter *Native) (*Native, error) {
	if publisherCredentialFile == "" && enrollmentKey == "" && publisherIdentityID == "" && adapter == nil {
		if configured, present := os.LookupEnv("TNL_PUBLISHER_CREDENTIAL_FILE"); present {
			if configured == "" {
				return nil, credentialfile.ErrInvalid
			}
			publisherCredentialFile = configured
		}
	}
	if publisherCredentialFile != "" {
		if enrollmentKey != "" || publisherIdentityID != "" || adapter != nil {
			return nil, ErrSelection
		}
		n, err := LoadFile(publisherCredentialFile, server, control, authority)
		if err != nil {
			return nil, err
		}
		if err := n.NamespaceScope(); err != nil {
			return nil, err
		}
		if _, err := n.Access(ctx); err != nil {
			return nil, err
		}
		return n, nil
	}
	if enrollmentKey != "" || publisherIdentityID != "" || adapter != nil {
		n, err := Resolve(ctx, state, control, authority, enrollmentKey, publisherIdentityID, adapter)
		if err != nil {
			return nil, err
		}
		if err := n.NamespaceScope(); err != nil {
			return nil, err
		}
		if n.ControlURL() != server {
			return nil, ErrScope
		}
		return n, nil
	}
	if team == "" && domain == "" && namespace == "" {
		return LoadDefaultNamespace(ctx, state, control, authority)
	}
	return LoadLocalNamespace(ctx, state, control, authority, team, domain, namespace)
}

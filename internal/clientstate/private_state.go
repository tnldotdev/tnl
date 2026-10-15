package clientstate

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/tnldotdev/tnl/internal/opaqueid"
)

// PublisherSigningIdentity adapts existing native publisher callers to the v1
// identity, pending enrollment, and selection records. keys live in one row.
type PublisherSigningIdentity struct {
	ID           string `json:"identity_id"`
	PublicValue  []byte `json:"public_value"`
	PrivateValue []byte `json:"-"`
}

func publisherSelectionScope(scope string) (kind, key string, ok bool) {
	if scope == "default-namespace" {
		return "default_namespace", "", true
	}
	for _, selected := range []struct{ prefix, kind string }{
		{"owner-namespace:", "namespace"}, {"owner-url:", "project"},
		{"project-publisher:", "project"}, {"job:", "job"},
	} {
		if strings.HasPrefix(scope, selected.prefix) && len(scope) > len(selected.prefix) {
			return selected.kind, scope, true
		}
	}
	return "", "", false
}

func savedSigningIdentity(identity PublisherIdentity) PublisherSigningIdentity {
	return PublisherSigningIdentity{ID: identity.ID, PublicValue: identity.PublicDocument, PrivateValue: identity.SigningKey}
}

func (s *Store) PublisherSigningIdentity(ctx context.Context, scope string) (PublisherSigningIdentity, bool, error) {
	if id, ok := strings.CutPrefix(scope, "publisher:"); ok {
		identity, found, err := s.PublisherIdentity(ctx, id)
		return savedSigningIdentity(identity), found, err
	}
	if id, ok := strings.CutPrefix(scope, "enrollment:"); ok {
		pending, found, err := s.PendingPublisherEnrollment(ctx, id)
		if err != nil || !found {
			return PublisherSigningIdentity{}, found, err
		}
		result := pending.ResultJSON
		if len(result) == 0 {
			result = []byte("{}")
		}
		return PublisherSigningIdentity{ID: id, PublicValue: result, PrivateValue: pending.SigningKey}, true, nil
	}
	kind, key, ok := publisherSelectionScope(scope)
	if !ok {
		return PublisherSigningIdentity{}, false, errors.New("clientstate: invalid publisher identity scope")
	}
	identity, found, err := s.SelectedPublisherIdentity(ctx, kind, key)
	if err != nil || found || kind == "default_namespace" {
		return savedSigningIdentity(identity), found, err
	}
	pending, found, err := s.PendingPublisherEnrollmentForSelection(ctx, kind, key)
	if err != nil || !found {
		return PublisherSigningIdentity{}, found, err
	}
	result := pending.ResultJSON
	if len(result) == 0 {
		result = []byte("{}")
	}
	return PublisherSigningIdentity{ID: pending.EnrollmentID, PublicValue: result, PrivateValue: pending.EnrollmentSecret}, true, nil
}

func (s *Store) SavePublisherSigningIdentity(ctx context.Context, scope string, value PublisherSigningIdentity) error {
	if !validOpaqueValue(value.ID, 256) || len(value.PublicValue) == 0 || len(value.PublicValue) > 65536 ||
		len(value.PrivateValue) == 0 || len(value.PrivateValue) > 65536 {
		return errors.New("clientstate: invalid publisher signing identity")
	}
	if id, ok := strings.CutPrefix(scope, "publisher:"); ok {
		if id != value.ID {
			return ErrPublisherStateConflict
		}
		return s.ImportPublisherIdentity(ctx, PublisherIdentity{ID: id, PublicDocument: value.PublicValue, SigningKey: value.PrivateValue})
	}
	if id, ok := strings.CutPrefix(scope, "enrollment:"); ok {
		if !opaqueid.Valid(id, opaqueid.PublisherEnrollmentPrefix) || len(value.PrivateValue) != ed25519.PrivateKeySize {
			return ErrPublisherStateConflict
		}
		if value.ID == id {
			pending, found, err := s.PendingPublisherEnrollment(ctx, id)
			if err != nil {
				return err
			}
			if found {
				if !bytes.Equal(pending.SigningKey, value.PrivateValue) {
					return ErrPublisherStateConflict
				}
				return nil
			}
			return s.SavePendingPublisherEnrollment(ctx, PendingPublisherEnrollment{
				EnrollmentID: id, SelectionKind: "explicit", SelectionKey: id,
				PublicKey:  ed25519.PrivateKey(value.PrivateValue).Public().(ed25519.PublicKey),
				SigningKey: value.PrivateValue, ExpiresAt: time.Now().Add(10 * time.Minute),
			})
		}
		if err := s.RecordPublisherEnrollmentResult(ctx, id, value.PublicValue); err != nil {
			return err
		}
		return s.PromotePublisherEnrollment(ctx, id, PublisherIdentity{ID: value.ID, PublicDocument: value.PublicValue, SigningKey: value.PrivateValue})
	}
	kind, key, ok := publisherSelectionScope(scope)
	if !ok {
		return errors.New("clientstate: invalid publisher identity scope")
	}
	if opaqueid.Valid(value.ID, opaqueid.PublisherEnrollmentPrefix) {
		if kind == "default_namespace" || !strings.HasPrefix(string(value.PrivateValue), value.ID+".") {
			return ErrPublisherStateConflict
		}
		if pending, found, err := s.PendingPublisherEnrollmentForSelection(ctx, kind, key); err != nil {
			return err
		} else if found {
			if pending.EnrollmentID != value.ID || !bytes.Equal(pending.EnrollmentSecret, value.PrivateValue) {
				return ErrPublisherStateConflict
			}
			return nil
		}
		public, private, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return err
		}
		return s.SavePendingPublisherEnrollment(ctx, PendingPublisherEnrollment{
			EnrollmentID: value.ID, SelectionKind: kind, SelectionKey: key,
			PublicKey: public, SigningKey: private, EnrollmentSecret: value.PrivateValue,
			ExpiresAt: time.Now().Add(10 * time.Minute),
		})
	}
	if !json.Valid(value.PublicValue) {
		return ErrPublisherStateConflict
	}
	if err := s.ImportPublisherIdentity(ctx, PublisherIdentity{ID: value.ID, PublicDocument: value.PublicValue, SigningKey: value.PrivateValue}); err != nil {
		return err
	}
	return s.SelectPublisherIdentity(ctx, kind, key, value.ID)
}

func (s *Store) RemovePublisherSigningIdentity(ctx context.Context, scope string) error {
	if id, ok := strings.CutPrefix(scope, "publisher:"); ok {
		return s.RemovePublisherIdentity(ctx, id)
	}
	if id, ok := strings.CutPrefix(scope, "enrollment:"); ok {
		return s.RemovePendingPublisherEnrollment(ctx, id)
	}
	kind, key, ok := publisherSelectionScope(scope)
	if !ok {
		return errors.New("clientstate: invalid publisher identity scope")
	}
	if kind != "default_namespace" {
		pending, found, err := s.PendingPublisherEnrollmentForSelection(ctx, kind, key)
		if err != nil {
			return err
		}
		if found {
			return s.RemovePendingPublisherEnrollment(ctx, pending.EnrollmentID)
		}
	}
	return s.RemovePublisherSelection(ctx, kind, key)
}

// SystemState exposes the two named protected system-job documents while their
// owner moves to the dedicated registry and manifest calls.
func (d *Database) SystemState(ctx context.Context, name string) ([]byte, bool, error) {
	switch name {
	case "publisher-jobs-v1":
		return d.PublisherJobRegistry(ctx)
	case "publisher-jobs-files-v1":
		return d.PublisherJobFileManifest(ctx)
	default:
		return nil, false, errors.New("clientstate: unsupported system state name")
	}
}

func (d *Database) SaveSystemState(ctx context.Context, name string, value []byte) error {
	switch name {
	case "publisher-jobs-v1":
		return d.SavePublisherJobRegistry(ctx, value)
	case "publisher-jobs-files-v1":
		return d.SavePublisherJobFileManifest(ctx, value)
	default:
		return errors.New("clientstate: unsupported system state name")
	}
}

func (d *Database) RemoveSystemState(ctx context.Context, name string) error {
	switch name {
	case "publisher-jobs-v1":
		return d.queries.DeletePublisherJobRegistry(ctx)
	case "publisher-jobs-files-v1":
		return d.queries.DeletePublisherJobFileManifest(ctx)
	default:
		return errors.New("clientstate: unsupported system state name")
	}
}

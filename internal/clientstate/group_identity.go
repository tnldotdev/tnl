package clientstate

import (
	"context"
	"crypto/ed25519"
	"crypto/subtle"
	"database/sql"
	"encoding/json"
	"errors"

	"github.com/tnldotdev/tnl/internal/clientstate/clientstatedb"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

// ImportPublisherGroupIdentity updates the public document and its authenticated
// encryption context together. callers first verify current membership with
// control. only the display selector may change; neither identity nor key may.
func (s *Store) ImportPublisherGroupIdentity(ctx context.Context, member controlv1.PublisherGroupMember, key ed25519.PrivateKey, selection string) error {
	if member.PublisherIdentityId == "" || member.GroupId == "" || len(key) != ed25519.PrivateKeySize || !validPublisherSelection("project", selection) {
		return ErrPublisherStateConflict
	}
	document, err := json.Marshal(member)
	if err != nil {
		return err
	}
	tx, err := s.database.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	q := s.database.queries.WithTx(tx)
	old, err := q.GetPublisherIdentity(ctx, clientstatedb.GetPublisherIdentityParams{ServerOrigin: s.controlEndpoint, IdentityID: member.PublisherIdentityId})
	if err == nil {
		var previous controlv1.PublisherGroupMember
		if json.Unmarshal([]byte(old.PublicDocumentJson), &previous) != nil {
			return ErrPublisherStateConflict
		}
		previous.GroupName = member.GroupName
		stored, err := s.secrets.Open(ctx, publisherKeyContext(member.PublisherIdentityId, []byte(old.PublicDocumentJson)), old.SigningKeyCiphertext)
		if err != nil || previous != member || subtle.ConstantTimeCompare(stored, key) != 1 {
			return ErrPublisherStateConflict
		}
	} else if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	selected, err := q.GetSelectedPublisherIdentity(ctx, clientstatedb.GetSelectedPublisherIdentityParams{ServerOrigin: s.controlEndpoint, SelectionKind: "project", SelectionKey: selection, Now: sql.NullInt64{Int64: s.database.now().UnixNano(), Valid: true}})
	if err == nil && selected.IdentityID != member.PublisherIdentityId {
		return ErrPublisherStateConflict
	} else if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	sealed, err := s.secrets.Seal(ctx, publisherKeyContext(member.PublisherIdentityId, document), key)
	if err != nil {
		return err
	}
	now := s.database.now().UTC().UnixNano()
	if _, err := tx.ExecContext(ctx, `INSERT INTO publisher_identities(server_origin,identity_id,public_document_json,signing_key_ciphertext,updated_at) VALUES(?,?,?,?,?) ON CONFLICT(server_origin,identity_id) DO UPDATE SET public_document_json=excluded.public_document_json,signing_key_ciphertext=excluded.signing_key_ciphertext,updated_at=excluded.updated_at`, s.controlEndpoint, member.PublisherIdentityId, string(document), sealed, now); err != nil {
		return err
	}
	if err := q.SelectPublisherIdentity(ctx, clientstatedb.SelectPublisherIdentityParams{ServerOrigin: s.controlEndpoint, SelectionKind: "project", SelectionKey: selection, IdentityID: member.PublisherIdentityId, UpdatedAt: now}); err != nil {
		return err
	}
	return tx.Commit()
}

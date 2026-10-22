package clientstate

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/tnldotdev/tnl/internal/clientstate/clientstatedb"
)

// PendingPublisherEnrollment keeps one key across an interrupted one-use
// redemption. the secret is present only when local setup must retry issuance.
type PendingPublisherEnrollment struct {
	EnrollmentID     string
	SelectionKind    string
	SelectionKey     string
	PublicKey        []byte
	SigningKey       []byte
	EnrollmentSecret []byte
	ResultJSON       []byte
	ExpiresAt        time.Time
}

type PublisherIdentity struct {
	ID             string
	PublicDocument []byte
	SigningKey     []byte
}

// PublisherSelection names a local use of an installed identity. its key is
// opaque to persistence and keeps the caller's existing selection encoding.
type PublisherSelection struct {
	Kind string
	Key  string
}

var ErrPublisherStateConflict = errors.New("clientstate: publisher identity or enrollment changed")

func pendingKeyContext(id string) string    { return "publisher-enrollment:" + id + ":key" }
func pendingSecretContext(id string) string { return "publisher-enrollment:" + id + ":secret" }
func publisherKeyContext(id string, document []byte) string {
	digest := sha256.Sum256(document)
	return "publisher-identity:" + id + ":" + hex.EncodeToString(digest[:])
}

func validPublisherSelection(kind, key string) bool {
	if kind == "default_namespace" {
		return key == ""
	}
	if !validOpaqueValue(key, 1024) {
		return false
	}
	switch kind {
	case "namespace", "project", "job", "enrollment", "explicit":
		return true
	}
	return false
}

func (s *Store) SavePendingPublisherEnrollment(ctx context.Context, value PendingPublisherEnrollment) error {
	if !validOpaqueValue(value.EnrollmentID, 256) || !validPublisherSelection(value.SelectionKind, value.SelectionKey) ||
		value.SelectionKind == "default_namespace" || len(value.PublicKey) != 32 || len(value.SigningKey) == 0 || len(value.SigningKey) > 65536 ||
		len(value.EnrollmentSecret) > 256 || !value.ExpiresAt.After(s.database.now()) {
		return errors.New("clientstate: invalid pending publisher enrollment")
	}
	key, err := s.secrets.Seal(ctx, pendingKeyContext(value.EnrollmentID), value.SigningKey)
	if err != nil {
		return err
	}
	var secret []byte
	if len(value.EnrollmentSecret) != 0 {
		secret, err = s.secrets.Seal(ctx, pendingSecretContext(value.EnrollmentID), value.EnrollmentSecret)
		if err != nil {
			return err
		}
	}
	if err := s.database.queries.PruneExpiredPendingPublisherEnrollments(ctx, s.database.now().UTC().UnixNano()); err != nil {
		return err
	}
	if err := s.database.queries.SavePendingPublisherEnrollment(ctx, clientstatedb.SavePendingPublisherEnrollmentParams{
		ServerOrigin: s.controlEndpoint, EnrollmentID: value.EnrollmentID,
		SelectionKind: value.SelectionKind, SelectionKey: value.SelectionKey,
		PublicKey: value.PublicKey, SigningKeyCiphertext: key, EnrollmentSecretCiphertext: secret,
		ExpiresAt: value.ExpiresAt.UTC().UnixNano(), UpdatedAt: s.database.now().UTC().UnixNano(),
	}); err != nil {
		return fmt.Errorf("clientstate: save pending publisher enrollment: %w", err)
	}
	stored, found, err := s.PendingPublisherEnrollment(ctx, value.EnrollmentID)
	if err != nil {
		return err
	}
	if !found || stored.SelectionKind != value.SelectionKind || stored.SelectionKey != value.SelectionKey ||
		stored.ExpiresAt.UnixNano() != value.ExpiresAt.UnixNano() || !bytes.Equal(stored.PublicKey, value.PublicKey) ||
		subtle.ConstantTimeCompare(stored.SigningKey, value.SigningKey) != 1 ||
		subtle.ConstantTimeCompare(stored.EnrollmentSecret, value.EnrollmentSecret) != 1 {
		return ErrPublisherStateConflict
	}
	return nil
}

func (s *Store) PendingPublisherEnrollment(ctx context.Context, id string) (PendingPublisherEnrollment, bool, error) {
	if !validOpaqueValue(id, 256) {
		return PendingPublisherEnrollment{}, false, errors.New("clientstate: invalid publisher enrollment ID")
	}
	row, err := s.database.queries.GetPendingPublisherEnrollment(ctx, clientstatedb.GetPendingPublisherEnrollmentParams{
		ServerOrigin: s.controlEndpoint, EnrollmentID: id,
	})
	if errors.Is(err, sql.ErrNoRows) {
		return PendingPublisherEnrollment{}, false, nil
	}
	if err != nil {
		return PendingPublisherEnrollment{}, false, err
	}
	key, err := s.secrets.Open(ctx, pendingKeyContext(id), row.SigningKeyCiphertext)
	if err != nil {
		return PendingPublisherEnrollment{}, true, err
	}
	var secret []byte
	if len(row.EnrollmentSecretCiphertext) != 0 {
		secret, err = s.secrets.Open(ctx, pendingSecretContext(id), row.EnrollmentSecretCiphertext)
		if err != nil {
			return PendingPublisherEnrollment{}, true, err
		}
	}
	return PendingPublisherEnrollment{
		EnrollmentID: id, SelectionKind: row.SelectionKind, SelectionKey: row.SelectionKey,
		PublicKey: row.PublicKey, SigningKey: key, EnrollmentSecret: secret,
		ResultJSON: []byte(row.ResultJson.String),
		ExpiresAt:  time.Unix(0, row.ExpiresAt).UTC(),
	}, true, nil
}

func (s *Store) PendingPublisherEnrollmentForSelection(ctx context.Context, kind, key string) (PendingPublisherEnrollment, bool, error) {
	if !validPublisherSelection(kind, key) || kind == "default_namespace" {
		return PendingPublisherEnrollment{}, false, errors.New("clientstate: invalid pending publisher selection")
	}
	row, err := s.database.queries.GetPendingPublisherEnrollmentForSelection(ctx, clientstatedb.GetPendingPublisherEnrollmentForSelectionParams{
		ServerOrigin: s.controlEndpoint, SelectionKind: kind, SelectionKey: key,
	})
	if errors.Is(err, sql.ErrNoRows) {
		return PendingPublisherEnrollment{}, false, nil
	}
	if err != nil {
		return PendingPublisherEnrollment{}, false, err
	}
	return s.PendingPublisherEnrollment(ctx, row.EnrollmentID)
}

// RecordPublisherEnrollmentResult keeps a successful redemption recoverable
// even when the process stops before it can install the identity.
func (s *Store) RecordPublisherEnrollmentResult(ctx context.Context, id string, document []byte) error {
	if !validOpaqueValue(id, 256) || !json.Valid(document) || len(document) > 65536 ||
		len(bytes.TrimSpace(document)) < 2 || bytes.TrimSpace(document)[0] != '{' {
		return errors.New("clientstate: invalid publisher enrollment result")
	}
	rows, err := s.database.queries.RecordPublisherEnrollmentResult(ctx, clientstatedb.RecordPublisherEnrollmentResultParams{
		ServerOrigin: s.controlEndpoint, EnrollmentID: id, ResultJson: sql.NullString{String: string(document), Valid: true},
		UpdatedAt: s.database.now().UTC().UnixNano(),
	})
	if err != nil {
		return err
	}
	if rows != 1 {
		return ErrPublisherStateConflict
	}
	return nil
}

// PromotePublisherEnrollment commits the installed key and its first selection
// together. a repeated redemption can only reuse the same public document/key.
func (s *Store) PromotePublisherEnrollment(ctx context.Context, enrollmentID string, identity PublisherIdentity) error {
	if !validOpaqueValue(enrollmentID, 256) || !validOpaqueValue(identity.ID, 256) ||
		!json.Valid(identity.PublicDocument) || len(identity.PublicDocument) > 65536 ||
		len(bytes.TrimSpace(identity.PublicDocument)) < 2 || bytes.TrimSpace(identity.PublicDocument)[0] != '{' {
		return errors.New("clientstate: invalid publisher identity")
	}
	tx, err := s.database.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	queries := s.database.queries.WithTx(tx)
	row, err := queries.GetPendingPublisherEnrollment(ctx, clientstatedb.GetPendingPublisherEnrollmentParams{
		ServerOrigin: s.controlEndpoint, EnrollmentID: enrollmentID,
	})
	if err != nil {
		return err
	}
	key, err := s.secrets.Open(ctx, pendingKeyContext(enrollmentID), row.SigningKeyCiphertext)
	if err != nil {
		return err
	}
	if subtle.ConstantTimeCompare(key, identity.SigningKey) != 1 || !time.Unix(0, row.ExpiresAt).After(s.database.now()) ||
		row.ResultJson.Valid && row.ResultJson.String != string(identity.PublicDocument) {
		return ErrPublisherStateConflict
	}
	sealed, err := s.secrets.Seal(ctx, publisherKeyContext(identity.ID, identity.PublicDocument), key)
	if err != nil {
		return err
	}
	now := s.database.now().UTC().UnixNano()
	if err := queries.SavePublisherIdentity(ctx, clientstatedb.SavePublisherIdentityParams{
		ServerOrigin: s.controlEndpoint, IdentityID: identity.ID,
		PublicDocumentJson: string(identity.PublicDocument), SigningKeyCiphertext: sealed, UpdatedAt: now,
	}); err != nil {
		return err
	}
	current, err := queries.GetPublisherIdentity(ctx, clientstatedb.GetPublisherIdentityParams{
		ServerOrigin: s.controlEndpoint, IdentityID: identity.ID,
	})
	if err != nil || current.PublicDocumentJson != string(identity.PublicDocument) {
		return ErrPublisherStateConflict
	}
	storedKey, err := s.secrets.Open(ctx, publisherKeyContext(identity.ID, identity.PublicDocument), current.SigningKeyCiphertext)
	if err != nil || subtle.ConstantTimeCompare(storedKey, key) != 1 {
		return ErrPublisherStateConflict
	}
	if row.SelectionKind != "explicit" {
		if err := queries.SelectPublisherIdentity(ctx, clientstatedb.SelectPublisherIdentityParams{
			ServerOrigin: s.controlEndpoint, SelectionKind: row.SelectionKind,
			SelectionKey: row.SelectionKey, IdentityID: identity.ID, UpdatedAt: now,
		}); err != nil {
			return err
		}
	}
	if len(row.EnrollmentSecretCiphertext) != 0 {
		secret, err := s.secrets.Open(ctx, pendingSecretContext(enrollmentID), row.EnrollmentSecretCiphertext)
		if err != nil {
			return err
		}
		digest := sha256.Sum256(secret)
		if err := queries.SelectPublisherIdentity(ctx, clientstatedb.SelectPublisherIdentityParams{
			ServerOrigin: s.controlEndpoint, SelectionKind: "enrollment", SelectionKey: hex.EncodeToString(digest[:]),
			IdentityID: identity.ID, UpdatedAt: now, ExpiresAt: sql.NullInt64{Int64: row.ExpiresAt, Valid: true},
		}); err != nil {
			return err
		}
	}
	if err := queries.PruneExpiredPublisherEnrollmentSelections(ctx, sql.NullInt64{Int64: now, Valid: true}); err != nil {
		return err
	}
	if err := queries.DeletePendingPublisherEnrollment(ctx, clientstatedb.DeletePendingPublisherEnrollmentParams{
		ServerOrigin: s.controlEndpoint, EnrollmentID: enrollmentID,
	}); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) PublisherIdentity(ctx context.Context, id string) (PublisherIdentity, bool, error) {
	if !validOpaqueValue(id, 256) {
		return PublisherIdentity{}, false, errors.New("clientstate: invalid publisher identity ID")
	}
	row, err := s.database.queries.GetPublisherIdentity(ctx, clientstatedb.GetPublisherIdentityParams{
		ServerOrigin: s.controlEndpoint, IdentityID: id,
	})
	if errors.Is(err, sql.ErrNoRows) {
		return PublisherIdentity{}, false, nil
	}
	return s.openPublisherIdentity(ctx, row, err)
}

func (s *Store) SelectedPublisherIdentity(ctx context.Context, kind, key string) (PublisherIdentity, bool, error) {
	if !validPublisherSelection(kind, key) || kind == "explicit" {
		return PublisherIdentity{}, false, errors.New("clientstate: invalid publisher selection")
	}
	row, err := s.database.queries.GetSelectedPublisherIdentity(ctx, clientstatedb.GetSelectedPublisherIdentityParams{
		ServerOrigin: s.controlEndpoint, SelectionKind: kind, SelectionKey: key,
		Now: sql.NullInt64{Int64: s.database.now().UTC().UnixNano(), Valid: true},
	})
	if errors.Is(err, sql.ErrNoRows) {
		return PublisherIdentity{}, false, nil
	}
	return s.openPublisherIdentity(ctx, row, err)
}

func (s *Store) openPublisherIdentity(ctx context.Context, row clientstatedb.PublisherIdentity, err error) (PublisherIdentity, bool, error) {
	if err != nil {
		return PublisherIdentity{}, false, err
	}
	document := []byte(row.PublicDocumentJson)
	key, err := s.secrets.Open(ctx, publisherKeyContext(row.IdentityID, document), row.SigningKeyCiphertext)
	if err != nil {
		return PublisherIdentity{}, true, err
	}
	return PublisherIdentity{ID: row.IdentityID, PublicDocument: document, SigningKey: key}, true, nil
}

func (s *Store) SelectPublisherIdentity(ctx context.Context, kind, key, id string) error {
	if !validPublisherSelection(kind, key) || kind == "explicit" || !validOpaqueValue(id, 256) {
		return errors.New("clientstate: invalid publisher selection")
	}
	return s.database.queries.SelectPublisherIdentity(ctx, clientstatedb.SelectPublisherIdentityParams{
		ServerOrigin: s.controlEndpoint, SelectionKind: kind, SelectionKey: key,
		IdentityID: id, UpdatedAt: s.database.now().UTC().UnixNano(),
	})
}

func (s *Store) RemovePublisherIdentity(ctx context.Context, id string) error {
	if !validOpaqueValue(id, 256) {
		return errors.New("clientstate: invalid publisher identity ID")
	}
	return s.database.queries.DeletePublisherIdentity(ctx, clientstatedb.DeletePublisherIdentityParams{ServerOrigin: s.controlEndpoint, IdentityID: id})
}

func (s *Store) RemovePendingPublisherEnrollment(ctx context.Context, id string) error {
	if !validOpaqueValue(id, 256) {
		return errors.New("clientstate: invalid publisher enrollment ID")
	}
	return s.database.queries.DeletePendingPublisherEnrollment(ctx, clientstatedb.DeletePendingPublisherEnrollmentParams{
		ServerOrigin: s.controlEndpoint, EnrollmentID: id,
	})
}

func (s *Store) RemovePublisherSelection(ctx context.Context, kind, key string) error {
	if !validPublisherSelection(kind, key) || kind == "explicit" {
		return errors.New("clientstate: invalid publisher selection")
	}
	return s.database.queries.DeletePublisherSelection(ctx, clientstatedb.DeletePublisherSelectionParams{
		ServerOrigin: s.controlEndpoint, SelectionKind: kind, SelectionKey: key,
	})
}

// ImportPublisherIdentity installs the exact public document and key once.
// retries may select it again but cannot silently replace its signing key.
func (s *Store) ImportPublisherIdentity(ctx context.Context, identity PublisherIdentity) error {
	return s.importPublisherIdentity(ctx, s.database.queries, identity)
}

// InstallPublisherIdentity commits an exact imported key and its selection
// together. a failed installation cannot leave the selection partially changed.
func (s *Store) InstallPublisherIdentity(ctx context.Context, identity PublisherIdentity, selection PublisherSelection) error {
	if !validPublisherSelection(selection.Kind, selection.Key) || selection.Kind == "explicit" {
		return errors.New("clientstate: invalid publisher selection")
	}
	tx, err := s.database.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	queries := s.database.queries.WithTx(tx)
	if err := s.importPublisherIdentity(ctx, queries, identity); err != nil {
		return err
	}
	if err := queries.SelectPublisherIdentity(ctx, clientstatedb.SelectPublisherIdentityParams{
		ServerOrigin: s.controlEndpoint, SelectionKind: selection.Kind, SelectionKey: selection.Key,
		IdentityID: identity.ID, UpdatedAt: s.database.now().UTC().UnixNano(),
	}); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) importPublisherIdentity(ctx context.Context, queries *clientstatedb.Queries, identity PublisherIdentity) error {
	if !validOpaqueValue(identity.ID, 256) || !json.Valid(identity.PublicDocument) ||
		len(identity.PublicDocument) > 65536 || len(identity.SigningKey) == 0 || len(identity.SigningKey) > 65536 {
		return errors.New("clientstate: invalid publisher identity")
	}
	sealed, err := s.secrets.Seal(ctx, publisherKeyContext(identity.ID, identity.PublicDocument), identity.SigningKey)
	if err != nil {
		return err
	}
	if err := queries.SavePublisherIdentity(ctx, clientstatedb.SavePublisherIdentityParams{
		ServerOrigin: s.controlEndpoint, IdentityID: identity.ID,
		PublicDocumentJson: string(identity.PublicDocument), SigningKeyCiphertext: sealed,
		UpdatedAt: s.database.now().UTC().UnixNano(),
	}); err != nil {
		return err
	}
	row, err := queries.GetPublisherIdentity(ctx, clientstatedb.GetPublisherIdentityParams{ServerOrigin: s.controlEndpoint, IdentityID: identity.ID})
	stored, found, err := s.openPublisherIdentity(ctx, row, err)
	if err != nil {
		return err
	}
	if !found || !bytes.Equal(stored.PublicDocument, identity.PublicDocument) ||
		subtle.ConstantTimeCompare(stored.SigningKey, identity.SigningKey) != 1 {
		return ErrPublisherStateConflict
	}
	return nil
}

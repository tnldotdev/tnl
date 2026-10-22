package clientstate

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"

	"github.com/tnldotdev/tnl/internal/opaqueid"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

// VisitorDevice is the protected per-server, per-identity Ed25519 device key.
// ID is empty until enrollment succeeds. the key is never a plaintext DB field.
type VisitorDevice struct {
	ID         string
	PublicKey  ed25519.PublicKey
	SigningKey ed25519.PrivateKey `json:"-"`
}

func visitorDeviceContext(identity string, public []byte) string {
	return "visitor-device:" + identity + ":" + hex.EncodeToString(public)
}

func (s *Store) VisitorDevice(ctx context.Context, identity string) (VisitorDevice, bool, error) {
	if !validPrivatePortKey(identity, "device") {
		return VisitorDevice{}, false, errors.New("invalid visitor identity")
	}
	var result VisitorDevice
	var sealed []byte
	err := s.database.db.QueryRowContext(ctx, `SELECT device_id, public_key, signing_key_ciphertext FROM visitor_devices WHERE server_origin=? AND identity_id=?`, s.controlEndpoint, identity).Scan(&result.ID, &result.PublicKey, &sealed)
	if errors.Is(err, sql.ErrNoRows) {
		return VisitorDevice{}, false, nil
	}
	if err != nil {
		return VisitorDevice{}, false, err
	}
	key, err := s.secrets.Open(ctx, visitorDeviceContext(identity, result.PublicKey), sealed)
	if err != nil {
		return VisitorDevice{}, true, err
	}
	if len(key) != ed25519.PrivateKeySize || !bytes.Equal(ed25519.NewKeyFromSeed(key[:ed25519.SeedSize]), key) || !bytes.Equal(key[ed25519.SeedSize:], result.PublicKey) {
		return VisitorDevice{}, true, errors.New("invalid protected visitor key")
	}
	result.SigningKey = ed25519.PrivateKey(key)
	return result, true, nil
}

// EnsureVisitorDevice persists the retry key before sending an enrollment.
// concurrent callers select the same winning key without replacing it.
func (s *Store) EnsureVisitorDevice(ctx context.Context, identity string) (VisitorDevice, error) {
	if existing, found, err := s.VisitorDevice(ctx, identity); found || err != nil {
		return existing, err
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return VisitorDevice{}, err
	}
	sealed, err := s.secrets.Seal(ctx, visitorDeviceContext(identity, public), private)
	if err != nil {
		return VisitorDevice{}, err
	}
	_, err = s.database.db.ExecContext(ctx, `INSERT INTO visitor_devices(server_origin, identity_id, public_key, signing_key_ciphertext, updated_at) VALUES(?,?,?,?,?) ON CONFLICT DO NOTHING`, s.controlEndpoint, identity, []byte(public), sealed, s.database.now().UTC().UnixNano())
	if err != nil {
		return VisitorDevice{}, err
	}
	result, found, err := s.VisitorDevice(ctx, identity)
	if err == nil && !found {
		err = errors.New("visitor device disappeared")
	}
	return result, err
}

// EnrollVisitorDevice binds the issued device ID to the exact pending key.
// a stale enrollment reply cannot replace another key or enrollment.
func (s *Store) EnrollVisitorDevice(ctx context.Context, identity, deviceID string, public ed25519.PublicKey) error {
	if !validPrivatePortKey(identity, deviceID) || len(public) != ed25519.PublicKeySize {
		return errors.New("invalid visitor device enrollment")
	}
	result, err := s.database.db.ExecContext(ctx, `UPDATE visitor_devices SET device_id=?, updated_at=? WHERE server_origin=? AND identity_id=? AND public_key=? AND (device_id='' OR device_id=?)`, deviceID, s.database.now().UTC().UnixNano(), s.controlEndpoint, identity, []byte(public), deviceID)
	if err != nil {
		return err
	}
	count, err := result.RowsAffected()
	if err == nil && count != 1 {
		return errors.New("visitor device enrollment changed")
	}
	return err
}

// EnsureEnrolledVisitorDevice shares one protected key between connector
// sessions and service client certificates. a lost response retries that key.
func (s *Store) EnsureEnrolledVisitorDevice(ctx context.Context, identity string, enroll func(context.Context, ed25519.PublicKey) (controlv1.VisitorDevice, error)) (VisitorDevice, error) {
	if enroll == nil || !opaqueid.Valid(identity, opaqueid.IdentityPrefix) {
		return VisitorDevice{}, ErrPublisherStateConflict
	}
	device, err := s.EnsureVisitorDevice(ctx, identity)
	if err != nil {
		return VisitorDevice{}, err
	}
	if device.ID == "" {
		result, err := enroll(ctx, device.PublicKey)
		if err != nil {
			return VisitorDevice{}, err
		}
		if result.PublicKey != hex.EncodeToString(device.PublicKey) || result.IdentityId != identity || !opaqueid.Valid(result.Id, opaqueid.VisitorDevicePrefix) || result.RevokedAt != nil {
			return VisitorDevice{}, ErrPublisherStateConflict
		}
		if err = s.EnrollVisitorDevice(ctx, identity, result.Id, device.PublicKey); err != nil {
			return VisitorDevice{}, err
		}
		device.ID = result.Id
	}
	if !opaqueid.Valid(device.ID, opaqueid.VisitorDevicePrefix) {
		return VisitorDevice{}, ErrPublisherStateConflict
	}
	return device, nil
}

func (s *Store) RemoveVisitorDevice(ctx context.Context, identity string) error {
	if !validPrivatePortKey(identity, "device") {
		return errors.New("invalid visitor identity")
	}
	_, err := s.database.db.ExecContext(ctx, `DELETE FROM visitor_devices WHERE server_origin=? AND identity_id=?`, s.controlEndpoint, identity)
	return err
}

package state

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"time"

	"github.com/tnldotdev/tnl/internal/client/state/certificatestore"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type CertificateCache = certificatestore.CertificateCache
type Pending = certificatestore.Pending
type Material = certificatestore.Material

var ErrCertificateExpired = certificatestore.ErrCertificateExpired

// certificateFiles adapts the native private directory without changing its
// permissions, inode pinning, atomic rename, fsync or cross-process locks.
type certificateFiles struct{ files *PrivateDirectory }

func (f certificateFiles) Read(ctx context.Context, name string, limit int64) ([]byte, bool, error) {
	if err := context.Cause(ctx); err != nil {
		return nil, false, err
	}
	return f.files.Read(name, limit)
}

func (f certificateFiles) Write(ctx context.Context, name string, data []byte) error {
	if err := context.Cause(ctx); err != nil {
		return err
	}
	return f.files.Write(name, data)
}

func (f certificateFiles) Sync(ctx context.Context, name string) error {
	if err := context.Cause(ctx); err != nil {
		return err
	}
	return f.files.Sync(name)
}

func (f certificateFiles) Lock(ctx context.Context, name string) (io.Closer, error) {
	return f.files.Lock(ctx, name)
}

func (s *Store) certificateScope(team, publisher string) certificatestore.Scope {
	return certificatestore.Scope{ControlURL: s.controlEndpoint, TeamID: team, PublisherIdentityID: publisher}
}

// CertificatesForPublisher selects durable native TLS storage independently of
// SQLite and its wrapping key. native and host publishers use the same engine.
func (s *Store) CertificatesForPublisher(team, publisher string, plan controlv1.CertificatePlan) (*CertificateCache, error) {
	files, err := s.PublisherIdentityFiles(team, publisher)
	if err != nil {
		return nil, err
	}
	return certificatestore.New(certificateFiles{files}, s.certificateScope(team, publisher), plan)
}

func LockPublisherHostnameContext(ctx context.Context, store *Store, hostname, publisherIdentityID string) (*Lock, error) {
	if store == nil || !opaqueid.Valid(publisherIdentityID, opaqueid.PublisherIdentityPrefix) {
		return nil, errors.New("clientstate: state store and enrolled publisher identity are required")
	}
	canonical, err := naming.CanonicalizeHostname(hostname)
	if err != nil || canonical != hostname {
		return nil, errors.New("clientstate: canonical publisher hostname is required")
	}
	files, err := store.PublisherIdentityFiles("", publisherIdentityID)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256([]byte(hostname))
	return files.Lock(ctx, fmt.Sprintf("hostname-%x.lock", digest))
}

func (s *Store) PublisherCertificateMaterialExists(ctx context.Context, team, publisher string) (bool, error) {
	files, err := s.PublisherIdentityFiles(team, publisher)
	if err != nil {
		return false, err
	}
	entries, err := os.ReadDir(files.Path())
	if err != nil {
		return false, identityFileError(err)
	}
	names := make([]string, len(entries))
	for i, entry := range entries {
		names[i] = entry.Name()
	}
	return certificatestore.MaterialExists(ctx, certificateFiles{files}, s.certificateScope(team, publisher), names)
}

// RequirePublisherCertificatePlans checks control's monotonic plan inventory.
func (s *Store) RequirePublisherCertificatePlans(ctx context.Context, team, publisher string, plans []controlv1.CertificatePlan) error {
	files, err := s.PublisherIdentityFiles(team, publisher)
	if err != nil {
		return err
	}
	return certificatestore.RequirePlans(ctx, certificateFiles{files}, s.certificateScope(team, publisher), plans)
}

func databaseVersion(publishRunNumber uint64) (int64, error) {
	if publishRunNumber > math.MaxInt64 {
		return 0, errors.New("clientstate: publish run number exceeds database range")
	}
	return int64(publishRunNumber), nil
}

func unixNanoTime(value int64) time.Time {
	if value == 0 {
		return time.Time{}
	}
	return time.Unix(0, value).UTC()
}

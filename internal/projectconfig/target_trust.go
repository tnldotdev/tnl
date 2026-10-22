package projectconfig

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"

	"github.com/tnldotdev/tnl/internal/privatetrust"
)

// TargetTrustSnapshot is portable publisher-to-target trust for every protocol.
// its CA-only material adds to system roots, independently of visitor TLS.
type TargetTrustSnapshot struct {
	Hostname string
	CAPEM    []byte
	Digest   string
}

func (s TargetTrustSnapshot) Validate() error {
	_, err := s.PrivateSnapshot()
	return err
}

// PrivateSnapshot uses the same verifier for applied and local target trust.
func (s TargetTrustSnapshot) PrivateSnapshot() (*privatetrust.Snapshot, error) {
	if s.Digest != targetTrustDigest(s.Hostname, s.CAPEM) {
		return nil, errors.New("target trust digest does not match its snapshot")
	}
	mode := "pem"
	if len(s.CAPEM) == 0 {
		mode = "system"
	}
	digest := sha256.Sum256(append([]byte(s.Hostname+"\x00"+mode+"\x00"), s.CAPEM...))
	snapshot := &privatetrust.Snapshot{Hostname: s.Hostname, PEM: s.CAPEM, System: len(s.CAPEM) == 0, Digest: hex.EncodeToString(digest[:])}
	_, err := snapshot.Verifier()
	return snapshot, err
}

func targetTrustDigest(hostname string, ca []byte) string {
	digest := sha256.Sum256(append([]byte("tnl-target-tls/v1\x00"+hostname+"\x00"), ca...))
	return hex.EncodeToString(digest[:])
}

// CaptureTargetTrust reads the declared CA source at apply time. source paths
// and bundle URLs never enter the resulting declaration or remote worker.
func (p Project) CaptureTargetTrust(ctx context.Context, cache *privatetrust.Cache, name, discovered string) (*TargetTrustSnapshot, error) {
	trust, err := p.captureTrust(ctx, cache, name, discovered)
	if err != nil {
		return nil, err
	}
	if trust == nil {
		return nil, nil
	}
	snapshot := &TargetTrustSnapshot{Hostname: trust.Hostname, CAPEM: trust.PEM, Digest: targetTrustDigest(trust.Hostname, trust.PEM)}
	return snapshot, snapshot.Validate()
}

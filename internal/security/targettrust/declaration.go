package targettrust

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
)

// Declaration is portable publisher-to-target trust captured for project apply.
// its versioned digest is distinct from the saved-service snapshot digest.
type Declaration struct {
	Hostname string
	CAPEM    []byte
	Digest   string
}

func (d Declaration) Validate() error {
	_, err := d.Snapshot()
	return err
}

// Snapshot validates captured material without reading files or system roots.
func (d Declaration) Snapshot() (*Snapshot, error) {
	if d.Digest != declarationDigest(d.Hostname, d.CAPEM) {
		return nil, errors.New("target trust digest does not match its snapshot")
	}
	snapshot := &Snapshot{Hostname: d.Hostname, PEM: d.CAPEM, System: len(d.CAPEM) == 0}
	snapshot.Digest = snapshot.digest()
	return snapshot, snapshot.Validate()
}

// Declaration preserves the captured bytes while selecting the project digest.
func (s Snapshot) Declaration() (*Declaration, error) {
	if err := s.Validate(); err != nil {
		return nil, err
	}
	return &Declaration{Hostname: s.Hostname, CAPEM: s.PEM, Digest: declarationDigest(s.Hostname, s.PEM)}, nil
}

func declarationDigest(hostname string, ca []byte) string {
	digest := sha256.New()
	_, _ = digest.Write([]byte("tnl-target-tls/v1\x00" + hostname + "\x00"))
	_, _ = digest.Write(ca)
	return hex.EncodeToString(digest.Sum(nil))
}

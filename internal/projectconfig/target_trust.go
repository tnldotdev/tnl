package projectconfig

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/url"
	"path/filepath"
	"strings"

	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/privatetrust"
)

// TargetTrustSnapshot is portable publisher-to-HTTPS target trust. its CA-only
// material adds to system roots; private visitor TLS has a separate snapshot.
type TargetTrustSnapshot struct {
	Hostname string
	CAPEM    []byte
	Digest   string
}

func (s TargetTrustSnapshot) Validate() error {
	if s.Digest != targetTrustDigest(s.Hostname, s.CAPEM) {
		return errors.New("HTTPS target trust digest does not match its snapshot")
	}
	mode := "pem"
	if len(s.CAPEM) == 0 {
		mode = "system"
	}
	digest := sha256.Sum256(append([]byte(s.Hostname+"\x00"+mode+"\x00"), s.CAPEM...))
	_, err := (privatetrust.Snapshot{Hostname: s.Hostname, PEM: s.CAPEM, System: len(s.CAPEM) == 0, Digest: hex.EncodeToString(digest[:])}).Verifier()
	return err
}

func targetTrustDigest(hostname string, ca []byte) string {
	digest := sha256.Sum256(append([]byte("tnl-target-tls/v1\x00"+hostname+"\x00"), ca...))
	return hex.EncodeToString(digest[:])
}

// CaptureTargetTrust reads the declared CA source at apply time. source paths
// and bundle URLs never enter the resulting declaration or remote worker.
func (p Project) CaptureTargetTrust(ctx context.Context, cache *privatetrust.Cache, name, discovered string) (*TargetTrustSnapshot, error) {
	service, found := p.Config.Services[name]
	if !found {
		return nil, errors.New("HTTPS target service is not configured")
	}
	if service.Target == nil || service.Target.TLS == nil {
		return nil, nil
	}
	resolved, err := p.ResolvePublish(name, discovered)
	if err != nil {
		return nil, err
	}
	target, err := url.Parse(string(*resolved.Target))
	if err != nil || target.Scheme != "https" {
		return nil, errors.New("target trust requires an HTTPS origin")
	}
	setting := config.ServiceTLS{CA: "system", Hostname: service.Target.TLS.ServerName}
	root := p.Root
	if source := service.Target.TLS.CAFile; source != nil {
		setting.CA = *source
		if filepath.IsAbs(setting.CA) {
			root, setting.CA = filepath.Dir(setting.CA), filepath.Base(setting.CA)
		}
		if strings.HasPrefix(setting.CA, "https://") {
			root = p.Root
		}
	}
	if cache == nil {
		cache = privatetrust.NewCache(nil)
	}
	trust, err := cache.Capture(ctx, root, target.Host, setting)
	if err != nil {
		return nil, err
	}
	snapshot := &TargetTrustSnapshot{Hostname: trust.Hostname, CAPEM: trust.PEM, Digest: targetTrustDigest(trust.Hostname, trust.PEM)}
	return snapshot, snapshot.Validate()
}

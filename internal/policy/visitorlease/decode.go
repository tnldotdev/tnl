package visitorlease

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"

	"github.com/tnldotdev/tnl/internal/policy/ippolicy"
	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	"github.com/tnldotdev/tnl/internal/security/visitortoken"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func Decode(body controlv1.VisitorPolicyUpdate) (Update, error) {
	policy := body.Policy
	scope := visitorscope.Scope{Kind: visitorscope.Kind(policy.Resource.Kind), ID: policy.Resource.Id}
	if !scope.Valid() || policy.Port < 1 || policy.Port > 65535 || len(policy.VerificationKeys) > 64 || len(policy.WorkloadLeases) > 4096 || len(policy.CredentialLeases) > 4096 || len(body.Revisions) > 256 || len(policy.StreamAllocations) > 2048 {
		return Update{}, ErrUpdate
	}
	if scope.Kind == visitorscope.PublicURL && policy.MetadataRevision != 0 || scope.Kind == visitorscope.Service && policy.MetadataRevision < 1 {
		return Update{}, ErrUpdate
	}
	update := Update{View: visitortoken.View{Scope: scope, Issuer: policy.Issuer, Hostname: policy.Hostname, Port: uint16(policy.Port), VisitorPolicyRevision: policy.VisitorPolicyRevision,
		MetadataRevision: policy.MetadataRevision, Public: policy.Public, ObservedAt: policy.ObservedAt, ValidUntil: policy.ValidUntil, Keys: make(map[string]ed25519.PublicKey), Workloads: make(map[string]visitortoken.WorkloadLease)},
		KeyRevision: policy.KeyRevision, Enabled: policy.Enabled, Anonymous: policy.Anonymous, AfterRevision: body.AfterRevision, Events: body.Revisions, Snapshot: body.SnapshotRequired}
	update.View.Credentials = make(map[string]visitortoken.CredentialLease, len(policy.CredentialLeases))
	for _, lease := range policy.CredentialLeases {
		key, valid := visitortoken.CredentialLeaseKey(string(lease.Kind), lease.Id)
		digest, err := base64.RawURLEncoding.Strict().DecodeString(lease.SubjectSha256)
		if !valid || err != nil || len(digest) != 32 || base64.RawURLEncoding.EncodeToString(digest) != lease.SubjectSha256 || !lease.ExpiresAt.After(policy.ObservedAt) {
			return Update{}, ErrUpdate
		}
		if _, duplicate := update.View.Credentials[key]; duplicate {
			return Update{}, ErrUpdate
		}
		update.View.Credentials[key] = visitortoken.CredentialLease{SubjectSHA256: lease.SubjectSha256, ExpiresAt: lease.ExpiresAt}
	}
	if policy.ClientIssuerPem != nil {
		if scope.Kind != visitorscope.Service || len(*policy.ClientIssuerPem) > 4096 {
			return Update{}, ErrUpdate
		}
		block, remaining := pem.Decode([]byte(*policy.ClientIssuerPem))
		if block == nil || block.Type != "CERTIFICATE" || len(bytes.TrimSpace(remaining)) != 0 {
			return Update{}, ErrUpdate
		}
		issuer, err := x509.ParseCertificate(block.Bytes)
		if err != nil || !issuer.IsCA || issuer.CheckSignatureFrom(issuer) != nil {
			return Update{}, ErrUpdate
		}
		update.ClientAuthorities = x509.NewCertPool()
		update.ClientAuthorities.AddCert(issuer)
	}
	update.Allocations = make(map[string]controlv1.StreamCapacityAllocation, len(policy.StreamAllocations))
	for _, allocation := range policy.StreamAllocations {
		if !validAllocation(allocation, scope) {
			return Update{}, ErrUpdate
		}
		if _, found := update.Allocations[allocation.Id]; found {
			return Update{}, ErrUpdate
		}
		update.Allocations[allocation.Id] = allocation
	}
	for _, key := range policy.VerificationKeys {
		if len(key.PublicKey) != ed25519.PublicKeySize || key.Id == "" || update.View.Keys[key.Id] != nil {
			return Update{}, ErrUpdate
		}
		update.View.Keys[key.Id] = ed25519.PublicKey(key.PublicKey)
	}
	for _, parent := range policy.WorkloadLeases {
		if parent.SessionId == "" {
			return Update{}, ErrUpdate
		}
		if _, found := update.View.Workloads[parent.SessionId]; found {
			return Update{}, ErrUpdate
		}
		update.View.Workloads[parent.SessionId] = visitortoken.WorkloadLease{KeySHA256: parent.KeySha256, ExpiresAt: parent.ExpiresAt}
	}
	if policy.Ip != nil {
		if len(policy.Ip.Key) != 32 || len(policy.Ip.Prefixes) > 2048 {
			return Update{}, ErrUpdate
		}
		var key [32]byte
		copy(key[:], policy.Ip.Key)
		entries := make([]ippolicy.Entry, len(policy.Ip.Prefixes))
		for index, entry := range policy.Ip.Prefixes {
			entries[index] = ippolicy.Entry{Family: string(entry.Family), Bits: entry.PrefixLength, Digest: entry.Digest}
		}
		ip, err := ippolicy.New(key, entries)
		if err != nil {
			return Update{}, ErrUpdate
		}
		update.IP = &ip
	}
	return update, nil
}

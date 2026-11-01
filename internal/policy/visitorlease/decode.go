package visitorlease

import (
	"crypto/ed25519"

	"github.com/tnldotdev/tnl/internal/policy/ippolicy"
	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	"github.com/tnldotdev/tnl/internal/security/visitortoken"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func Decode(body controlv1.VisitorPolicyUpdate) (Update, error) {
	policy := body.Policy
	scope := visitorscope.Scope{Kind: visitorscope.Kind(policy.Resource.Kind), ID: policy.Resource.Id}
	if !scope.Valid() || policy.Port < 1 || policy.Port > 65535 || policy.MetadataRevision < 0 || len(policy.VerificationKeys) > 64 || len(policy.WorkloadLeases) > 4096 || len(body.Revisions) > 256 {
		return Update{}, ErrUpdate
	}
	update := Update{View: visitortoken.View{Scope: scope, Issuer: policy.Issuer, Hostname: policy.Hostname, Port: uint16(policy.Port), VisitorPolicyRevision: policy.VisitorPolicyRevision,
		ObservedAt: policy.ObservedAt, ValidUntil: policy.ValidUntil, MetadataRevision: policy.MetadataRevision},
		KeyRevision: policy.KeyRevision, Enabled: policy.Enabled, Anonymous: policy.Anonymous, AfterRevision: body.AfterRevision, Events: body.Revisions, Snapshot: body.SnapshotRequired}
	keys := make(map[string]ed25519.PublicKey, len(policy.VerificationKeys))
	for _, key := range policy.VerificationKeys {
		if len(key.PublicKey) != ed25519.PublicKeySize || key.Id == "" || keys[key.Id] != nil {
			return Update{}, ErrUpdate
		}
		keys[key.Id] = ed25519.PublicKey(key.PublicKey)
	}
	workloads := make(map[string]visitortoken.WorkloadLease, len(policy.WorkloadLeases))
	for _, parent := range policy.WorkloadLeases {
		if parent.SessionId == "" {
			return Update{}, ErrUpdate
		}
		if _, found := workloads[parent.SessionId]; found {
			return Update{}, ErrUpdate
		}
		workloads[parent.SessionId] = visitortoken.WorkloadLease{KeySHA256: parent.KeySha256, ExpiresAt: parent.ExpiresAt}
	}
	update.View = update.View.WithVerificationKeys(keys).WithWorkloadLeases(workloads)
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

package visitortoken

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"time"

	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

var ErrVisitorSource = errors.New("visitor source proof is unavailable or stale")

// PublicVisitorSourceKey derives a purpose-separated, run-owned key from the
// stored secret digest. only the exact publisher receives this master key;
// ingress receives a delegated child key that cannot mint another authority.
func PublicVisitorSourceKey(secretDigest []byte, run string, number uint64) ([32]byte, error) {
	if len(secretDigest) != sha256.Size || !validText(run, 256) || number == 0 {
		return [32]byte{}, ErrVisitorSource
	}
	mac := hmac.New(sha256.New, secretDigest)
	mac.Write([]byte("tnl-public-visitor-source-key-v1\x00"))
	mac.Write(binary.BigEndian.AppendUint64(nil, number))
	mac.Write([]byte(run))
	return [32]byte(mac.Sum(nil)), nil
}

func sourceMAC(key [32]byte, domain string, input []byte) []byte {
	mac := hmac.New(sha256.New, key[:])
	mac.Write([]byte(domain))
	mac.Write([]byte{0})
	mac.Write(input)
	return mac.Sum(nil)
}

func visitorSourceChildKey(master [32]byte, authority tunnelv1.VisitorSourceAuthority) [32]byte {
	return [32]byte(sourceMAC(master, "tnl-public-visitor-source-child-v1", authority.MAC))
}

func IssueVisitorSourceAuthority(master [32]byte, authority tunnelv1.VisitorSourceAuthority, now time.Time) (tunnelv1.VisitorSourceAuthority, [32]byte, error) {
	input, err := authority.SigningBytes()
	if err != nil || master == ([32]byte{}) || authority.ValidUntil <= now.Unix() || authority.ValidUntil > now.Add(PolicyLifetime).Unix() {
		return tunnelv1.VisitorSourceAuthority{}, [32]byte{}, ErrVisitorSource
	}
	authority.MAC = sourceMAC(master, "tnl-public-visitor-source-authority-v1", input)
	return authority, visitorSourceChildKey(master, authority), nil
}

// SignVisitorSource spends only the installed delegation's deadline. it never
// extends authority after renewal or substitutes a capacity count for permission.
func SignVisitorSource(key [32]byte, authority tunnelv1.VisitorSourceAuthority, sequence uint64, binding tunnelv1.VisitorSourceBinding, now time.Time) (tunnelv1.VisitorSourceProof, error) {
	proof := tunnelv1.VisitorSourceProof{Authority: authority, Sequence: sequence}
	input, err := proof.SigningBytes(binding)
	if err != nil || key == ([32]byte{}) || authority.ValidUntil <= now.Unix() {
		return tunnelv1.VisitorSourceProof{}, ErrVisitorSource
	}
	proof.MAC = sourceMAC(key, "tnl-public-visitor-source-proof-v1", input)
	return proof, nil
}

// VerifyVisitorSource authenticates origin, not visitor access. the caller must
// consume replay evidence once per run after metadata arrives, then perform the
// ordinary current visitor-policy check before forwarding any application work.
// an older delegation remains source evidence until its original deadline; it
// cannot roll back the publisher's newer access policy. a future delegation may
// not outrun the policy the publisher has actually installed.
func VerifyVisitorSource(master [32]byte, proof tunnelv1.VisitorSourceProof, binding tunnelv1.VisitorSourceBinding, policyRevision int64, now time.Time) error {
	input, err := proof.Authority.SigningBytes()
	if err != nil || master == ([32]byte{}) || policyRevision < 1 || proof.Authority.VisitorPolicyRevision > policyRevision || proof.Authority.ValidUntil <= now.Unix() ||
		proof.Authority.ValidUntil > now.Add(PolicyLifetime).Unix() ||
		!hmac.Equal(proof.Authority.MAC, sourceMAC(master, "tnl-public-visitor-source-authority-v1", input)) {
		return ErrVisitorSource
	}
	input, err = proof.SigningBytes(binding)
	if err != nil || !hmac.Equal(proof.MAC, sourceMAC(visitorSourceChildKey(master, proof.Authority), "tnl-public-visitor-source-proof-v1", input)) {
		return ErrVisitorSource
	}
	return nil
}

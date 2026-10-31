package visitortoken

import (
	"crypto/ed25519"
	"encoding/base64"
	"time"

	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func NativeSubject(subject Subject) (tunnelv1.VisitorSubject, error) {
	switch subject := subject.(type) {
	case Device:
		return tunnelv1.VisitorSubject{Kind: tunnelv1.VisitorHumanDevice, IdentityID: subject.IdentityID, DeviceID: subject.DeviceID}, nil
	case Workload:
		return tunnelv1.VisitorSubject{Kind: tunnelv1.VisitorWorkloadSession, WorkloadSessionID: subject.SessionID}, nil
	default:
		return tunnelv1.VisitorSubject{}, ErrBinding
	}
}

// VerifyNativePeerSession follows independently checked control delivery and
// relay receipts. the stream cannot attest its own source, pair or run. this
// verifies evidence only; the service still binds current policy, owner and C.
func VerifyNativePeerSession(entry tunnelv1.NativePeerVisitorEntry, initial []byte, expected tunnelv1.NativePeerSession, view View, now time.Time) (VerifiedPermission, error) {
	permission, err := VerifyNativePeerRenewalProof(entry, initial, expected, view, now)
	if err == nil {
		err = CheckCurrent(permission, view, now)
	}
	if err != nil {
		return VerifiedPermission{}, err
	}
	return permission, nil
}

// VerifyNativePeerRenewalProof does not grant a new stream or extend a guard.
func VerifyNativePeerRenewalProof(entry tunnelv1.NativePeerVisitorEntry, initial []byte, expected tunnelv1.NativePeerSession, view View, now time.Time) (VerifiedPermission, error) {
	wire := expected
	wire.ExpiresAt = time.Time{}
	if entry.Validate() != nil || expected.Validate() != nil || !expected.ExpiresAt.After(now) || entry.Session() != wire ||
		view.Scope.Kind != visitorscope.Service || view.Scope.ID != expected.ServiceID || view.MetadataRevision < 1 || uint64(view.MetadataRevision) != entry.MetadataRevision {
		return VerifiedPermission{}, ErrBinding
	}
	permission, err := verifySignature(Token(entry.Permission.Token), view, now)
	if err != nil {
		return VerifiedPermission{}, err
	}
	subject, err := NativeSubject(permission.Subject)
	if err != nil || subject != expected.Subject {
		return VerifiedPermission{}, ErrBinding
	}
	public, keyErr := base64.RawURLEncoding.Strict().DecodeString(entry.Permission.PublicKey)
	signature, signatureErr := base64.RawURLEncoding.Strict().DecodeString(entry.Permission.Signature)
	message, messageErr := tunnelv1.NativePeerProofMessage(entry, initial)
	digest, digestErr := KeyDigest(ed25519.PublicKey(public))
	var expectedKey string
	switch s := permission.Subject.(type) {
	case Device:
		expectedKey = s.KeySHA256
	case Workload:
		expectedKey = s.KeySHA256
	}
	if keyErr != nil || signatureErr != nil || messageErr != nil || digestErr != nil || expectedKey == "" || digest != expectedKey || !ed25519.Verify(public, message, signature) {
		return VerifiedPermission{}, ErrBinding
	}
	return VerifiedPermission{facts: permission}, nil
}

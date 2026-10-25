package visitortoken

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"math"
	"time"

	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

// NativeProofMessage binds permission to one authenticated infrastructure session,
// visitor connection, exact service run, approved metadata revision and opening
// bytes. replay exclusion belongs to ingress and the publisher's reservation owner.
func NativeProofMessage(token Token, session, connection, runID string, runNumber, metadataRevision uint64, initial []byte) ([]byte, error) {
	if len(token.Reveal()) == 0 || len(token.Reveal()) > MaxTokenBytes || !opaqueid.Valid(session, opaqueid.ConnectorSessionPrefix) || !opaqueid.Valid(connection, opaqueid.VisitorConnectionPrefix) || !opaqueid.Valid(runID, opaqueid.ServiceRunPrefix) || runNumber == 0 || runNumber > math.MaxInt64 || metadataRevision == 0 || metadataRevision > math.MaxInt64 || len(initial) > 64<<10 {
		return nil, ErrBinding
	}
	permissionHash, initialHash := sha256.Sum256([]byte(token.Reveal())), sha256.Sum256(initial)
	body, err := json.Marshal(struct {
		Session          string   `json:"session_id"`
		Connection       string   `json:"visitor_connection_id"`
		ServiceRunID     string   `json:"service_run_id"`
		RunNumber        uint64   `json:"run_number"`
		Token            [32]byte `json:"token_sha256"`
		Initial          [32]byte `json:"initial_sha256"`
		MetadataRevision uint64   `json:"metadata_revision"`
	}{session, connection, runID, runNumber, permissionHash, initialHash, metadataRevision})
	if err != nil {
		return nil, ErrBinding
	}
	return append([]byte("tnl visitor opening v1\x00"), body...), nil
}

func VerifyNative(token Token, view View, expectedSubject Subject, session, connection, runID string, runNumber, metadataRevision uint64, initial []byte, public ed25519.PublicKey, signature []byte, now time.Time) (VerifiedPermission, error) {
	if view.MetadataRevision < 1 || uint64(view.MetadataRevision) != metadataRevision {
		return VerifiedPermission{}, ErrBinding
	}
	permission, err := verify(token, view, now)
	if err != nil {
		return VerifiedPermission{}, err
	}
	if permission.Subject != expectedSubject {
		return VerifiedPermission{}, ErrBinding
	}
	return verifyNativePossession(token, permission, session, connection, runID, runNumber, metadataRevision, initial, public, signature)
}

// VerifyNativeSession compares signed permission with the subject already bound
// to the infrastructure session, then proves possession of the signed key.
func VerifyNativeSession(token Token, view View, expected tunnelv1.VisitorSubject, session, connection, runID string, runNumber, metadataRevision uint64, initial []byte, public ed25519.PublicKey, signature []byte, now time.Time) (VerifiedPermission, error) {
	permission, err := VerifyNativeRenewalProof(token, view, expected, session, connection, runID, runNumber, metadataRevision, initial, public, signature, now)
	if err != nil {
		return VerifiedPermission{}, err
	}
	if err := CheckCurrent(permission, view, now); err != nil {
		return VerifiedPermission{}, err
	}
	return permission, nil
}

// VerifyNativeRenewalProof verifies the signature and possession binding without
// granting admission. an active guard may retain one verified future revision
// until its independently refreshed policy covers it; it cannot extend the old
// confirmed deadline or revive an expired admission while waiting.
func VerifyNativeRenewalProof(token Token, view View, expected tunnelv1.VisitorSubject, session, connection, runID string, runNumber, metadataRevision uint64, initial []byte, public ed25519.PublicKey, signature []byte, now time.Time) (VerifiedPermission, error) {
	if expected.Validate() != nil || view.MetadataRevision < 1 || uint64(view.MetadataRevision) != metadataRevision {
		return VerifiedPermission{}, ErrBinding
	}
	permission, err := verifySignature(token, view, now)
	if err != nil {
		return VerifiedPermission{}, err
	}
	peer, err := NativeSubject(permission.Subject)
	if err != nil || peer != expected {
		return VerifiedPermission{}, ErrBinding
	}
	return verifyNativePossession(token, permission, session, connection, runID, runNumber, metadataRevision, initial, public, signature)
}

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

func verifyNativePossession(token Token, permission Permission, session, connection, runID string, runNumber, metadataRevision uint64, initial []byte, public ed25519.PublicKey, signature []byte) (VerifiedPermission, error) {
	var expectedKey string
	switch subject := permission.Subject.(type) {
	case Device:
		expectedKey = subject.KeySHA256
	case Workload:
		expectedKey = subject.KeySHA256
	default:
		return VerifiedPermission{}, ErrBinding
	}
	digest, err := KeyDigest(public)
	if err != nil || digest != expectedKey || len(public) != ed25519.PublicKeySize || len(signature) != ed25519.SignatureSize {
		return VerifiedPermission{}, ErrBinding
	}
	message, err := NativeProofMessage(token, session, connection, runID, runNumber, metadataRevision, initial)
	if err != nil || !ed25519.Verify(public, message, signature) {
		return VerifiedPermission{}, ErrBinding
	}
	return VerifiedPermission{facts: permission}, nil
}

func VerifyCertificate(token Token, view View, state tls.ConnectionState, now time.Time) (VerifiedPermission, error) {
	permission, err := VerifyCertificateRenewalProof(token, view, state, now)
	if err != nil {
		return VerifiedPermission{}, err
	}
	if err := CheckCurrent(permission, view, now); err != nil {
		return VerifiedPermission{}, err
	}
	return permission, nil
}

// VerifyCertificateRenewalProof identifies the signed certificate source even
// when its policy revision changed. it grants no access; current admission must
// also pass CheckCurrent. credential selection cannot replace a workload source.
func VerifyCertificateRenewalProof(token Token, view View, state tls.ConnectionState, now time.Time) (VerifiedPermission, error) {
	permission, err := verifySignature(token, view, now)
	if err != nil {
		return VerifiedPermission{}, err
	}
	subject, ok := permission.Subject.(Certificate)
	if !ok || !state.HandshakeComplete || len(state.VerifiedChains) == 0 || len(state.VerifiedChains[0]) == 0 || len(state.PeerCertificates) == 0 || !state.PeerCertificates[0].Equal(state.VerifiedChains[0][0]) {
		return VerifiedPermission{}, ErrBinding
	}
	leaf := state.PeerCertificates[0]
	authorityNow := view.AuthorityTime(now)
	digest, err := KeyDigest(leaf.PublicKey)
	if err != nil || digest != subject.KeySHA256 || leaf.SerialNumber == nil || leaf.SerialNumber.Text(16) != subject.Serial || !authorityNow.Before(leaf.NotAfter) || authorityNow.Before(leaf.NotBefore) || permission.ExpiresAt.After(leaf.NotAfter) {
		return VerifiedPermission{}, ErrBinding
	}
	return VerifiedPermission{facts: permission}, nil
}

// ServiceAuditReference follows successful local admission. control resolves
// human attribution from durable issuance/sign-in facts, never from actor claims.
func ServiceAuditReference(permission Permission, state tls.ConnectionState) (tunnelv1.ServiceVisitorReference, error) {
	var reference tunnelv1.ServiceVisitorReference
	switch subject := permission.Subject.(type) {
	case Certificate:
		if !state.HandshakeComplete || len(state.PeerCertificates) == 0 || state.PeerCertificates[0].SerialNumber == nil || state.PeerCertificates[0].SerialNumber.Text(16) != subject.Serial {
			return reference, ErrBinding
		}
		digest := sha256.Sum256(state.PeerCertificates[0].Raw)
		reference = tunnelv1.ServiceVisitorReference{Kind: "certificate", ID: hex.EncodeToString(digest[:])}
	case Browser:
		reference = tunnelv1.ServiceVisitorReference{Kind: "browser_session", ID: subject.SessionID}
	case Grant:
		reference = tunnelv1.ServiceVisitorReference{Kind: "grant", ID: subject.GrantID}
	default:
		return reference, ErrBinding
	}
	if !reference.Valid() {
		return tunnelv1.ServiceVisitorReference{}, ErrBinding
	}
	return reference, nil
}

package visitortoken

import (
	"crypto/tls"
	"time"
)

// the completed TLS handshake proves possession of the peer key. control's
// signature, rather than the certificate CA, authorizes the exact key, serial,
// resource and source. the certificate itself is only the credential carrier.
func VerifyCertificate(token Token, view View, state tls.ConnectionState, now time.Time) (VerifiedPermission, error) {
	if !view.current(now) {
		return VerifiedPermission{}, ErrPolicy
	}
	header, err := credentialHeader(token)
	if err != nil {
		return VerifiedPermission{}, err
	}
	switch header.Type {
	case WorkloadIdentityType:
		return verifyWorkloadIdentity(token, view, state, now)
	case Type:
	default:
		return VerifiedPermission{}, ErrToken
	}
	permission, err := verify(token, view, now)
	if err != nil {
		return VerifiedPermission{}, err
	}
	subject, ok := permission.Subject.(Certificate)
	if !ok {
		return VerifiedPermission{}, ErrBinding
	}
	if err := certificateBinding(token, subject, permission.ExpiresAt, state, view, now); err != nil {
		return VerifiedPermission{}, err
	}
	return VerifiedPermission{facts: permission}, nil
}

func certificateBinding(token Token, subject Certificate, expires time.Time, state tls.ConnectionState, view View, now time.Time) error {
	if !state.HandshakeComplete || len(state.PeerCertificates) != 1 || state.PeerCertificates[0] == nil {
		return ErrBinding
	}
	leaf := state.PeerCertificates[0]
	carried, err := CertificateToken(leaf)
	if err != nil || carried != token || leaf.IsCA {
		return ErrBinding
	}
	authorityNow := view.AuthorityTime(now)
	digest, err := KeyDigest(leaf.PublicKey)
	if err != nil || digest != subject.KeySHA256 || leaf.SerialNumber == nil || leaf.SerialNumber.Text(16) != subject.Serial || !authorityNow.Before(leaf.NotAfter) || authorityNow.Before(leaf.NotBefore) || expires.After(leaf.NotAfter) {
		return ErrBinding
	}
	return nil
}

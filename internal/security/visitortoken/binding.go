package visitortoken

import (
	"crypto/tls"
	"time"
)

// the completed TLS handshake proves possession of the peer key. control's
// signature, rather than the certificate CA, authorizes the exact key, serial,
// resource and source. the certificate itself is only the credential carrier.
func VerifyCertificate(token Token, view View, state tls.ConnectionState, now time.Time) (VerifiedPermission, error) {
	permission, err := verify(token, view, now)
	if err != nil {
		return VerifiedPermission{}, err
	}
	subject, ok := permission.Subject.(Certificate)
	if !ok || !state.HandshakeComplete || len(state.PeerCertificates) != 1 || state.PeerCertificates[0] == nil {
		return VerifiedPermission{}, ErrBinding
	}
	leaf := state.PeerCertificates[0]
	carried, err := CertificateToken(leaf)
	if err != nil || carried != token || leaf.IsCA {
		return VerifiedPermission{}, ErrBinding
	}
	authorityNow := view.AuthorityTime(now)
	digest, err := KeyDigest(leaf.PublicKey)
	if err != nil || digest != subject.KeySHA256 || leaf.SerialNumber == nil || leaf.SerialNumber.Text(16) != subject.Serial || !authorityNow.Before(leaf.NotAfter) || authorityNow.Before(leaf.NotBefore) || permission.ExpiresAt.After(leaf.NotAfter) {
		return VerifiedPermission{}, ErrBinding
	}
	return VerifiedPermission{facts: permission}, nil
}

package auth

import "crypto/ed25519"

// DeploymentSigner retains a validated signing operation, not serving permission.
// negative cleanup can still use it after the portable approval has expired.
type DeploymentSigner struct{ key ed25519.PrivateKey }

func (*DeploymentSigner) String() string   { return "private deployment signer" }
func (*DeploymentSigner) GoString() string { return "private deployment signer" }

func (c DeploymentCredential) CaptureSigner() (*DeploymentSigner, error) {
	key, err := c.key()
	if err != nil {
		return nil, err
	}
	return &DeploymentSigner{key: key}, nil
}

func (s *DeploymentSigner) PublicKey() ed25519.PublicKey {
	return s.key.Public().(ed25519.PublicKey)
}

func (s *DeploymentSigner) Sign(message []byte) []byte { return ed25519.Sign(s.key, message) }

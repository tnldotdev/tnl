package managedssh

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"

	"golang.org/x/crypto/ssh"
)

// GenerateHostKey creates an OpenSSH ed25519 host key.
func GenerateHostKey() ([]byte, string, error) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, "", err
	}
	block, err := ssh.MarshalPrivateKey(key, "tnl managed ssh")
	if err != nil {
		return nil, "", err
	}
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		return nil, "", err
	}
	return pem.EncodeToMemory(block), string(ssh.MarshalAuthorizedKey(signer.PublicKey())), nil
}

// ParseHostKey reads an unencrypted OpenSSH private key.
func ParseHostKey(privatePEM []byte) (ssh.Signer, error) { return ssh.ParsePrivateKey(privatePEM) }

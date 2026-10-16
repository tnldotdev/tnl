package authorization

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestSSHHostKeyValid(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ssh.NewPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	encoded := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))
	signer, err := ssh.NewSignerFromKey(private)
	if err != nil {
		t.Fatal(err)
	}
	certificate := &ssh.Certificate{Key: key, CertType: ssh.HostCert, ValidBefore: ssh.CertTimeInfinity}
	if err := certificate.SignCert(rand.Reader, signer); err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKey(private, "host")
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{encoded, encoded + " host@example", encoded + "\n"} {
		if !SSHHostKeyValid(value) {
			t.Errorf("valid public host key rejected")
		}
	}
	for name, value := range map[string]string{
		"empty":           "",
		"private":         string(pem.EncodeToMemory(block)),
		"certificate":     string(ssh.MarshalAuthorizedKey(certificate)),
		"options":         "restrict " + encoded,
		"command option":  "command=\"echo hi\" " + encoded,
		"multiple keys":   encoded + "\n" + encoded,
		"trailing line":   encoded + "\ntrailing data",
		"leading line":    "ignored data\n" + encoded,
		"malformed":       "ssh-ed25519 invalid",
		"null comment":    encoded + " comment\x00",
		"other algorithm": strings.Replace(encoded, "ssh-ed25519", "ssh-rsa", 1),
	} {
		t.Run(name, func(t *testing.T) {
			if SSHHostKeyValid(value) {
				t.Fatal("invalid public host key accepted")
			}
		})
	}
}

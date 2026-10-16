package managedssh

import (
	"bytes"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestHostKeyRoundTrip(t *testing.T) {
	private, public, err := GenerateHostKey()
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ParseHostKey(private)
	if err != nil {
		t.Fatal(err)
	}
	key, _, _, rest, err := ssh.ParseAuthorizedKey([]byte(public))
	if err != nil || len(rest) != 0 || !bytes.Equal(key.Marshal(), signer.PublicKey().Marshal()) || key.Type() != ssh.KeyAlgoED25519 {
		t.Fatal("host key does not round trip", err)
	}
	if _, err := ParseHostKey([]byte("invalid")); err == nil {
		t.Fatal("accepted invalid private key")
	}
}

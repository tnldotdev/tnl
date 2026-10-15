package visitorcert

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/opaqueid"
)

func TestClientExportProtectsPrivateFilesAndNeverOverwrites(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	urlID, _ := opaqueid.New(opaqueid.PublicURLPrefix)
	identityID, _ := opaqueid.New(opaqueid.IdentityPrefix)
	issuer, err := New(bytes.Repeat([]byte{2}, 32))
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		t.Fatal(err)
	}
	expires := now.Add(time.Hour)
	certificate, err := issuer.Issue(csr, urlID, identityID, expires, now)
	if err != nil {
		t.Fatal(err)
	}
	private, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	privatePEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private})
	export := func(directory string) error {
		return Export(directory, privatePEM, certificate, issuer.CertificatePEM(), key, urlID, expires, now)
	}
	directory := filepath.Join(t.TempDir(), "client")
	if err = export(directory); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(directory)
	if err != nil || info.Mode().Perm() != 0700 {
		t.Fatal("directory permissions", err)
	}
	for _, name := range []string{"client-key.pem", "client-cert.pem", "issuer.pem"} {
		info, err := os.Stat(filepath.Join(directory, name))
		if err != nil || info.Mode().Perm() != 0600 {
			t.Fatal("file permissions", name, err)
		}
	}
	if err = export(directory); !errors.Is(err, os.ErrExist) {
		t.Fatal("existing certificate overwritten", err)
	}
	unsafe := filepath.Join(t.TempDir(), "unsafe")
	if err = os.Mkdir(unsafe, 0755); err != nil {
		t.Fatal(err)
	}
	if err = export(unsafe); err == nil {
		t.Fatal("exported to non-private directory")
	}
	partial := filepath.Join(t.TempDir(), "partial")
	if err = os.Mkdir(partial, 0700); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(partial, "client-cert.pem"), []byte("existing user file"), 0600); err != nil {
		t.Fatal(err)
	}
	if err = export(partial); !errors.Is(err, os.ErrExist) {
		t.Fatal(err)
	}
	if _, err = os.Stat(filepath.Join(partial, "client-key.pem")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("partial private key retained", err)
	}
	existing, err := os.ReadFile(filepath.Join(partial, "client-cert.pem"))
	if err != nil || string(existing) != "existing user file" {
		t.Fatal("user file changed", err)
	}
	wrong := filepath.Join(t.TempDir(), "wrong-scope")
	wrongID, _ := opaqueid.New(opaqueid.PublicURLPrefix)
	if err = Export(wrong, privatePEM, certificate, issuer.CertificatePEM(), key, wrongID, expires, now); !errors.Is(err, ErrInvalidCertificate) {
		t.Fatal("wrong scope exported", err)
	}
	if _, err = os.Stat(wrong); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("invalid response touched disk", err)
	}
}

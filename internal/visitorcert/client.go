package visitorcert

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"os"
	"strings"
	"time"

	"github.com/tnldotdev/tnl/internal/opaqueid"
)

// Export writes only local files. the private key is never part of a control
// request or response; callers render the public URL, directory and expiry.
func Export(directory string, privatePEM, certificatePEM, issuerPEM []byte, key *ecdsa.PrivateKey, urlID string, expires, now time.Time) (retErr error) {
	if key == nil {
		return ErrInvalidCertificate
	}
	block, rest := pem.Decode(certificatePEM)
	if block == nil || block.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
		return ErrInvalidCertificate
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return ErrInvalidCertificate
	}
	public, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok || !public.Equal(&key.PublicKey) || !leaf.NotAfter.Equal(expires) || !leaf.NotAfter.After(now) || leaf.NotAfter.Sub(leaf.NotBefore) > MaxLifetime {
		return ErrInvalidCertificate
	}
	privateBlock, rest := pem.Decode(privatePEM)
	if privateBlock == nil || privateBlock.Type != "PRIVATE KEY" || len(bytes.TrimSpace(rest)) != 0 {
		return ErrInvalidCertificate
	}
	parsed, err := x509.ParsePKCS8PrivateKey(privateBlock.Bytes)
	if err != nil {
		return ErrInvalidCertificate
	}
	parsedKey, ok := parsed.(*ecdsa.PrivateKey)
	if !ok || !parsedKey.Equal(key) {
		return ErrInvalidCertificate
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(issuerPEM) {
		return ErrInvalidCertificate
	}
	if _, err = leaf.Verify(x509.VerifyOptions{Roots: roots, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		return ErrInvalidCertificate
	}
	if !opaqueid.Valid(urlID, opaqueid.PublicURLPrefix) || len(leaf.URIs) != 1 {
		return ErrInvalidCertificate
	}
	scope := leaf.URIs[0]
	identity, found := strings.CutPrefix(scope.Path, "/"+urlID+"/")
	if !found || !opaqueid.Valid(identity, opaqueid.IdentityPrefix) || scope.Scheme != "tnl" || scope.Host != "visitor" || scope.User != nil || scope.RawPath != "" || scope.RawQuery != "" || scope.Fragment != "" || scope.Opaque != "" {
		return ErrInvalidCertificate
	}
	madeDirectory := false
	if err = os.Mkdir(directory, 0700); err == nil {
		madeDirectory = true
	} else if !errors.Is(err, os.ErrExist) {
		return err
	}
	info, err := os.Lstat(directory)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0700 {
		return errors.New("certificate directory must have mode 0700")
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		return err
	}
	defer root.Close()
	opened, err := root.Stat(".")
	if err != nil {
		return err
	}
	if !os.SameFile(info, opened) {
		return errors.New("certificate directory changed")
	}
	created := []string{}
	defer func() {
		if retErr != nil {
			for _, name := range created {
				_ = root.Remove(name)
			}
			if madeDirectory {
				_ = os.Remove(directory)
			}
		}
	}()
	for _, file := range []struct {
		Name string
		Data []byte
	}{{"client-key.pem", privatePEM}, {"client-cert.pem", certificatePEM}, {"issuer.pem", issuerPEM}} {
		f, err := root.OpenFile(file.Name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return err
		}
		created = append(created, file.Name)
		n, writeErr := f.Write(file.Data)
		if n != len(file.Data) && writeErr == nil {
			writeErr = io.ErrShortWrite
		}
		syncErr := f.Sync()
		closeErr := f.Close()
		if err = errors.Join(writeErr, syncErr, closeErr); err != nil {
			return err
		}
	}
	return nil
}

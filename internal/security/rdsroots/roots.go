// package rdsroots owns the pinned, regional Amazon RDS root trust library.
// runtime lookups are offline and never add system or other regions' roots.
package rdsroots

import (
	"crypto/sha256"
	"crypto/x509"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"strings"

	"github.com/tnldotdev/tnl/internal/naming"
)

//go:embed bundles.json
var data []byte

//go:embed source.pem
var source []byte

const Source = "https://truststore.pki.rds.amazonaws.com/global/global-bundle.pem"

type Catalog struct {
	Source    string            `json:"source"`
	SHA256    string            `json:"sha256"`
	Retrieved string            `json:"retrieved"`
	Regions   map[string]Region `json:"regions"`
}
type Region struct {
	PEM    string `json:"pem"`
	SHA256 string `json:"sha256"`
}

var ErrBundle = errors.New("pinned regional RDS root bundle is unavailable or invalid")

// BundleForHostname selects only the supplied RDS endpoint's region, offline.
// custom DNS aliases need explicit CA material because they do not identify it.
func BundleForHostname(hostname string) (string, error) {
	canonical, err := naming.CanonicalizeHostname(hostname)
	if err != nil || canonical != hostname {
		return "", ErrBundle
	}
	suffix := ".rds.amazonaws.com"
	china := strings.HasSuffix(hostname, suffix+".cn")
	if china {
		suffix += ".cn"
	}
	if !strings.HasSuffix(hostname, suffix) {
		return "", ErrBundle
	}
	parts := strings.Split(strings.TrimSuffix(hostname, suffix), ".")
	if len(parts) < 3 || strings.HasPrefix(parts[len(parts)-1], "cn-") != china {
		return "", ErrBundle
	}
	return Bundle(parts[len(parts)-1])
}

func Bundle(region string) (string, error) {
	var catalog Catalog
	if json.Unmarshal(data, &catalog) != nil || catalog.Source != Source || len(catalog.SHA256) != 64 {
		return "", ErrBundle
	}
	sourceSum := sha256.Sum256(source)
	if hex.EncodeToString(sourceSum[:]) != catalog.SHA256 {
		return "", ErrBundle
	}
	bundle, ok := catalog.Regions[region]
	if !ok || len(bundle.PEM) == 0 || len(bundle.PEM) > 64<<10 {
		return "", ErrBundle
	}
	sum := sha256.Sum256([]byte(bundle.PEM))
	if hex.EncodeToString(sum[:]) != bundle.SHA256 {
		return "", ErrBundle
	}
	remaining := []byte(bundle.PEM)
	for len(remaining) != 0 {
		block, rest := pem.Decode(remaining)
		if block == nil || block.Type != "CERTIFICATE" {
			return "", ErrBundle
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil || !cert.IsCA || cert.CheckSignatureFrom(cert) != nil || !strings.HasPrefix(cert.Subject.CommonName, "Amazon RDS "+region+" Root CA ") {
			return "", ErrBundle
		}
		remaining = rest
	}
	return bundle.PEM, nil
}

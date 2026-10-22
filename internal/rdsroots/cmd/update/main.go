// command update refreshes the vendored public certificate data. it is an
// explicit maintainer operation, never go:generate or publisher runtime work.
package main

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/tnldotdev/tnl/internal/rdsroots"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run() error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, rdsroots.Source, nil)
	if err != nil {
		return err
	}
	client := &http.Client{Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("RDS trust source returned HTTP %d", response.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, (1<<20)+1))
	if err != nil {
		return err
	}
	if len(data) > 1<<20 {
		return fmt.Errorf("RDS trust source exceeds bounds")
	}
	sum := sha256.Sum256(data)
	original := append([]byte(nil), data...)
	catalog := rdsroots.Catalog{Source: rdsroots.Source, SHA256: hex.EncodeToString(sum[:]), Retrieved: time.Now().UTC().Format(time.RFC3339), Regions: map[string]rdsroots.Region{}}
	pattern := regexp.MustCompile(`^Amazon RDS ([a-z]{2}(?:-[a-z]+)+-[0-9]+) Root CA (?:RSA2048|RSA4096|ECC384) G1$`)
	for len(data) > 0 {
		block, rest := pem.Decode(data)
		if block == nil || block.Type != "CERTIFICATE" {
			return fmt.Errorf("RDS source contains invalid PEM")
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil || !cert.IsCA || cert.CheckSignatureFrom(cert) != nil {
			return fmt.Errorf("RDS source contains a non-root certificate")
		}
		// preview environments are a separate trust boundary, never production roots.
		if strings.HasPrefix(cert.Subject.CommonName, "Amazon RDS Preview ") || strings.HasPrefix(cert.Subject.CommonName, "Amazon RDS Beta ") {
			data = rest
			continue
		}
		match := pattern.FindStringSubmatch(cert.Subject.CommonName)
		if len(match) != 2 {
			return fmt.Errorf("RDS source contains an unrecognized root: %q", cert.Subject.CommonName)
		}
		region := catalog.Regions[match[1]]
		region.PEM += string(pem.EncodeToMemory(block))
		catalog.Regions[match[1]] = region
		data = rest
	}
	if len(catalog.Regions) < 25 {
		return fmt.Errorf("RDS source unexpectedly omits regions")
	}
	for key, region := range catalog.Regions {
		sum := sha256.Sum256([]byte(region.PEM))
		region.SHA256 = hex.EncodeToString(sum[:])
		catalog.Regions[key] = region
	}
	encoded, err := json.MarshalIndent(catalog, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile("internal/rdsroots/source.pem", original, 0644); err != nil {
		return err
	}
	return os.WriteFile("internal/rdsroots/bundles.json", append(encoded, '\n'), 0644)
}

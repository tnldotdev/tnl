package rdsroots

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"strings"
	"testing"
	"time"
)

func TestPinnedOfficialRegionalRootCatalog(t *testing.T) {
	var catalog Catalog
	if err := json.Unmarshal(data, &catalog); err != nil {
		t.Fatal(err)
	}
	if catalog.Source != Source || catalog.SHA256 != "90a6f1a7978a1b1b096dca6c57511ca48d3b8cf052f8e704baf358f34ea2f21b" {
		t.Fatal("official source changed without review")
	}
	if _, err := time.Parse(time.RFC3339, catalog.Retrieved); err != nil {
		t.Fatal(err)
	}
	if len(catalog.Regions) < 25 || len(catalog.Regions) > 64 {
		t.Fatal("unexpected root catalog size")
	}
	// each selected root must be byte-identical to a certificate in the pinned
	// original official source, not merely a certificate with a matching CN.
	official := map[[32]byte]bool{}
	for rest := source; len(rest) != 0; {
		block, next := pem.Decode(rest)
		if block == nil {
			t.Fatal("invalid official source PEM")
		}
		official[sha256.Sum256(block.Bytes)] = true
		rest = next
	}
	for region := range catalog.Regions {
		bundle, err := Bundle(region)
		if err != nil {
			t.Fatal(region, err)
		}
		count := 0
		for rest := []byte(bundle); len(rest) != 0; count++ {
			block, next := pem.Decode(rest)
			if block == nil {
				t.Fatal("invalid PEM")
			}
			if !official[sha256.Sum256(block.Bytes)] {
				t.Fatal("regional root did not come from pinned AWS source")
			}
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				t.Fatal(err)
			}
			if !cert.IsCA || cert.CheckSignatureFrom(cert) != nil || !strings.HasPrefix(cert.Subject.CommonName, "Amazon RDS "+region+" Root CA ") || cert.NotAfter.Before(time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)) {
				t.Fatal("wrong region, untrusted, or expired root")
			}
			rest = next
		}
		if count < 1 || count > 3 {
			t.Fatal("unexpected number of regional roots")
		}
	}
	for _, region := range []string{"unknown", "us-east-1/../../", "https://private.invalid", "us-east-1-preview"} {
		if _, err := Bundle(region); err == nil {
			t.Fatal("unknown region accepted")
		}
	}
	a, _ := Bundle("us-east-1")
	b, _ := Bundle("us-west-2")
	if a == b {
		t.Fatal("regional roots were combined")
	}
}

func TestEndpointSelectsOnlyItsRegionalRoots(t *testing.T) {
	for _, entry := range []struct{ host, region string }{
		{"orders.abc123.us-east-1.rds.amazonaws.com", "us-east-1"},
		{"orders.cluster-ro-abc.us-west-2.rds.amazonaws.com", "us-west-2"},
		{"orders.abc123.eu-central-1.rds.amazonaws.com", "eu-central-1"},
	} {
		bundle, err := BundleForHostname(entry.host)
		want, _ := Bundle(entry.region)
		if err != nil || bundle != want {
			t.Fatal("wrong regional root selection", entry.host, err)
		}
	}
	for _, hostname := range []string{
		"db.internal", "127.0.0.1", "rds.amazonaws.com", "us-east-1.rds.amazonaws.com",
		"orders.abc.us-east-1.rds.amazonaws.com.evil.invalid", "orders.abc.unknown.rds.amazonaws.com",
		"orders.abc.cn-north-1.rds.amazonaws.com", "orders.abc.us-east-1.rds.amazonaws.com.cn",
		"orders.abc.us-east-1.rds.amazonaws.com.", "ORDERS.abc.us-east-1.rds.amazonaws.com",
		// the pinned global catalog does not contain China or GovCloud roots.
		"orders.abc.cn-north-1.rds.amazonaws.com.cn", "orders.abc.us-gov-west-1.rds.amazonaws.com",
	} {
		if _, err := BundleForHostname(hostname); err == nil {
			t.Fatal("unrecognized endpoint accepted", hostname)
		}
	}
}

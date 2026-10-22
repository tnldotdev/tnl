package kubernetes

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

type discoveryFunc func(context.Context, string, string) (DiscoveredCluster, error)

func (f discoveryFunc) DescribeEKS(ctx context.Context, region, cluster string) (DiscoveredCluster, error) {
	return f(ctx, region, cluster)
}

func TestEKSDiscoveryOwnsIndependentClusterTrust(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, ca, ca, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	found := DiscoveredCluster{Endpoint: "https://cluster.eks.example.test", CertificateAuthorityData: base64.StdEncoding.EncodeToString(caPEM)}
	target, err := ResolveEKS(t.Context(), discoveryFunc(func(_ context.Context, region, cluster string) (DiscoveredCluster, error) {
		if region != "us-east-1" || cluster != "shop" {
			t.Fatal("discovery changed the cluster selector")
		}
		return found, nil
	}), "us-east-1", "shop")
	if err != nil || target.Address != "cluster.eks.example.test:443" || target.TLS.InsecureSkipVerify || target.TLS.ServerName != "cluster.eks.example.test" || target.Trust.Digest == "" || target.Trust.System {
		t.Fatal("invalid independent cluster trust", err)
	}
	verifier, err := target.Trust.CAVerifier()
	if err != nil || !verifier.RootCAs.Equal(target.TLS.RootCAs) {
		t.Fatal("explicit cluster CA trust included unrelated roots", err)
	}
	encodedKey, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	found.CertificateAuthorityData = base64.StdEncoding.EncodeToString(append(caPEM, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: encodedKey})...))
	if _, err := VerifyTarget(found); err == nil {
		t.Fatal("discovery accepted a private key as public CA material")
	}
	for _, endpoint := range []string{"http://cluster.example.test", "https://user:secret@cluster.example.test", "https://cluster.example.test/path", "https://cluster.example.test?token=secret"} {
		found.Endpoint = endpoint
		if _, err := VerifyTarget(found); err == nil {
			t.Fatal("unsafe cluster endpoint accepted")
		}
	}
}

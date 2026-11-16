package state

import (
	"crypto/x509"
	"errors"
	"strings"
	"testing"

	"github.com/tnldotdev/tnl/internal/security/rdsroots"
	"github.com/tnldotdev/tnl/internal/security/targettrust"
)

func TestDeploymentKubernetesTargetRequiresTLS(t *testing.T) {
	if _, err := normalizeDeploymentTarget(t.Context(), "kube", "kubernetes", DeploymentTarget{Address: "cluster.example:6443"}); !errors.Is(err, ErrProjectConfigurationInvalid) {
		t.Fatal("Kubernetes target without verified TLS accepted", err)
	}
	service, err := normalizeDeploymentTarget(t.Context(), "kube", "kubernetes", DeploymentTarget{
		Address: "cluster.example:6443", TLS: &DeploymentTargetTLS{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if service.Target != "cluster.example:6443" || service.TargetTLS == nil || service.TargetTLS.Hostname != "cluster.example" {
		t.Fatal("Kubernetes target lost its captured TLS trust", service)
	}
	for _, protocol := range []string{"http", "tcp", "postgres", "mysql"} {
		t.Run(protocol, func(t *testing.T) {
			service, err := normalizeDeploymentTarget(t.Context(), "service", protocol, DeploymentTarget{Address: "target.internal:1234"})
			if err != nil || service.TargetTLS != nil {
				t.Fatal("non-Kubernetes protocol required or enabled target TLS", service, err)
			}
		})
	}
}

func TestDeploymentTargetUsesCapturedTrustWithoutDiscovery(t *testing.T) {
	for _, protocol := range []string{"postgres", "mysql"} {
		service, err := normalizeDeploymentTarget(t.Context(), "db", protocol, DeploymentTarget{
			Address: "orders.abc.us-east-1.rds.amazonaws.com:5432", TLS: &DeploymentTargetTLS{CA: "aws-rds"},
		})
		if err != nil || service.TargetDiscovery != nil || service.TargetTLS == nil || service.TargetTLS.Hostname != "orders.abc.us-east-1.rds.amazonaws.com" {
			t.Fatal("RDS target was not captured offline", service, err)
		}
		trust := service.TargetTLS
		snapshot, err := (targettrust.Declaration{Hostname: trust.Hostname, CAPEM: []byte(trust.CAPEM), Digest: trust.Digest}).Snapshot()
		if err != nil || snapshot.System || !strings.Contains(trust.CAPEM, "BEGIN CERTIFICATE") {
			t.Fatal("RDS trust did not use the shared verified snapshot", err)
		}
		verifier, err := snapshot.CAVerifier()
		bundle, bundleErr := rdsroots.Bundle("us-east-1")
		expected := x509.NewCertPool()
		if bundleErr != nil || !expected.AppendCertsFromPEM([]byte(bundle)) {
			t.Fatal("expected pinned roots unavailable", bundleErr)
		}
		if err != nil || verifier.InsecureSkipVerify || verifier.ServerName != trust.Hostname || !verifier.RootCAs.Equal(expected) {
			t.Fatal("RDS trust widened or disabled hostname verification", err)
		}
	}
	for _, target := range []DeploymentTarget{
		{Address: "db.internal:5432", TLS: &DeploymentTargetTLS{CA: "aws-rds"}},
		{Address: "orders.abc.us-east-1.rds.amazonaws.com:5432", TLS: &DeploymentTargetTLS{CA: "aws-rds", Hostname: "different.internal"}},
		{Address: "db.internal:5432", TLS: &DeploymentTargetTLS{CA: "https://private.invalid/roots.pem"}},
		{Address: "db.internal:5432", TLS: &DeploymentTargetTLS{CA: "/private/roots.pem"}},
		{Address: "rds:orders"},
	} {
		if _, err := normalizeDeploymentTarget(t.Context(), "db", "postgres", target); err == nil {
			t.Fatal("invalid target or remote/local trust source accepted", target.Address)
		}
	}
}

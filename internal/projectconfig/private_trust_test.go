package projectconfig

import (
	"testing"

	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/privatetrust"
)

func TestPrivateTrustCaptureUsesTargetOrExplicitCertificateHostname(t *testing.T) {
	protocol, host, serviceName, port := "postgres", "provider.example", "db", 5432
	address := config.Target("127.0.0.1:5432")
	project := Project{Root: t.TempDir(), Config: config.TNL{Services: config.Services{
		"db": {Protocol: &protocol, Target: &config.ServiceTarget{Type: "address", Address: &address}},
	}}}
	cache := privatetrust.NewCache(nil)
	if snapshot, err := project.CaptureServiceTrust(t.Context(), cache, "db", ""); err != nil || snapshot != nil {
		t.Fatalf("protocol label enabled TLS: %v", err)
	}
	service := project.Config.Services["db"]
	service.Target.TLS = &config.TargetTLS{}
	project.Config.Services["db"] = service
	snapshot, err := project.CaptureServiceTrust(t.Context(), cache, "db", "ignored.example:9999")
	if err != nil || snapshot.Hostname != "127.0.0.1" || !snapshot.System {
		t.Fatalf("target certificate identity: %+v %v", snapshot, err)
	}
	firstDigest := snapshot.Digest
	service.Target = &config.ServiceTarget{Type: "compose", Service: &serviceName, Port: &port}
	service.Target.TLS = &config.TargetTLS{ServerName: &host}
	project.Config.Services["db"] = service
	snapshot, err = project.CaptureServiceTrust(t.Context(), cache, "db", "127.0.0.1:49152")
	if err != nil || snapshot.Hostname != host || snapshot.Digest == firstDigest {
		t.Fatalf("explicit provider identity: %+v %v", snapshot, err)
	}
	if _, err := project.CaptureServiceTrust(t.Context(), cache, "db", ""); err == nil {
		t.Fatal("missing private discovery accepted")
	}
}

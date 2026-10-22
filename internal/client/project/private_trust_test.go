package projectconfig

import (
	"testing"

	"github.com/tnldotdev/tnl/internal/config"
	privatetrust "github.com/tnldotdev/tnl/internal/security/targettrust"
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
	snapshot, err := project.CaptureServiceTrust(t.Context(), cache, "db", "127.0.0.1:5432")
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

func TestPrivateTrustCaptureUsesResolvedContainerHTTPOrigin(t *testing.T) {
	for _, target := range []*config.ServiceTarget{
		{Type: "compose", Service: new("web"), Port: new(443), TLS: &config.TargetTLS{}},
		{Type: "docker", Container: new("web"), Port: new(443), TLS: &config.TargetTLS{}},
	} {
		t.Run(target.Type, func(t *testing.T) {
			project := Project{Root: t.TempDir(), Config: config.TNL{Services: config.Services{"web": {Target: target}}}}
			resolved, err := project.ResolvePublish("web", "127.0.0.1:49152")
			if err != nil {
				t.Fatal(err)
			}
			if string(*resolved.Target) != "https://127.0.0.1:49152" {
				t.Fatalf("resolved container target: %+v", resolved)
			}
			trust, err := project.CaptureServiceTrust(t.Context(), nil, "web", string(*resolved.Target))
			if err != nil || trust == nil || trust.Hostname != "127.0.0.1" || !trust.System {
				t.Fatalf("resolved target trust: %+v %v", trust, err)
			}
			applied, err := project.CaptureTargetTrust(t.Context(), nil, "web", "127.0.0.1:49152")
			if err != nil {
				t.Fatal(err)
			}
			private, err := applied.PrivateSnapshot()
			if err != nil || private.Digest != trust.Digest {
				t.Fatalf("declared and resolved target trust disagree: %v", err)
			}
		})
	}
}

func TestPrivateTrustRequiresCanonicalResolvedHTTPSOrigin(t *testing.T) {
	project := Project{Root: t.TempDir(), Config: config.TNL{Services: config.Services{
		"web": {Target: &config.ServiceTarget{Type: "app", TLS: &config.TargetTLS{}}},
	}}}
	for _, target := range []string{"http://127.0.0.1:443", "https://127.0.0.1:443?", "https://127.0.0.1:443#", "https://127.0.0.1:443/", "https://user@127.0.0.1:443", "127.0.0.1:443"} {
		if _, err := project.CaptureServiceTrust(t.Context(), nil, "web", target); err == nil {
			t.Fatalf("noncanonical target trust accepted: %q", target)
		}
	}
}

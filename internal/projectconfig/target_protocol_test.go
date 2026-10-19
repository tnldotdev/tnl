package projectconfig

import (
	"testing"

	"github.com/tnldotdev/tnl/internal/config"
)

func TestTargetTrustSnapshotsAgreeForAllProtocolsAndPublisherGroups(t *testing.T) {
	for _, protocol := range []string{"http", "tcp", "postgres", "mysql"} {
		for _, publisher := range []string{"local", "production"} {
			t.Run(protocol+"/"+publisher, func(t *testing.T) {
				host := "target.internal"
				address := config.Target("127.0.0.1:5432")
				if protocol == "http" {
					address = "https://127.0.0.1:8443"
				}
				project := Project{Root: t.TempDir(), Config: config.TNL{Publishers: map[string]config.Publisher{"production": {}}, Services: config.Services{
					"service": {Publisher: &publisher, Protocol: &protocol, Target: &config.ServiceTarget{Type: "address", Address: &address, TLS: &config.TargetTLS{ServerName: &host}}},
				}}}
				local, err := project.CaptureServiceTrust(t.Context(), nil, "service", "")
				if err != nil {
					t.Fatal(err)
				}
				applied, err := project.CaptureTargetTrust(t.Context(), nil, "service", "")
				if err != nil {
					t.Fatal(err)
				}
				remote, err := applied.PrivateSnapshot()
				if err != nil || remote.Digest != local.Digest || remote.Hostname != host || !remote.System {
					t.Fatalf("local and applied trust diverged: %+v %+v %v", local, remote, err)
				}
			})
		}
	}
}

func TestDeferredAppTargetTrustRequiresKnownCertificateIdentity(t *testing.T) {
	host := "app.internal"
	project := Project{Root: t.TempDir(), Config: config.TNL{Services: config.Services{
		"app": {Target: &config.ServiceTarget{Type: "app", TLS: &config.TargetTLS{ServerName: &host}}},
	}}}
	if snapshot, err := project.CaptureTargetTrust(t.Context(), nil, "app", ""); err != nil || snapshot.Hostname != host {
		t.Fatalf("deferred app trust: %+v %v", snapshot, err)
	}
	if _, err := project.ResolvePublish("app", "http://127.0.0.1:3000"); err == nil {
		t.Fatal("TLS declaration accepted a plaintext app listener")
	}
	if _, err := project.ResolvePublish("app", "https://127.0.0.1:3000"); err != nil {
		t.Fatal(err)
	}
	project.Config.Services["app"].Target.TLS.ServerName = nil
	if _, err := project.CaptureTargetTrust(t.Context(), nil, "app", ""); err == nil {
		t.Fatal("deferred app captured an unknown certificate identity")
	}
	project.Config.Services["app"].Target.TLS = nil
	if _, err := project.ResolvePublish("app", "https://127.0.0.1:3000"); err == nil {
		t.Fatal("HTTPS app listener became an unverified plaintext backend")
	}
}

package main

import (
	"encoding/json"
	"encoding/pem"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tnldotdev/tnl/internal/config"
	installedjobs "github.com/tnldotdev/tnl/internal/installed"
	publisheridentity "github.com/tnldotdev/tnl/internal/publisher/identity"
	targetplan "github.com/tnldotdev/tnl/internal/publisher/target"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestScopedPrivateInstallCapturesTargetTrustForRuntime(t *testing.T) {
	registry, authority, base, selection := backgroundFixture(t)
	target := httptest.NewTLSServer(nil)
	defer target.Close()
	ca := filepath.Join(t.TempDir(), "target.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: target.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	authority.identity.Kind = authorityv1.Service
	flags := publishCommand{Target: target.Listener.Addr().String(), Protocol: "tcp", TargetTLSName: target.Certificate().DNSNames[0], tunnelFlags: tunnelFlags{TargetCAFile: ca, InspectionMode: config.InspectionNone}}
	flags.ServerURL = "https://control.example"
	trust, err := captureServiceTargetTrust(t.Context(), flags, controlv1.Tcp, flags.Target)
	if err != nil {
		t.Fatal(err)
	}
	base.service.Name, base.service.Protocol = "database", controlv1.Tcp
	base.service.TargetTls = publisheridentity.ServiceTargetTLS(trust)
	base.service.Endpoint = &controlv1.ServiceEndpoint{Hostname: "database.worktree.member.example.test", Port: 25443}
	clients := func(installedjobs.Job) (installedjobs.PublisherClients, publisheridentity.EnrollmentAuthority, error) {
		return backgroundClients(base), authority, nil
	}
	if err := installBackgroundJob(t.Context(), registry, flags, selection, backgroundPublishFlags{Install: true}, strings.NewReader(""), clients, nil); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(ca); err != nil {
		t.Fatal(err)
	}
	jobs, err := registry.List(t.Context())
	if err != nil || len(jobs) != 1 {
		t.Fatalf("installed private jobs: %+v %v", jobs, err)
	}
	job := jobs[0]
	if job.Kind != installedjobs.KindService || job.Protocol != config.ProtocolTCP || job.Trust == nil || job.Trust.Digest != trust.Digest {
		t.Fatalf("private target trust was split or lost: %+v", job)
	}
	encoded, err := json.Marshal(job)
	if err != nil || strings.Contains(string(encoded), `"target_tls_name"`) || strings.Contains(string(encoded), `"target_ca_pem"`) {
		t.Fatal("private target trust retained a second trust representation", err)
	}
	if err := targetplan.PreflightPrivate(t.Context(), job.TargetPlan()); err != nil {
		t.Fatalf("installed preflight reopened a deleted source: %v", err)
	}
}

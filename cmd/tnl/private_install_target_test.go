package main

import (
	"context"
	"encoding/pem"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tnldotdev/tnl/internal/client/supervisor"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	publisheridentity "github.com/tnldotdev/tnl/internal/publisher/identity"
	targetplan "github.com/tnldotdev/tnl/internal/publisher/target"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type installedServiceTargetControl struct {
	*backgroundControl
	service controlv1.Service
}

func (c installedServiceTargetControl) GetPublisherService(context.Context, string) (controlv1.Service, error) {
	return c.service, nil
}

func TestScopedPrivateInstallCapturesTargetTrustForRuntime(t *testing.T) {
	registry, authority, base, selection := backgroundFixture(t)
	target := httptest.NewTLSServer(nil)
	defer target.Close()
	ca := filepath.Join(t.TempDir(), "target.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: target.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	id, err := opaqueid.New(opaqueid.ServicePrefix)
	if err != nil {
		t.Fatal(err)
	}
	authority.identity.Kind, authority.identity.ServiceId, authority.identity.PublicUrlId = authorityv1.Service, &id, nil
	flags := publishCommand{Target: target.Listener.Addr().String(), Protocol: "tcp", TargetTLSName: target.Certificate().DNSNames[0], tunnelFlags: tunnelFlags{TargetCAFile: ca, InspectionMode: config.InspectionNone}}
	flags.ServerURL = "https://control.example"
	trust, err := captureServiceTargetTrust(t.Context(), flags, controlv1.Tcp, flags.Target)
	if err != nil {
		t.Fatal(err)
	}
	control := installedServiceTargetControl{backgroundControl: base, service: controlv1.Service{Id: id, TeamId: authority.identity.TeamId, Name: "database", Enabled: true, Protocol: controlv1.Tcp, TrustRevision: 1, TargetTls: publisheridentity.ServiceTargetTLS(trust), Endpoint: &controlv1.ServiceEndpoint{Hostname: "database.worktree.member.example.test", Port: 25443}}}
	clients := func(supervisor.Job) (publisheridentity.NativeControl, publisheridentity.EnrollmentAuthority, error) {
		return control, authority, nil
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
	if job.Kind != supervisor.KindService || job.Protocol != config.ProtocolTCP || job.Trust == nil || job.Trust.Digest != trust.Digest || job.TargetTLSName != "" || len(job.TargetCAPEM) != 0 {
		t.Fatalf("private target trust was split or lost: %+v", job)
	}
	if err := targetplan.PreflightPrivate(t.Context(), job.TargetPlan()); err != nil {
		t.Fatalf("installed preflight reopened a deleted source: %v", err)
	}
}

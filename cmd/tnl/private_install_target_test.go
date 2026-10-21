package main

import (
	"context"
	"encoding/pem"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/opaqueid"
	nativeauth "github.com/tnldotdev/tnl/internal/publisheridentity/native"
	"github.com/tnldotdev/tnl/internal/publisherjob"
	"github.com/tnldotdev/tnl/pkg/api/authorityv1"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

type installedPrivateTargetControl struct {
	*backgroundControl
	service controlv1.PrivateService
}

func (c installedPrivateTargetControl) GetPublisherPrivateService(context.Context, string) (controlv1.PrivateService, error) {
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
	id, err := opaqueid.New(opaqueid.PrivateServicePrefix)
	if err != nil {
		t.Fatal(err)
	}
	authority.identity.Kind, authority.identity.PrivateServiceId, authority.identity.PublicUrlId = authorityv1.PrivateService, &id, nil
	flags := publishCommand{Target: target.Listener.Addr().String(), Protocol: "tcp", TargetTLSName: target.Certificate().DNSNames[0], tunnelFlags: tunnelFlags{TargetCAFile: ca, InspectionMode: config.InspectionNone}}
	flags.ServerURL = "https://control.example"
	trust, err := capturePrivateTargetTrust(t.Context(), flags, controlv1.Tcp, flags.Target)
	if err != nil {
		t.Fatal(err)
	}
	control := installedPrivateTargetControl{backgroundControl: base, service: controlv1.PrivateService{Id: id, TeamId: authority.identity.TeamId, Name: "database", Enabled: true, Protocol: controlv1.Tcp, TrustRevision: 1, TargetTls: nativeauth.PrivateServiceTLS(trust), ManagedTls: &controlv1.ManagedServiceTLS{Hostname: "database.worktree.member.example.test", Port: 25443}}}
	clients := func(publisherjob.Job) (nativeauth.NativeControl, nativeauth.EnrollmentAuthority, error) {
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
	if job.Kind != publisherjob.KindPrivateService || job.Protocol != config.ProtocolTCP || job.Trust == nil || job.Trust.Digest != trust.Digest || job.TargetTLSName != "" || len(job.TargetCAPEM) != 0 {
		t.Fatalf("private target trust was split or lost: %+v", job)
	}
	if err := publisherjob.PreflightPrivate(t.Context(), job); err != nil {
		t.Fatalf("installed preflight reopened a deleted source: %v", err)
	}
}

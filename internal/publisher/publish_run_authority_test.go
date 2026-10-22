package publisher

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/security/credentials"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func testRunAuthority(t *testing.T, client PublicURLControlClient, setup controlv1.PublishRunSetup) publicRunAuthority {
	t.Helper()
	config := testRunConfig(client, setup)
	authority, err := bindPublicRun(config, setup)
	if err != nil {
		t.Fatal(err)
	}
	return authority
}

func testRunConfig(client PublicURLControlClient, setup controlv1.PublishRunSetup) Config {
	publicURL := setup.PublicUrl
	config := Config{Control: client, Hostname: publicURL.CanonicalHostname, TeamID: publicURL.TeamId, DomainID: publicURL.DomainId, PublicURLScope: publicURL.PublicUrlScope, Purpose: publicURL.Purpose, Ephemeral: publicURL.Ephemeral}
	if publicURL.MembershipId != nil {
		config.MembershipID = *publicURL.MembershipId
	}
	return config
}

func heartbeatTestAuthority(client PublicURLControlClient, runID string, token credentials.PublishRunToken) publicRunAuthority {
	return publicRunAuthority{client: client, identity: PublishRunIdentity{PublishRunID: runID, Number: 1}, token: token}
}

func TestBoundPublicRunKeepsIdentityTokenAndCertificatePlanTogether(t *testing.T) {
	control := newCertificateTestControl(t, "route.example", publicURLCertificateTestPlan())
	setup := control.setup
	authority := testRunAuthority(t, control, setup)
	setup.PublishRun.Id = "another-run"
	setup.PublishRun.PublishRunNumber++
	setup.PublishRunToken = "another-token"
	setup.CertificatePlan.Identifiers[0] = "another.example"
	// restore the server fixture's separate expected plan; the authority must
	// still retain the canonical copy made before the source slice changed.
	control.setup.CertificatePlan = publicURLCertificateTestPlan()
	if authority.plan.Identifiers[0] != "route.example" || authority.identity.PublishRunID == setup.PublishRun.Id || authority.token.String() == setup.PublishRunToken {
		t.Fatal("source mutation changed bound authority")
	}
	if err := authority.markReady(t.Context()); err != nil {
		t.Fatal("readiness mixed another token or run into the authority", err)
	}
	control.installed = func(runID string, number uint64, _ string, _ time.Time) error {
		if runID != authority.identity.PublishRunID || number != authority.identity.Number {
			return errors.New("certificate acknowledgement changed the bound run")
		}
		return nil
	}
	if err := authority.certificateInstalled(t.Context(), "issuance", time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, observed, err := heartbeatResponseOnce(t.Context(), authority, control.setup.PublishRun.ExpiresAt); err != nil || !observed {
		t.Fatal("heartbeat mixed another token or run into the authority", err)
	}
	if text := fmt.Sprintf("%+v %#v", authority, authority); strings.Contains(text, authority.token.String()) {
		t.Fatal("incidental authority formatting exposed the token")
	}
}

func TestBoundPublicRunRejectsSetupBeforeUseAndStillCloses(t *testing.T) {
	for _, test := range []struct {
		name   string
		change func(*controlv1.PublishRunSetup)
	}{
		{"public URL mismatch", func(s *controlv1.PublishRunSetup) { s.PublishRun.PublicUrlId = "different" }},
		{"team mismatch", func(s *controlv1.PublishRunSetup) { s.PublishRun.TeamId = "different" }},
		{"run zero", func(s *controlv1.PublishRunSetup) { s.PublishRun.PublishRunNumber = 0 }},
		{"missing run", func(s *controlv1.PublishRunSetup) { s.PublishRun.Id = "" }},
		{"managed token", func(s *controlv1.PublishRunSetup) { s.PublishRunToken = strings.Repeat("A", 43) }},
		{"invalid token", func(s *controlv1.PublishRunSetup) { s.PublishRunToken += "=" }},
		{"certificate plan", func(s *controlv1.PublishRunSetup) { s.CertificatePlan.Identifiers = []string{"another.example"} }},
	} {
		t.Run(test.name, func(t *testing.T) {
			control := newCertificateTestControl(t, "route.example", publicURLCertificateTestPlan())
			cfg := testRunConfig(control, control.setup)
			test.change(&control.setup)
			ready := false
			err := runPublishRun(t.Context(), cfg, control.setup, func() error { ready = true; return nil })
			if err == nil || ready || len(control.closedSessions) != 1 {
				t.Fatal("invalid setup escaped validation or skipped cleanup", err)
			}
		})
	}
}

func TestBoundPublicRunRejectsHeartbeatIdentityMismatch(t *testing.T) {
	for _, change := range []func(*controlv1.PublishRun){
		func(r *controlv1.PublishRun) { r.Id = "different" },
		func(r *controlv1.PublishRun) { r.PublicUrlId = "different" },
		func(r *controlv1.PublishRun) { r.TeamId = "different" },
		func(r *controlv1.PublishRun) { r.PublishRunNumber++ },
		func(r *controlv1.PublishRun) { r.ExpiresAt = time.Now().Add(-time.Second) },
	} {
		control := newCertificateTestControl(t, "route.example", publicURLCertificateTestPlan())
		authority := testRunAuthority(t, control, control.setup)
		control.heartbeat = func(context.Context, string, uint64, credentials.PublishRunToken) (controlv1.PublishRunHeartbeat, error) {
			run := control.setup.PublishRun
			change(&run)
			return controlv1.PublishRunHeartbeat{PublishRun: run}, nil
		}
		confirmed := control.setup.PublishRun.ExpiresAt
		response, observed, err := heartbeatResponseOnce(t.Context(), authority, confirmed)
		if err == nil || observed || !response.PublishRun.ExpiresAt.Equal(confirmed) {
			t.Fatal("invalid heartbeat changed confirmed authority", err)
		}
	}
}

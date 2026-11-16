package main

import (
	"bytes"
	"errors"
	"io"
	"maps"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/alecthomas/kong"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/policy/publisherprovenance"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestPublisherDeploymentInvalidMetadataFailsBeforeIdentityState(t *testing.T) {
	t.Setenv(publisherprovenance.DeploymentIDEnv, "must-not-appear-in-diagnostics")
	state := filepath.Join(t.TempDir(), "state")
	var output, diagnostics bytes.Buffer
	err := run(t.Context(), []string{"--no-config", "publisher", "serve", "--deployment", "production", "--instance", "replica-1", "--state-dir", state}, &output, &diagnostics)
	if reason, _ := failure.ReasonOf(err); reason != failure.PublisherDeploymentMetadataInvalid {
		t.Fatal("wrong deployment validation boundary", err)
	}
	writeCommandError(&diagnostics, err)
	if bytes.Contains(diagnostics.Bytes(), []byte("must-not-appear")) || output.Len() != 0 {
		t.Fatal("metadata leaked into output")
	}
	if _, err := os.Lstat(state); !os.IsNotExist(err) {
		t.Fatal("invalid metadata opened client state")
	}
}

func TestDeploymentPublisherCommandSelection(t *testing.T) {
	for _, args := range [][]string{
		{"publisher", "setup", "--deployment", "customer", "--service", "db", "--service", "cache", "--members", "2", "--expires-in", "5m", "--idempotency-key", "original"},
		{"publisher", "list", "--deployment", "customer", "--limit", "1"},
		{"publisher", "revoke", "pub_aaaaaaaaaaaaaaaaaaaaaa", "--deployment", "customer"},
	} {
		var flags cli
		parser, err := kong.New(&flags, kong.Writers(io.Discard, io.Discard))
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := parser.Parse(append(args, "--project-key", "shop", "--team", "acme", "--output", "json"))
		if err != nil {
			t.Fatal(err)
		}
		team := "project-team"
		project := projectConfiguration{}
		project.Config.Team = &team
		if err = applyProjectCommandContext(parsed.Command(), project, &flags); err != nil {
			t.Fatal(err)
		}
		switch parsed.Command() {
		case "publisher setup":
			body, err := deploymentPublisherSetupBody(flags.Publisher.Setup)
			if err != nil || len(body.Services) != 2 || *body.MaxMembers != 2 || *body.ExpiresIn != 300 || flags.Publisher.Setup.ProjectTeam != team || flags.Publisher.Setup.Team != "acme" {
				t.Fatal("setup lost its captured selection", err)
			}
		case "publisher list":
			if flags.Publisher.List.ProjectKey != "shop" || flags.Publisher.List.ProjectTeam != team || flags.Publisher.List.Limit != 1 {
				t.Fatal("list lost deployment selection")
			}
		case "publisher revoke <publisher-identity-id>":
			if flags.Publisher.Revoke.ProjectKey != "shop" || flags.Publisher.Revoke.ProjectTeam != team || flags.Publisher.Revoke.Deployment != "customer" {
				t.Fatal("revoke lost deployment selection")
			}
		default:
			t.Fatal("unexpected command", parsed.Command())
		}
	}
}

func TestDeploymentPublisherSetupBounds(t *testing.T) {
	valid := publisherSetupCommand{Services: []string{"db"}, Members: 1, ExpiresIn: time.Minute}
	for _, mutate := range []func(*publisherSetupCommand){
		func(f *publisherSetupCommand) { f.Services = nil }, func(f *publisherSetupCommand) { f.Services = []string{"db", "db"} },
		func(f *publisherSetupCommand) { f.Services = []string{"db\nsecret"} }, func(f *publisherSetupCommand) { f.Namespace = true },
		func(f *publisherSetupCommand) { f.URL = "url_selected" }, func(f *publisherSetupCommand) { f.Members = 257 },
		func(f *publisherSetupCommand) { f.ExpiresIn = time.Second }, func(f *publisherSetupCommand) { f.ExpiresIn = time.Minute + time.Nanosecond },
		func(f *publisherSetupCommand) { f.IdempotencyKey = "private\nsecret" },
	} {
		flags := valid
		mutate(&flags)
		_, err := deploymentPublisherSetupBody(flags)
		if reason, ok := failure.ReasonOf(err); !ok || reason != failure.InvalidTunnelFlags || strings.Contains(err.Error(), "secret") {
			t.Fatal("invalid setup lost its classification or exposed input", err)
		}
	}
	for _, duration := range []time.Duration{time.Minute, 24 * time.Hour} {
		valid.ExpiresIn, valid.Members = duration, 256
		if _, err := deploymentPublisherSetupBody(valid); err != nil {
			t.Fatal("valid setup bound rejected", err)
		}
	}
}

func TestDeploymentPublisherEnrollmentKeepsSecretOutOfHumanOutput(t *testing.T) {
	enrollment := controlv1.DeploymentPublisherEnrollment{EnrollmentId: "pen_aaaaaaaaaaaaaaaaaaaaaa", EnrollmentKey: "pen_aaaaaaaaaaaaaaaaaaaaaa.private-secret", DeploymentId: "dpl_bbbbbbbbbbbbbbbbbbbbbb", MaxMembers: 1, ExpiresAt: time.Now().Add(time.Minute), Services: map[string]controlv1.ServiceProtocol{"db": controlv1.Postgres}}
	var output, diagnostics bytes.Buffer
	if err := writeDeploymentPublisherEnrollment(&output, &diagnostics, statusOutputHuman, enrollment); err != nil {
		t.Fatal(err)
	}
	if output.String() != enrollment.EnrollmentKey+"\n" || strings.Contains(diagnostics.String(), "private-secret") || !strings.Contains(diagnostics.String(), enrollment.EnrollmentId) {
		t.Fatal("enrollment secret was framed, logged, or changed")
	}
	output.Reset()
	diagnostics.Reset()
	if err := writeDeploymentPublisherEnrollment(&output, &diagnostics, statusOutputJSON, enrollment); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), `"enrollment_key":"`+enrollment.EnrollmentKey+`"`) || diagnostics.Len() != 0 {
		t.Fatal("explicit JSON enrollment changed its contract")
	}
	cause := errors.New("closed output")
	if err := writeDeploymentPublisherEnrollment(failingDeploymentWriter{cause}, io.Discard, statusOutputHuman, enrollment); !errors.Is(err, cause) {
		t.Fatal("credential output failure lost its cause", err)
	}
}

func TestDeploymentPublisherEnrollmentRejectsBroadenedApproval(t *testing.T) {
	now := time.Now()
	enrollment := controlv1.DeploymentPublisherEnrollment{EnrollmentId: "pen_aaaaaaaaaaaaaaaaaaaaaa", EnrollmentKey: "pen_aaaaaaaaaaaaaaaaaaaaaa.private-secret", DeploymentId: "dpl_bbbbbbbbbbbbbbbbbbbbbb", MaxMembers: 1, ExpiresAt: now.Add(time.Minute), Services: map[string]controlv1.ServiceProtocol{"db": controlv1.Postgres}}
	if err := validateDeploymentPublisherEnrollment(enrollment, enrollment.DeploymentId, 1, enrollment.Services, now); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*controlv1.DeploymentPublisherEnrollment){
		func(e *controlv1.DeploymentPublisherEnrollment) { e.DeploymentId = "other" }, func(e *controlv1.DeploymentPublisherEnrollment) { e.MaxMembers = 2 },
		func(e *controlv1.DeploymentPublisherEnrollment) { e.ExpiresAt = now }, func(e *controlv1.DeploymentPublisherEnrollment) { e.Services["cache"] = controlv1.Tcp },
		func(e *controlv1.DeploymentPublisherEnrollment) { e.Services["db"] = controlv1.Mysql }, func(e *controlv1.DeploymentPublisherEnrollment) { e.EnrollmentKey += "\n" },
	} {
		changed := enrollment
		changed.Services = maps.Clone(enrollment.Services)
		mutate(&changed)
		err := validateDeploymentPublisherEnrollment(changed, enrollment.DeploymentId, 1, enrollment.Services, now)
		if reason, ok := failure.ReasonOf(err); !ok || reason != failure.ServerResponseInvalid || strings.Contains(err.Error(), "private-secret") {
			t.Fatal("invalid enrollment scope escaped or exposed its secret", err)
		}
	}
}

type failingDeploymentWriter struct{ err error }

func (w failingDeploymentWriter) Write([]byte) (int, error) { return 0, w.err }

func TestDeploymentPublisherObservationScope(t *testing.T) {
	deployment := controlv1.Deployment{Id: "dpl_aaaaaaaaaaaaaaaaaaaaaa", TeamId: "team-selected", ProjectKey: "shop"}
	publisher := controlv1.DeploymentPublisher{DeploymentId: deployment.Id, TeamId: deployment.TeamId, ProjectKey: deployment.ProjectKey, PublisherIdentityId: "pub_bbbbbbbbbbbbbbbbbbbbbb", SnapshotAt: time.Now(), Services: map[string]controlv1.ServiceProtocol{"db": controlv1.Postgres}}
	if err := validateDeploymentPublisher(publisher, deployment); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*controlv1.DeploymentPublisher){
		func(p *controlv1.DeploymentPublisher) { p.DeploymentId = "dpl_other" }, func(p *controlv1.DeploymentPublisher) { p.TeamId = "other" },
		func(p *controlv1.DeploymentPublisher) { p.ProjectKey = "other" }, func(p *controlv1.DeploymentPublisher) { p.Services["db"] = "unknown" },
	} {
		changed := publisher
		changed.Services = maps.Clone(publisher.Services)
		mutate(&changed)
		if reason, ok := failure.ReasonOf(validateDeploymentPublisher(changed, deployment)); !ok || reason != failure.ServerResponseInvalid {
			t.Fatal("publisher observation crossed its selected deployment")
		}
	}
	var output bytes.Buffer
	if err := writeHumanFrame(&output, "tnl publisher list", "listed", "", deploymentPublisherBlock(publisher)); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(output.String(), "query succeeded") || !strings.Contains(output.String(), "not current") {
		t.Fatal("publisher observation overstated readiness")
	}
}

package certificates

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/internal/testutil/controltest"
)

// serviceCertificateRun creates a real service, enrolled publisher, and run so
// ACME tests exercise the same durable certificate queue as production.
func serviceCertificateRun(t *testing.T, database *controlstate.Database, domain string, now time.Time) (controlstate.ServiceRunPreparation, controlstate.ServiceRunState) {
	t.Helper()
	ctx := t.Context()
	session, err := controltest.Session(ctx, database, domain, time.Hour, 24*time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	member := session.Identity.Memberships[0]
	service, err := database.CreateServiceAt(ctx, member.TeamID, session.Identity.Identity.ID, "api", "certificates-api",
		controlstate.ServicePlacement{}, now, controlstate.ServiceMetadata{Protocol: "http"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	enrollment, err := database.IssuePublisherEnrollment(ctx, controlstate.CreatePublisherEnrollmentRequest{
		Scope: controlstate.PublisherScope{TeamID: member.TeamID, Kind: "service", ServiceID: service.ID},
		Name:  "certificates-api", Kind: "installed", EditorID: session.Identity.Identity.ID,
		EditorMembershipID: member.ID, PolicyRevision: uint64(member.PolicyRevision), Now: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publisher, err := database.RedeemPublisherEnrollment(ctx, enrollment.Key, public, now)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := database.PrepareServiceRun(ctx, service.ID, publisher, "certificates-run", now,
		controlstate.ServiceRunRequest{Metadata: service.ServiceMetadata})
	if err != nil {
		t.Fatal(err)
	}
	run, err := database.StartServiceRun(ctx, service.ID, prepared.RunID, prepared.RunNumber, publisher, now)
	if err != nil {
		t.Fatal(err)
	}
	return prepared, run
}

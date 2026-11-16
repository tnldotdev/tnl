package state

import (
	"encoding/json"
	"errors"
	"math"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/policy/trafficlimits"
	"github.com/tnldotdev/tnl/internal/security/targettrust"
)

func TestServiceRestoredStoredRecordProjectionAndInvalidProtocol(t *testing.T) {
	now := time.Date(2026, 11, 16, 0, 0, 0, 0, time.UTC)
	expiry := now.Add(time.Hour)
	trust, err := targettrust.CapturePortable(t.Context(), "postgres", "database.internal:5432", "system", "database.internal")
	if err != nil {
		t.Fatal(err)
	}
	tls := &ServiceTargetTLS{Hostname: trust.Hostname, System: trust.System, PEM: string(trust.PEM), Digest: trust.Digest}
	encoded, err := json.Marshal(tls)
	if err != nil {
		t.Fatal(err)
	}
	for _, guest := range []bool{false, true} {
		for _, flags := range []bool{false, true} {
			row := controlstatedb.ControlService{
				ID: "svc_" + strings.Repeat("a", 22), TeamID: text("team-one"), Name: "orders",
				Protocol: "postgres", TlsMetadata: encoded, TrustRevision: 7, EndpointRevision: 11,
				DomainID: text("domain-one"), CertificateHostname: "orders.example.test",
				PlacementWorktreeKey: "checkout-key", PlacementWorktreeLabel: "feature",
				ServicePort: pgtype.Int4{Int32: 24001, Valid: true}, Public: true,
				Enabled: flags, Ephemeral: flags, RequirePostQuantum: flags, PublisherPool: flags,
				CreatedAt: timestamptz(now), ExpiresAt: timestamptz(expiry),
			}
			if guest {
				row.TeamID, row.GuestID = pgtype.Text{}, text("guest-one")
			}
			want := ServiceRecord{
				ServiceMetadata: ServiceMetadata{Protocol: "postgres", TLS: tls, TrustRevision: 7, PublisherPool: flags,
					Endpoint: &ServiceEndpoint{Hostname: "orders.example.test", Port: 24001, Public: true}},
				ID: row.ID, TeamID: row.TeamID.String, GuestID: row.GuestID.String, Name: "orders", DomainID: "domain-one",
				EndpointRevision: 11, Enabled: flags, Ephemeral: flags, RequirePostQuantum: flags,
				CreatedAt: now, ExpiresAt: &expiry,
				Placement: &ServicePlacement{DomainID: "domain-one", Hostname: "orders.example.test",
					WorktreeKey: "checkout-key", WorktreeLabel: "feature"},
			}
			got, err := checkedServiceRecord(row)
			if err != nil || !reflect.DeepEqual(got, want) {
				t.Fatalf("stored service projection guest=%t flags=%t changed defining fields: %v", guest, flags, err)
			}
			row.ExpiresAt = pgtype.Timestamptz{}
			got, err = checkedServiceRecord(row)
			if err != nil || got.ExpiresAt != nil {
				t.Fatal("absent service expiry became a fabricated deadline", err)
			}
		}
	}
	for _, protocol := range []string{"", "unknown", "invalid-stored-protocol"} {
		record, err := checkedServiceRecord(controlstatedb.ControlService{Protocol: protocol, TrustRevision: 1})
		if !errors.Is(err, ErrServiceMetadata) || !reflect.DeepEqual(record, ServiceRecord{}) {
			t.Fatal("invalid stored protocol escaped a fail-closed projection", protocol, err)
		}
	}
	// tcp is now an ordinary valid service protocol, not an invalid HTTP-only
	// public URL discriminator.
	if _, err := checkedServiceRecord(controlstatedb.ControlService{Protocol: "tcp", TrustRevision: 1}); err != nil {
		t.Fatal("unified TCP service metadata was rejected", err)
	}
}

func TestServiceRunRestoredPreparationProjectionAndIdentifierOwnership(t *testing.T) {
	now := time.Date(2026, 11, 16, 0, 0, 0, 0, time.UTC)
	limits := trafficlimits.Default()
	limits.RatePer, limits.TotalUploadBytes = 2*time.Second, 1048576
	encoded, err := json.Marshal(limits)
	if err != nil {
		t.Fatal(err)
	}
	for _, number := range []int64{1, 7, math.MaxInt64} {
		for _, publisherFirst := range []bool{false, true} {
			row := controlstatedb.ControlServiceRun{
				ID: "srun-one", ServiceID: "service-one", TeamID: text("team-one"), RunNumber: number,
				PublisherIdentityID: "publisher-one", PublisherGrantID: "grant-one", PublisherKeyID: "key-one",
				IdempotencyKey: "exact-preparation", PreparationExpiresAt: timestamptz(now.Add(time.Minute)),
				PublisherExpiresAt:  timestamptz(now.Add(45 * time.Second)),
				CertificateCacheKey: "scope.example.test", CertificateScope: "scope.example.test",
				CertificateIdentifiers: []string{"*.scope.example.test"}, CertificateDomainID: text("domain-one"),
				CertificateHostname: "app.scope.example.test", RequirePostQuantum: true, TrafficLimits: encoded,
			}
			expiry := row.PublisherExpiresAt.Time
			if !publisherFirst {
				row.PreparationExpiresAt = timestamptz(now.Add(10 * time.Second))
				expiry = row.PreparationExpiresAt.Time
			}
			got, err := serviceRunPreparation(row)
			want := ServiceRunPreparation{
				ServiceID: row.ServiceID, TeamID: row.TeamID.String, RunID: row.ID, RunNumber: number,
				PublisherIdentityID: row.PublisherIdentityID, PublisherGrantID: row.PublisherGrantID,
				PublisherKeyID: row.PublisherKeyID, IdempotencyKey: row.IdempotencyKey,
				ExpiresAt: expiry, Hostname: row.CertificateHostname, DomainID: row.CertificateDomainID.String,
				Traffic: limits, RequirePostQuantum: true,
				CertificatePlan: CertificatePlan{CacheKey: row.CertificateCacheKey, Scope: row.CertificateScope,
					Identifiers: []string{"*.scope.example.test"}, ChallengeMethod: "dns-01"},
			}
			if err != nil || !reflect.DeepEqual(got, want) {
				t.Fatalf("run preparation projection number=%d publisherFirst=%t changed fields: %v", number, publisherFirst, err)
			}
			got.CertificatePlan.Identifiers[0] = "changed.example.test"
			if row.CertificateIdentifiers[0] != "*.scope.example.test" {
				t.Fatal("preparation projection aliased stored certificate identifiers")
			}
		}
	}
}

package public

import (
	"errors"
	"reflect"
	"testing"
	"time"

	clientauthority "github.com/tnldotdev/tnl/internal/client/authority"
	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	"github.com/tnldotdev/tnl/internal/client/credentialfile"
	"github.com/tnldotdev/tnl/internal/client/identity/workload"
	publisheridentity "github.com/tnldotdev/tnl/internal/publisher/identity"
	"github.com/tnldotdev/tnl/internal/testutil/githubtest"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestIntegrationWorkloadPreparesApplicationForNativePublisher(t *testing.T) {
	for _, mixed := range []bool{false, true} {
		name := "publish only"
		if mixed {
			name = "mixed visit and publish"
		}
		t.Run(name, func(t *testing.T) {
			f := newWorkloadExchangeRetryFixture(t)
			policy := (*f.body.Configuration.Workloads)["test"]
			publish := workloadVisitGrants(t, "api")
			policy.Grants.Publish = publish.Visit
			if !mixed {
				policy.Grants.Visit = nil
			}
			(*f.body.Configuration.Workloads)["test"] = policy
			f.apply(t)
			capturedExpiry := time.Now().Add(time.Hour).UTC().Truncate(time.Second)
			if _, err := f.inspect.Exec(t.Context(), `UPDATE control.publisher_grants SET expires_at=$2 WHERE publisher_identity_id IN (SELECT publisher_identity_id FROM control.workload_applications WHERE team_id=$1 AND revoked_at IS NULL)`, f.team, capturedExpiry); err != nil {
				t.Fatal(err)
			}
			job, err := workload.New(f.server.URL, f.server.Client())
			if err != nil {
				t.Fatal(err)
			}
			claims := githubtest.Claims(f.server.URL, time.Now().Truncate(time.Second))
			session, err := job.Exchange(t.Context(), f.team, "example", f.body.SourceFingerprint, "test", f.issuer.Sign(t, claims), nil)
			if err != nil {
				t.Fatal(err)
			}
			wantGrants := 1
			if mixed {
				wantGrants = 3
			}
			if len(session.Application.Grants) != wantGrants || (len(session.ServiceIds) > 0) != mixed {
				t.Fatal("federation lost or added an operation")
			}
			prepared, err := job.PrepareApplication()
			if err != nil {
				t.Fatal(err)
			}
			var service string
			for _, grant := range prepared.Grants {
				if grant.ExpiresAt == nil || !grant.ExpiresAt.Equal(capturedExpiry) || !grant.ExpiresAt.After(session.LeaseExpiresAt) {
					t.Fatal("prepared grant confused source lease with captured expiry")
				}
				if grant.Operation == controlv1.ApplicationPublish {
					service = *grant.ServiceID
				}
			}
			identity, key, err := prepared.Publisher(service)
			if err != nil {
				t.Fatal(err)
			}
			// these clients have no personal session or client state directory.
			control, err := clientcontrol.New(f.server.URL, f.server.Client(), "")
			if err != nil {
				t.Fatal(err)
			}
			authority, err := clientauthority.New(f.server.URL, f.server.Client(), "")
			if err != nil {
				t.Fatal(err)
			}
			native, err := publisheridentity.NewNative(control, authority, identity, key)
			if err != nil {
				t.Fatal(err)
			}
			saved, err := native.SavedService(t.Context())
			if err != nil || saved.Id != service || saved.TeamId != f.team {
				t.Fatal("prepared session key could not use native publisher adapter", err)
			}
			if mixed {
				inventory, err := job.ListServices(t.Context())
				if err != nil || len(inventory.Services) != 2 {
					t.Fatal("mixed source lost visitor inventory", err)
				}
			}
			// a renewable lease and a parent extension cannot extend captured grants.
			if _, err := f.inspect.Exec(t.Context(), `UPDATE control.publisher_grants SET expires_at=NULL WHERE publisher_identity_id=$1`, prepared.ClientID); err != nil {
				t.Fatal(err)
			}
			if _, err := job.Renew(t.Context()); err != nil {
				t.Fatal(err)
			}
			repeated, err := job.PrepareApplication()
			if err != nil || !reflect.DeepEqual(repeated, prepared) {
				t.Fatal("renewal replaced the source key or widened captured expiry", err)
			}
			// keep the identity but replace every operation, leaving this source empty.
			policy.Grants = workloadVisitGrants(t, "db")
			(*f.body.Configuration.Workloads)["test"] = policy
			f.apply(t)
			if _, err := native.SavedService(t.Context()); err == nil {
				t.Fatal("removed publication grant retained access")
			}
			narrowed, err := job.Renew(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			if !mixed && (len(narrowed.Application.Grants) != 0 || len(narrowed.ServiceIds) != 0) {
				t.Fatal("new grant upgraded an existing source")
			}
			if !mixed {
				if _, err := job.PrepareApplication(); !errors.Is(err, credentialfile.ErrInvalid) {
					t.Fatal("empty source produced executable credentials", err)
				}
			}
			if err := job.Revoke(t.Context()); err != nil {
				t.Fatal(err)
			}
			if _, err := native.Access(t.Context()); err == nil {
				t.Fatal("prepared credential outlived source revocation")
			}
		})
	}
}

package state

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	"github.com/tnldotdev/tnl/internal/security/publisherproof"
)

func TestIntegrationExactGrantProtocolsFenceServingWithoutChangingManagementOrCleanup(t *testing.T) {
	for _, phase := range []string{"prepared", "started"} {
		for _, protocol := range []string{"tcp", "mysql", "postgres", "kubernetes"} {
			t.Run(phase+"/"+protocol, func(t *testing.T) {
				f := newServiceManagementFixture(t)
				ctx := t.Context()
				registerCertificatePlanRelays(t, f.d, f.now)
				request := standaloneEnrollmentRequest(t, f.d, f.local, f.member.IdentityID, "member-http", f.now)
				enrollment, err := f.d.IssuePublisherEnrollment(ctx, request)
				if err != nil || !reflect.DeepEqual(enrollment.Protocols, []string{"http"}) {
					t.Fatal("member issuance did not capture exactly HTTP", enrollment.Protocols, err)
				}
				public, private, err := ed25519.GenerateKey(rand.Reader)
				if err != nil {
					t.Fatal(err)
				}
				publisher, err := f.d.RedeemPublisherEnrollment(ctx, enrollment.Key, public, f.now)
				if err != nil {
					t.Fatal(err)
				}
				access := publisherAccess(t, f.d, publisher, private, "", f.now)
				prepared, err := f.d.PrepareServiceRun(ctx, f.local.ID, publisher, "original-http", f.now, ServiceRunRequest{Metadata: f.local.ServiceMetadata})
				if err != nil {
					t.Fatal(err)
				}
				if phase == "started" {
					if _, err := f.d.StartServiceRun(ctx, f.local.ID, prepared.RunID, prepared.RunNumber, publisher, f.now); err != nil {
						t.Fatal(err)
					}
				}
				pendingRequest := request
				pendingRequest.Name = "pending-http"
				pending, err := f.d.IssuePublisherEnrollment(ctx, pendingRequest)
				if err != nil {
					t.Fatal(err)
				}
				at := f.now.Add(time.Second)
				metadata := f.local.ServiceMetadata
				metadata.Protocol = protocol
				native, err := f.d.ConfigureService(ctx, f.local.ID, f.member.IdentityID, metadata, nil, ServiceUpdateConditions{}, at)
				if err != nil || native.Protocol != protocol || native.TrustRevision != f.local.TrustRevision+1 {
					t.Fatal("protocol capability changed existing human service-edit rights", native, err)
				}
				if _, err := f.d.AuthenticatePublisherAccess(ctx, access.Token, "", at); !errors.Is(err, ErrPublisherIdentity) {
					t.Fatal("cached HTTP access authorized native publication", err)
				}
				assertion, err := publisherproof.Sign(publisher.ID, publisher.KeyID, publisher.GrantID, publisherTestAudience, private, at)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := f.d.ExchangePublisherAssertion(ctx, publisher.ID, publisher.GrantID, publisherTestAudience, assertion, "", at); !errors.Is(err, ErrPublisherIdentity) {
					t.Fatal("retained signing key widened its actual grant", err)
				}
				if _, err := f.d.GetServiceForPublisher(ctx, native.ID, publisher, at); !errors.Is(err, ErrServiceAccess) {
					t.Fatal("HTTP grant selected native publisher metadata", err)
				}
				if _, err := f.d.PrepareServiceRun(ctx, native.ID, publisher, "native-attempt", at, ServiceRunRequest{Metadata: native.ServiceMetadata}); !errors.Is(err, ErrServiceAccess) {
					t.Fatal("HTTP grant prepared a native run using current native metadata", err)
				}
				if _, err := f.d.StartServiceRun(ctx, native.ID, prepared.RunID, prepared.RunNumber, publisher, at); !errors.Is(err, ErrServiceAccess) {
					t.Fatal("exact start/retry revived a protocol-fenced run", err)
				}
				if _, err := f.d.HeartbeatServiceRun(ctx, native.ID, prepared.RunID, prepared.Token, at, ServiceRunHealth{Healthy: true, StreamCapacity: 1}); !errors.Is(err, ErrServiceAccess) {
					t.Fatal("old exact token renewed native serving authority", err)
				}
				if _, err := f.d.ReadPublisherVisitorPolicy(ctx, visitorscope.Scope{Kind: visitorscope.Service, ID: native.ID},
					prepared.RunID, prepared.RunNumber, prepared.Token, 0, at); !errors.Is(err, ErrServiceAccess) {
					t.Fatal("old exact token acquired current serving policy", err)
				}
				if _, err := f.d.RedeemPublisherEnrollment(ctx, pending.Key, public, at); err == nil {
					t.Fatal("HTTP pending enrollment gained capability from the edited service")
				}
				for range 2 {
					if err := f.d.CloseServiceRun(ctx, native.ID, prepared.RunID, prepared.Token, at); err != nil {
						t.Fatal("serving protocol check incorrectly gated exact-token cleanup/retry", err)
					}
				}
				request = standaloneEnrollmentRequest(t, f.d, native, f.member.IdentityID, "forbidden-native", at)
				request.Protocols = []string{protocol}
				if _, err := f.d.IssuePublisherEnrollment(ctx, request); !errors.Is(err, ErrPublisherIdentity) {
					t.Fatal("member self-issued native capability after editing its service", err)
				}
				if _, err := f.d.pool.Exec(ctx, `UPDATE control.publisher_grants SET protocols=$2 WHERE id=$1`, publisher.GrantID, []string{protocol}); err == nil {
					t.Fatal("actual grant capability was mutable")
				}
				if _, err := f.d.pool.Exec(ctx, `UPDATE control.publisher_enrollments SET protocols=$2 WHERE id=$1`, pending.ID, []string{protocol}); err == nil {
					t.Fatal("pending capability was mutable")
				}
				if err := f.d.RevokePublisherGrant(ctx, f.team, publisher.ID, publisher.GrantID, f.owner, at); err != nil {
					t.Fatal(err)
				}
				editor := standaloneEnrollmentRequest(t, f.d, native, f.owner, "administrator-native", at)
				grant, err := f.d.CreatePublisherGrant(ctx, CreatePublisherGrantRequest{
					PublisherIdentityID: publisher.ID, Scope: editor.Scope, EditorID: editor.EditorID,
					EditorMembershipID: editor.EditorMembershipID, PolicyRevision: editor.PolicyRevision,
					Protocols: []string{protocol}, Now: at,
				})
				if err != nil || grant == publisher.GrantID {
					t.Fatal("administrator did not issue a real replacement native grant", grant, err)
				}
				proof, err := publisherproof.Sign(publisher.ID, publisher.KeyID, grant, publisherTestAudience, private, at)
				if err != nil {
					t.Fatal(err)
				}
				approved, err := f.d.ExchangePublisherAssertion(ctx, publisher.ID, grant, publisherTestAudience, proof, "", at)
				if err != nil || approved.Ownership != "member" || approved.OwnerMembershipID != f.member.ID {
					t.Fatal("administrator-approved member-owned native grant was rejected or changed owner", approved.PublisherIdentity, err)
				}
				nativeRun, err := f.d.PrepareServiceRun(ctx, native.ID, approved.PublisherIdentity, "authorized-native", at,
					ServiceRunRequest{Metadata: native.ServiceMetadata})
				if err != nil {
					t.Fatal("actual administrator native capability could not prepare", err)
				}
				captured, err := controlstatedb.New(f.d.pool).LockServiceRun(ctx, controlstatedb.LockServiceRunParams{ID: nativeRun.RunID, ServiceID: native.ID})
				if err != nil || captured.Protocol != protocol {
					t.Fatal("native run did not capture the authorized service protocol", captured.Protocol, err)
				}
				if _, err := f.d.StartServiceRun(ctx, native.ID, nativeRun.RunID, nativeRun.RunNumber, approved.PublisherIdentity, at); err != nil {
					t.Fatal("actual administrator native capability could not start", err)
				}
				if err := f.d.CloseServiceRun(ctx, native.ID, nativeRun.RunID, nativeRun.Token, at); err != nil {
					t.Fatal(err)
				}
				stored, err := controlstatedb.New(f.d.pool).GetPublisherGrant(ctx, controlstatedb.GetPublisherGrantParams{
					ID: grant, PublisherIdentityID: publisher.ID,
				})
				if err != nil || !reflect.DeepEqual(stored.Protocols, []string{protocol}) {
					t.Fatal("administrator capability was not the actual stored exact grant", stored.Protocols, err)
				}
			})
		}
	}
}

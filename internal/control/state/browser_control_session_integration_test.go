package state

import (
	"errors"
	"testing"
	"time"

	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestIntegrationBrowserHandoffSeparatesIdentityVisitAndManagement(t *testing.T) {
	for _, visit := range []bool{false, true} {
		name := "identity only"
		if visit {
			name = "visitor without management"
		}
		t.Run(name, func(t *testing.T) {
			f := newServiceHTTPFixture(t)
			f.run = f.publish(t, f.service)
			d, ctx := f.database, t.Context()
			reviewer := finalVisitorIdentity(t, d, f.now, "browser-viewer@example.test")
			parent := browserTestControlSession(t, d, reviewer, f.now)
			if visit {
				if _, err := d.CreateServiceGrant(ctx, f.service.ID, f.project.ActorID, "browser-visitor", "identity", reviewer, nil, f.now); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := d.GetService(ctx, f.service.ID, reviewer); !errors.Is(err, ErrServiceAccess) {
				t.Fatal("fixture gave a reviewer management authority", err)
			}
			handoff, err := d.IssueControlBrowserHandoff(ctx, parent.AccessToken, parent.RefreshToken, f.service.ID, time.Hour, 24*time.Hour, f.now)
			if err != nil || handoff.Origin != "https://"+f.service.Endpoint.Hostname {
				t.Fatal("browser authentication required management or changed the host", err)
			}
			cookie, err := d.RedeemServiceBrowserHandoff(ctx, f.auth(), handoff.Token, f.now)
			if err != nil {
				t.Fatal(err)
			}
			permission, err := d.ServiceBrowserSession(ctx, f.auth(), cookie.CookieSecret, false, f.now)
			if err != nil || !permission.Authenticated || permission.IdentityID != reviewer || permission.VisitAllowed != visit {
				t.Fatal("browser authentication inferred visit permission or lost its author", permission, err)
			}
			if _, err := d.GetService(ctx, f.service.ID, reviewer); !errors.Is(err, ErrServiceAccess) {
				t.Fatal("browser handoff conferred management authority", err)
			}
			if !visit {
				services, _, err := d.ListAvailableServices(WithControlPrincipal(ctx, ControlPrincipal{IdentityID: reviewer, SessionID: parent.SessionID}), reviewer, "", controlv1.ServiceAccessPathConnector, f.now)
				if err != nil || len(services) != 0 {
					t.Fatal("identity-only handoff conferred connector access", err)
				}
			}
			if err := d.RevokeControlSession(ctx, ControlPrincipal{SessionID: parent.SessionID, IdentityID: reviewer}, f.now); err != nil {
				t.Fatal(err)
			}
			if _, err := d.ServiceBrowserSession(ctx, f.auth(), cookie.CookieSecret, false, f.now); !errors.Is(err, ErrVisitorSignIn) {
				t.Fatal("independent browser session outlived parent revocation", err)
			}
		})
	}
}

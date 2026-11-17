package state

import (
	"context"
	"encoding/base64"
	"errors"
	"net/netip"
	"time"

	"github.com/tnldotdev/tnl/internal/policy/visitorlease"
	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	"github.com/tnldotdev/tnl/internal/security/visitortoken"
)

type preparedVisitorInput struct {
	SourceIP, BrowserCookieSecret, ShareID string
	ShareCookieSecret, ShareSecret         []byte
}

// exercise the real preparation and local verifier instead of the retired
// per-request authorization RPC. state fixtures supply their own clock.
func preparedServiceRunPermission(ctx context.Context, d *Database, auth ServiceHTTPRun, input preparedVisitorInput, now time.Time) (VisitorPermission, error) {
	return preparedVisitorPermission(ctx, d, auth.Subject, auth.RunID, auth.Number, auth.Token.String(), input, now)
}

func preparedServiceHTTPPermission(ctx context.Context, d *Database, auth ServiceHTTPRun, input preparedVisitorInput, now time.Time) (VisitorPermission, error) {
	return preparedServiceRunPermission(ctx, d, auth, input, now)
}

func preparedVisitorPermission(ctx context.Context, d *Database, scope visitorscope.Scope, run string, number int64, token string, input preparedVisitorInput, now time.Time) (VisitorPermission, error) {
	result := VisitorPermission{}
	var source VisitorTokenSource
	switch {
	case input.BrowserCookieSecret != "":
		if input.ShareID != "" || len(input.ShareSecret) != 0 || len(input.ShareCookieSecret) != 0 {
			return result, ErrVisitorSignIn
		}
		source = BrowserSessionTokenSource{Secret: input.BrowserCookieSecret}
	case len(input.ShareSecret) != 0:
		if len(input.ShareCookieSecret) != 0 {
			return result, ErrVisitorSignIn
		}
		source = ShareTokenSource{ShareID: input.ShareID, Secret: base64.RawURLEncoding.EncodeToString(input.ShareSecret)}
	case input.ShareID != "" || len(input.ShareCookieSecret) != 0:
		source = ShareSessionTokenSource{ShareID: input.ShareID, Secret: base64.RawURLEncoding.EncodeToString(input.ShareCookieSecret)}
	}
	if err := d.PrepareVisitorSigningKeys(ctx, testVisitorIssuer, now); err != nil {
		return result, err
	}
	var issued IssuedVisitorToken
	var err error
	if source != nil {
		issued, err = d.IssueVisitorToken(ctx, testVisitorIssuer, scope, source, now)
		if errors.Is(err, ErrVisitorPermission) {
			return result, nil
		}
		if err != nil {
			return result, err
		}
	}
	body, err := d.ReadPublisherVisitorPolicy(ctx, scope, run, number, token, 0, now)
	if err != nil {
		return result, err
	}
	update, err := visitorlease.Decode(body)
	if err != nil {
		return result, err
	}
	lease, err := visitorlease.New(scope, func() time.Time { return now })
	if err != nil {
		return result, err
	}
	defer lease.Close()
	if err := lease.Apply(lease.Begin(), update); err != nil {
		return result, err
	}
	view, _, _ := lease.Current()
	result.ExpiresAt = &view.ValidUntil
	var guard *visitorlease.Guard
	if source == nil {
		guard, err = lease.BindAnonymous(netip.MustParseAddr(input.SourceIP), func() {})
	} else {
		permission, verifyErr := visitortoken.VerifyBearer(issued.Token, view, now)
		if verifyErr != nil {
			return result, verifyErr
		}
		result.ExpiresAt = earlierVisitorExpiry(result.ExpiresAt, permission.Facts().ExpiresAt)
		guard, err = lease.Bind(permission, netip.MustParseAddr(input.SourceIP), func() {})
		if _, ok := permission.Facts().Subject.(visitortoken.Share); ok {
			result.Reason = "anonymous_share"
		}
	}
	if errors.Is(err, visitortoken.ErrPolicy) {
		return result, nil
	}
	if err != nil {
		return result, err
	}
	defer guard.Close()
	result.VisitAllowed = true
	return result, nil
}

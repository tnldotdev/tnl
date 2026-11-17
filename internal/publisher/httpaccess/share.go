package httpaccess

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/textproto"
	"net/url"
	"strings"
	"time"

	"github.com/tnldotdev/tnl/internal/browserpage"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	"github.com/tnldotdev/tnl/internal/security/visitortoken"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

const ShareCookieName = "__Host-tnl-share"

// FeedbackBrowserCookieName is reserved even on services without feedback.
// all forwarding boundaries strip publisher-owned browser credentials.
const FeedbackBrowserCookieName = "__Host-tnl-feedback-browser"

type ShareClient interface {
	RedeemServiceShare(context.Context, string, string, controlv1.RedeemServiceShareRequest, credentials.ServiceRunToken) (controlv1.ShareRedemption, error)
}

// Shares binds share redemption and browser permission to one service run.
type Shares struct {
	Client  ShareClient
	Browser *Browser
	Logf    func(string, ...any)
}

// MarshalJSON keeps run credentials and live clients out of diagnostic snapshots.
func (Shares) MarshalJSON() ([]byte, error) { return []byte("{}"), nil }

func (a *Shares) Redeem(ctx context.Context, path string) (controlv1.ShareRedemption, error) {
	if a == nil || a.Client == nil || a.Browser == nil || a.Browser.Tokens == nil || a.Browser.Policy == nil {
		return controlv1.ShareRedemption{}, visitortoken.ErrBinding
	}
	browser := a.Browser
	view, enabled, _ := browser.Policy.Lease().Current()
	if !enabled {
		return controlv1.ShareRedemption{}, visitortoken.ErrPolicy
	}
	if browser.Subject.Kind != visitorscope.Service || !browser.Subject.Valid() || browser.Subject != view.Scope ||
		!opaqueid.Valid(browser.RunID, opaqueid.ServiceRunPrefix) || browser.Number < 1 || browser.Token == "" {
		return controlv1.ShareRedemption{}, visitortoken.ErrBinding
	}
	const linkPrefix = "/__tnl/share/"
	const handoffPrefix = "/__tnl/share/handoff/"
	request := controlv1.RedeemServiceShareRequest{RunNumber: browser.Number, Hostname: browser.Hostname}
	if token, found := strings.CutPrefix(path, handoffPrefix); found {
		if decoded, err := base64.RawURLEncoding.Strict().DecodeString(token); err != nil || len(decoded) != 32 {
			return controlv1.ShareRedemption{}, visitortoken.ErrToken
		}
		request.HandoffToken = &token
	} else if link, found := strings.CutPrefix(path, linkPrefix); found {
		id, secret, found := strings.Cut(link, ".")
		if !found || !opaqueid.Valid(id, opaqueid.SharePrefix) {
			return controlv1.ShareRedemption{}, visitortoken.ErrToken
		}
		if decoded, err := base64.RawURLEncoding.Strict().DecodeString(secret); err != nil || len(decoded) != 32 {
			return controlv1.ShareRedemption{}, visitortoken.ErrToken
		}
		request.ShareId, request.Secret = &id, &secret
	} else {
		return controlv1.ShareRedemption{}, visitortoken.ErrToken
	}
	result, err := a.Client.RedeemServiceShare(ctx, browser.Subject.ID, browser.RunID, request, browser.Token)
	if err != nil {
		return controlv1.ShareRedemption{}, err
	}
	next, parseErr := url.Parse(result.NextUrl)
	if !opaqueid.Valid(result.ShareId, opaqueid.SharePrefix) || request.ShareId != nil && result.ShareId != *request.ShareId ||
		!result.ExpiresAt.After(time.Now()) || parseErr != nil || next.Scheme != "https" ||
		next.Host == "" || next.User != nil || next.Fragment != "" || len(result.NextUrl) > 4096 {
		return controlv1.ShareRedemption{}, failure.Wrap("redeem share", failure.ServerResponseInvalid, errors.New("server returned invalid share redemption"))
	}
	if cookie, err := base64.RawURLEncoding.Strict().DecodeString(result.CookieSecret); err != nil || len(cookie) != 32 {
		return controlv1.ShareRedemption{}, failure.Wrap("redeem share", failure.ServerResponseInvalid, errors.New("server returned invalid share cookie"))
	}
	source, err := json.Marshal(controlv1.VisitorTokenShareSessionSource{Kind: controlv1.VisitorTokenShareSession, ShareId: result.ShareId, Secret: result.CookieSecret})
	if err == nil {
		result.Permission, err = a.Browser.PrepareToken(ctx, source, result.Permission, result.ExpiresAt)
	}
	if err != nil {
		if a.Logf != nil {
			a.Logf("publisher: share permission preparation failed: %s", sharePreparationFailure(err))
		}
		return controlv1.ShareRedemption{}, err
	}
	return result, nil
}

func sharePreparationFailure(err error) string {
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return "policy refresh timed out"
	case errors.Is(err, visitortoken.ErrPolicy):
		return "visitor policy unavailable"
	case errors.Is(err, visitortoken.ErrKey):
		return "verification key unavailable"
	case errors.Is(err, visitortoken.ErrToken):
		return "visitor token invalid"
	case errors.Is(err, visitortoken.ErrBinding):
		return "visitor token binding invalid"
	default:
		return "visitor permission unavailable"
	}
}

func StripCookies(request *http.Request) *http.Request {
	if len(request.Header.Values("Cookie")) == 0 {
		return request
	}
	clean := make([]string, 0, len(request.Header.Values("Cookie")))
	for _, header := range request.Header.Values("Cookie") {
		for _, pair := range strings.Split(header, ";") {
			pair = textproto.TrimString(pair)
			name, _, found := strings.Cut(pair, "=")
			// net/http trims the name separately from the cookie pair.
			name = textproto.TrimString(name)
			if found && name != ShareCookieName && name != FeedbackBrowserCookieName && name != BrowserCookieName && name != LoginAttemptCookieName && name != VisitorTokenCookie && pair != "" {
				clean = append(clean, pair)
			}
		}
	}
	copy := request.Clone(request.Context())
	copy.Header.Del("Cookie")
	if len(clean) != 0 {
		copy.Header.Set("Cookie", strings.Join(clean, "; "))
	}
	return copy
}

func ShareRedirect(response http.ResponseWriter, request *http.Request, redemption controlv1.ShareRedemption) {
	if err := PermissionCookie(response, redemption.Permission); err != nil {
		browserpage.Error(response, request, "share visitor permission is unavailable", http.StatusServiceUnavailable)
		return
	}
	http.SetCookie(response, &http.Cookie{
		Name: ShareCookieName, Value: redemption.ShareId + "." + redemption.CookieSecret,
		Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode,
		Expires: redemption.ExpiresAt,
	})
	response.Header().Set("Cache-Control", "no-store")
	response.Header().Set("Referrer-Policy", "no-referrer")
	if redemption.Bridge {
		browserpage.Redirect(response, redemption.NextUrl)
		return
	}
	response.Header().Set("Location", redemption.NextUrl)
	response.WriteHeader(http.StatusSeeOther)
}

func SharePath(path string) bool {
	return strings.HasPrefix(path, "/__tnl/share/")
}

// net/http omits malformed cookies. their presence must still fail closed.
func SuppliedCookieCount(r *http.Request, name string) int {
	count := 0
	for _, header := range r.Header.Values("Cookie") {
		for _, pair := range strings.Split(header, ";") {
			key, _, _ := strings.Cut(strings.TrimSpace(pair), "=")
			if strings.TrimSpace(key) == name {
				count++
			}
		}
	}
	return count
}

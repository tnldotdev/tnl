package httpaccess

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"html"
	"io"
	"net/http"
	"net/textproto"
	"strings"
	"time"

	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	"github.com/tnldotdev/tnl/internal/security/visitortoken"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

const ShareCookieName = "__Host-tnl-share"

// FeedbackBrowserCookieName is reserved even on services without feedback.
// all forwarding boundaries strip publisher-owned browser credentials.
const FeedbackBrowserCookieName = "__Host-tnl-feedback-browser"

type ShareClient interface {
	EnableShareAccess(context.Context, string, uint64, string, credentials.PublishRunToken) error
	RedeemPublishRunShare(context.Context, string, controlv1.RedeemShareRequest, credentials.PublishRunToken) (controlv1.ShareRedemption, error)
}

// Shares binds public URL share redemption to one publish run and its shared
// browser preparation. service grant redemption is composed by the service run.
type Shares struct {
	Client  ShareClient
	RunID   string
	Number  uint64
	Token   credentials.PublishRunToken
	Browser *Browser
	Logf    func(string, ...any)
}

// MarshalJSON keeps run credentials and live clients out of diagnostic snapshots.
func (Shares) MarshalJSON() ([]byte, error) { return []byte("{}"), nil }

func (a *Shares) Redeem(ctx context.Context, path string) (controlv1.ShareRedemption, error) {
	const linkPrefix = "/__tnl/share/"
	const handoffPrefix = "/__tnl/share/handoff/"
	request := controlv1.RedeemShareRequest{PublishRunNumber: int64(a.Number)}
	if token, found := strings.CutPrefix(path, handoffPrefix); found {
		if decoded, err := base64.RawURLEncoding.DecodeString(token); err != nil || len(decoded) != 32 {
			return controlv1.ShareRedemption{}, errors.New("invalid share handoff")
		}
		request.HandoffToken = &token
	} else if link, found := strings.CutPrefix(path, linkPrefix); found {
		id, secret, found := strings.Cut(link, ".")
		if !found || !opaqueid.Valid(id, opaqueid.SharePrefix) {
			return controlv1.ShareRedemption{}, errors.New("invalid share link")
		}
		if decoded, err := base64.RawURLEncoding.DecodeString(secret); err != nil || len(decoded) != 32 {
			return controlv1.ShareRedemption{}, errors.New("invalid share link")
		}
		request.ShareId, request.Secret = &id, &secret
	} else {
		return controlv1.ShareRedemption{}, errors.New("invalid share path")
	}
	result, err := a.Client.RedeemPublishRunShare(ctx, a.RunID, request, a.Token)
	if err != nil {
		return controlv1.ShareRedemption{}, err
	}
	if !opaqueid.Valid(result.ShareId, opaqueid.SharePrefix) || !result.ExpiresAt.After(time.Now()) ||
		!strings.HasPrefix(result.NextUrl, "https://") || strings.Contains(result.CookieSecret, ".") {
		return controlv1.ShareRedemption{}, errors.New("publisher: server returned invalid share redemption")
	}
	if cookie, err := base64.RawURLEncoding.DecodeString(result.CookieSecret); err != nil || len(cookie) != 32 {
		return controlv1.ShareRedemption{}, errors.New("publisher: server returned invalid share cookie")
	}
	if a.Browser != nil && a.Browser.Tokens != nil {
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

func ShareRedirect(response http.ResponseWriter, redemption controlv1.ShareRedemption) {
	if err := PermissionCookie(response, redemption.Permission); err != nil {
		http.Error(response, "share visitor permission is unavailable", http.StatusServiceUnavailable)
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
		response.Header().Set("Content-Type", "text/html; charset=utf-8")
		response.Header().Set("Content-Security-Policy", "default-src 'none'; base-uri 'none'")
		response.WriteHeader(http.StatusOK)
		url := html.EscapeString(redemption.NextUrl)
		_, _ = io.WriteString(response, `<!doctype html><html><head><meta charset="utf-8"><meta http-equiv="refresh" content="0;url=`+url+`"><title>tnl preview</title></head><body><a href="`+url+`">Continue to the preview</a></body></html>`)
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

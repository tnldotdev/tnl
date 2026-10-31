package publisher

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
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

const shareCookieName = "__Host-tnl-share"

type shareAccessClient interface {
	EnableShareAccess(context.Context, string, uint64, string, credentials.PublishRunToken) error
	RedeemPublishRunShare(context.Context, string, controlv1.RedeemShareRequest, credentials.PublishRunToken) (controlv1.ShareRedemption, error)
}

type shareAccess struct {
	client  shareAccessClient
	runID   string
	version uint64
	token   credentials.PublishRunToken
	browser *browserAccess
}

func (a *shareAccess) redeem(ctx context.Context, path string) (controlv1.ShareRedemption, error) {
	const linkPrefix = "/__tnl/share/"
	const handoffPrefix = "/__tnl/share/handoff/"
	request := controlv1.RedeemShareRequest{PublishRunNumber: int64(a.version)}
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
	result, err := a.client.RedeemPublishRunShare(ctx, a.runID, request, a.token)
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
	if a.browser != nil && a.browser.tokens != nil {
		source, err := json.Marshal(controlv1.VisitorTokenShareSessionSource{Kind: controlv1.VisitorTokenShareSession, ShareId: result.ShareId, Secret: result.CookieSecret})
		if err == nil {
			err = a.browser.prepareToken(ctx, source, result.Permission, result.ExpiresAt)
		}
		if err != nil {
			return controlv1.ShareRedemption{}, err
		}
	}
	return result, nil
}

func stripTnlCookies(request *http.Request) *http.Request {
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
			if found && name != shareCookieName && name != feedbackBrowserCookieName && name != browserAccessCookieName && name != browserLoginAttemptCookieName && name != visitorTokenCookie && pair != "" {
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

func shareRedirect(response http.ResponseWriter, redemption controlv1.ShareRedemption) {
	if err := visitorPermissionCookie(response, redemption.Permission); err != nil {
		http.Error(response, "share visitor permission is unavailable", http.StatusServiceUnavailable)
		return
	}
	http.SetCookie(response, &http.Cookie{
		Name: shareCookieName, Value: redemption.ShareId + "." + redemption.CookieSecret,
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

func sharePath(path string) bool {
	return strings.HasPrefix(path, "/__tnl/share/")
}

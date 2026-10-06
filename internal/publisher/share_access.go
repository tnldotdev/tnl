package publisher

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"html"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/internal/opaqueid"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

const (
	shareCookieName     = "__Host-tnl-share"
	shareStateFreshness = 30 * time.Second
	shareRefreshPeriod  = 10 * time.Second
)

type shareAccessClient interface {
	EnableShareAccess(context.Context, string, uint64, string, credentials.PublishRunToken) error
	GetPublishRunShareState(context.Context, string, uint64, credentials.PublishRunToken) (controlv1.PublishRunShareState, error)
	RedeemPublishRunShare(context.Context, string, controlv1.RedeemShareRequest, credentials.PublishRunToken) (controlv1.ShareRedemption, error)
}

type cachedShare struct {
	expiresAt time.Time
	cookies   map[[32]byte]struct{}
}

type shareAccess struct {
	client  shareAccessClient
	runID   string
	version uint64
	token   credentials.PublishRunToken

	mu        sync.RWMutex
	confirmed time.Time
	shares    map[string]cachedShare
}

func (a *shareAccess) refresh(ctx context.Context) error {
	started := time.Now()
	response, err := a.client.GetPublishRunShareState(ctx, a.runID, a.version, a.token)
	if err != nil {
		return err
	}
	if len(response.Shares) > 256 {
		return errors.New("publisher: share state exceeds the supported bound")
	}
	shares := make(map[string]cachedShare, len(response.Shares))
	now := time.Now()
	for _, entry := range response.Shares {
		if !opaqueid.Valid(entry.ShareId, opaqueid.SharePrefix) || !entry.ExpiresAt.After(now) || len(entry.CookieHashes) > 2048 {
			return errors.New("publisher: server returned invalid share state")
		}
		fingerprint, err := hex.DecodeString(entry.SecretFingerprint)
		if err != nil || len(fingerprint) != 32 {
			return errors.New("publisher: server returned an invalid share fingerprint")
		}
		if _, duplicate := shares[entry.ShareId]; duplicate {
			return errors.New("publisher: server returned duplicate share state")
		}
		share := cachedShare{expiresAt: entry.ExpiresAt, cookies: make(map[[32]byte]struct{}, len(entry.CookieHashes))}
		for _, encoded := range entry.CookieHashes {
			decoded, err := hex.DecodeString(encoded)
			if err != nil || len(decoded) != 32 {
				return errors.New("publisher: server returned an invalid share cookie hash")
			}
			var digest [32]byte
			copy(digest[:], decoded)
			share.cookies[digest] = struct{}{}
		}
		shares[entry.ShareId] = share
	}
	a.mu.Lock()
	a.shares, a.confirmed = shares, started
	a.mu.Unlock()
	return nil
}

func (a *shareAccess) permits(request *http.Request) bool {
	cookie, err := request.Cookie(shareCookieName)
	if err != nil {
		return false
	}
	shareID, raw, found := strings.Cut(cookie.Value, ".")
	if !found || !opaqueid.Valid(shareID, opaqueid.SharePrefix) {
		return false
	}
	secret, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil || len(secret) != 32 {
		return false
	}
	digest := sha256.Sum256(secret)
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.confirmed.IsZero() || time.Since(a.confirmed) > shareStateFreshness {
		return false
	}
	share, found := a.shares[shareID]
	if !found || !share.expiresAt.After(time.Now()) {
		return false
	}
	_, allowed := share.cookies[digest]
	return allowed
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
	if err := a.refresh(ctx); err != nil {
		return controlv1.ShareRedemption{}, fmt.Errorf("publisher: refresh redeemed share: %w", err)
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
			pair = strings.TrimSpace(pair)
			name, _, found := strings.Cut(pair, "=")
			if found && name != shareCookieName && name != feedbackBrowserCookieName && pair != "" {
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

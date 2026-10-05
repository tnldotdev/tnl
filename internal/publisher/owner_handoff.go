package publisher

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	ownerHandoffLifetime = time.Minute
	ownerSessionLifetime = 4 * time.Hour
)

// OwnerHandoff keeps short-lived local owner links and browser sessions in
// memory. only the private tnl dev socket can issue a new link.
type OwnerHandoff struct {
	mu       sync.Mutex
	pending  map[[32]byte]time.Time
	sessions map[[32]byte]time.Time
}

func NewOwnerHandoff() *OwnerHandoff {
	return &OwnerHandoff{pending: make(map[[32]byte]time.Time), sessions: make(map[[32]byte]time.Time)}
}

func (o *OwnerHandoff) NewLink(publicURL string) (string, error) {
	parsed, err := url.Parse(publicURL)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", errors.New("owner link requires the current HTTPS public URL")
	}
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return "", err
	}
	digest := sha256.Sum256(secret)
	o.mu.Lock()
	defer o.mu.Unlock()
	o.cleanup(time.Now())
	if len(o.pending) >= 16 {
		return "", errors.New("too many unredeemed owner links; retry after a minute")
	}
	o.pending[digest] = time.Now().Add(ownerHandoffLifetime)
	return publicURL + "/__tnl/feedback/owner/handoff/" + base64.RawURLEncoding.EncodeToString(secret), nil
}

func (o *OwnerHandoff) Redeem(token string) (string, time.Time, bool) {
	secret, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil || len(secret) != 32 {
		return "", time.Time{}, false
	}
	digest := sha256.Sum256(secret)
	o.mu.Lock()
	defer o.mu.Unlock()
	now := time.Now()
	o.cleanup(now)
	expires, found := o.pending[digest]
	if !found || !expires.After(now) {
		return "", time.Time{}, false
	}
	delete(o.pending, digest)
	session := make([]byte, 32)
	if _, err := rand.Read(session); err != nil {
		return "", time.Time{}, false
	}
	expires = now.Add(ownerSessionLifetime)
	o.sessions[sha256.Sum256(session)] = expires
	return base64.RawURLEncoding.EncodeToString(session), expires, true
}

func (o *OwnerHandoff) ValidSession(cookie string) bool {
	secret, err := base64.RawURLEncoding.DecodeString(cookie)
	if err != nil || len(secret) != 32 {
		return false
	}
	digest := sha256.Sum256(secret)
	o.mu.Lock()
	defer o.mu.Unlock()
	expires, found := o.sessions[digest]
	return found && expires.After(time.Now())
}

func (o *OwnerHandoff) cleanup(now time.Time) {
	for digest, expires := range o.pending {
		if !expires.After(now) {
			delete(o.pending, digest)
		}
	}
	for digest, expires := range o.sessions {
		if !expires.After(now) {
			delete(o.sessions, digest)
		}
	}
}

func ownerHandoffToken(path string) (string, bool) {
	return strings.CutPrefix(path, "/__tnl/feedback/owner/handoff/")
}

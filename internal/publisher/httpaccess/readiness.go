package httpaccess

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	publisherproxy "github.com/tnldotdev/tnl/internal/publisher/proxy"
)

// ReadinessRun identifies the exact publication accepting a probe. a hostname
// alone is not authority, including when a later run reuses the same hostname.
type ReadinessRun struct {
	Subject  visitorscope.Scope
	ID       string
	Hostname string
	Number   uint64
}

// ReadinessProof is an in-memory, short-lived, single-use proof for one GET path.
// the publication owner renews it for each probe and fences application ownership.
type ReadinessProof struct {
	mu      sync.Mutex
	run     ReadinessRun
	path    string
	secret  string
	expires time.Time
}

func (*ReadinessProof) String() string   { return "readiness proof" }
func (*ReadinessProof) GoString() string { return "readiness proof" }

func NewReadinessProof(run ReadinessRun, path string) (*ReadinessProof, error) {
	if !run.Subject.Valid() || run.Number == 0 || run.Hostname == "" || !strings.HasPrefix(path, "/") ||
		strings.ContainsAny(path, "?#\r\n") || strings.HasPrefix(path, "/__tnl/") {
		return nil, errors.New("readiness proof requires an exact run and absolute path")
	}
	p := &ReadinessProof{run: run, path: path}
	if _, err := p.Renew(); err != nil {
		return nil, err
	}
	return p, nil
}

// Renew replaces any outstanding proof for a later check of the same run/path.
// the returned value belongs only in the probe's private request header.
func (p *ReadinessProof) Renew() (string, error) {
	var secret [32]byte
	if _, err := rand.Read(secret[:]); err != nil {
		return "", err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.secret = hex.EncodeToString(secret[:])
	p.expires = time.Now().Add(2 * time.Minute)
	return p.secret, nil
}

func (p *ReadinessProof) HeaderValue() string {
	if p == nil {
		return ""
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.secret
}

// Consume verifies the body-free request and consumes the proof atomically.
// invalid attempts leave the current proof available for its intended request.
func (p *ReadinessProof) Consume(r *http.Request, run ReadinessRun) bool {
	if p == nil {
		return false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	values := r.Header.Values(publisherproxy.ReadinessProbeHeader)
	if p.secret == "" || !time.Now().Before(p.expires) || run != p.run || r.Method != http.MethodGet ||
		r.URL.EscapedPath() != p.path || r.URL.RawQuery != "" || r.ContentLength != 0 || len(r.TransferEncoding) != 0 || r.Header.Get("Upgrade") != "" || len(values) != 1 ||
		subtle.ConstantTimeCompare([]byte(values[0]), []byte(p.secret)) != 1 {
		return false
	}
	p.secret = ""
	return true
}

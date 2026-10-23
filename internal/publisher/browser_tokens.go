package publisher

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"sort"
	"sync"
	"time"

	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	"github.com/tnldotdev/tnl/internal/httpjson"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/policy/visitorlease"
	"github.com/tnldotdev/tnl/internal/security/visitortoken"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

const maximumBrowserTokenSources = 512
const maximumBrowserTokenAliases = 256

type browserTokenClient interface {
	IssueVisitorToken(context.Context, controlv1.VisitorTokenRequest) (controlv1.VisitorTokenResponse, error)
}

// browserTokens owns renewal for this run's redeemed browser/share sign-ins.
// requests only register use or select an already prepared replacement cookie;
// they never issue or refresh permission. the publisher run closes and joins it.
type browserTokens struct {
	client  browserTokenClient
	policy  *visitorlease.Lease
	mu      sync.Mutex
	sources map[[32]byte]*browserTokenSource
	tokens  map[[32]byte]*browserTokenSource
	cancel  context.CancelFunc
	done    chan struct{}
	closed  bool
}

type browserTokenSource struct {
	source         json.RawMessage
	response       controlv1.VisitorTokenResponse
	permission     visitortoken.Permission
	parentDeadline time.Time
	used           time.Time
	aliases        map[[32]byte]time.Time
	guards         map[*visitorlease.Guard]struct{}
	generation     uint64
	denied         bool
}

type browserTokenRenewal struct {
	key            [32]byte
	source         *browserTokenSource
	generation     uint64
	request        controlv1.VisitorTokenRequest
	permission     visitortoken.Permission
	parentDeadline time.Time
}

func (*browserTokens) String() string        { return "publisher browser token renewal" }
func (*browserTokens) GoString() string      { return "publisher browser token renewal" }
func (*browserTokenSource) String() string   { return "browser token source" }
func (*browserTokenSource) GoString() string { return "browser token source" }

func startBrowserTokens(ctx context.Context, client browserTokenClient, policy *visitorlease.Lease, report func(error)) (*browserTokens, error) {
	if client == nil || policy == nil {
		return nil, errors.New("browser token renewal needs a prepared visitor policy")
	}
	life, cancel := context.WithCancel(ctx)
	b := &browserTokens{client: client, policy: policy, sources: make(map[[32]byte]*browserTokenSource), tokens: make(map[[32]byte]*browserTokenSource), cancel: cancel, done: make(chan struct{})}
	go func() {
		defer close(b.done)
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-life.Done():
				return
			case <-ticker.C:
				b.refresh(life, report)
			}
		}
	}()
	return b, nil
}

func (b *browserTokens) verify(response controlv1.VisitorTokenResponse, parent time.Time) (visitortoken.Permission, error) {
	view, enabled, _ := b.policy.Current()
	if !enabled {
		return visitortoken.Permission{}, visitortoken.ErrPolicy
	}
	permission, err := visitortoken.VerifyBearer(visitortoken.Token(response.VisitorToken), view, time.Now())
	if err != nil {
		return visitortoken.Permission{}, err
	}
	if response.Resource.Id != permission.Scope.ID || string(response.Resource.Kind) != string(permission.Scope.Kind) || response.Hostname != permission.Hostname || response.Port != int(permission.Port) ||
		response.VisitorPolicyRevision != permission.VisitorPolicyRevision || !response.ExpiresAt.Equal(permission.ExpiresAt) || parent.IsZero() || response.ExpiresAt.After(parent) {
		return visitortoken.Permission{}, visitortoken.ErrBinding
	}
	return permission, nil
}

func (b *browserTokens) install(source json.RawMessage, response controlv1.VisitorTokenResponse, parent time.Time) error {
	// only redemption code constructs these two closed source shapes. accepting
	// a general token/grant source here would transfer another credential owner.
	var err error
	source, err = canonicalBrowserTokenSource(source)
	if err != nil {
		return err
	}
	permission, err := b.verify(response, parent)
	if err != nil {
		return err
	}
	var binding struct {
		Kind    string `json:"kind"`
		ShareID string `json:"share_id"`
	}
	if json.Unmarshal(source, &binding) != nil {
		return visitortoken.ErrBinding
	}
	switch subject := permission.Subject.(type) {
	case visitortoken.Browser:
		if binding.Kind != "browser_session" {
			return visitortoken.ErrBinding
		}
	case visitortoken.Share:
		if binding.Kind != "share_session" || binding.ShareID != subject.ShareID {
			return visitortoken.ErrBinding
		}
	default:
		return visitortoken.ErrBinding
	}
	now := time.Now()
	view, _, _ := b.policy.Current()
	key := sha256.Sum256(source)
	digest := sha256.Sum256([]byte(response.VisitorToken))
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return visitortoken.ErrPolicy
	}
	prior := b.sources[key]
	if owner := b.tokens[digest]; owner != nil && owner != prior {
		return visitortoken.ErrBinding
	}
	if prior == nil {
		if len(b.sources) >= maximumBrowserTokenSources {
			return errors.New("publisher browser token sources are full")
		}
		prior = &browserTokenSource{source: bytes.Clone(source), aliases: make(map[[32]byte]time.Time), guards: make(map[*visitorlease.Guard]struct{})}
		b.sources[key] = prior
	} else if prior.permission.Subject != permission.Subject || !prior.parentDeadline.Equal(parent) {
		return visitortoken.ErrBinding
	}
	for digest, until := range prior.aliases {
		if !until.After(view.AuthorityTime(now)) {
			delete(prior.aliases, digest)
			delete(b.tokens, digest)
		}
	}
	if _, exists := prior.aliases[digest]; !exists && len(prior.aliases) >= maximumBrowserTokenAliases {
		return errors.New("browser token renewal aliases are full")
	}
	prior.response, prior.permission, prior.parentDeadline, prior.used = response, permission, parent, now
	clear(prior.source)
	prior.source = bytes.Clone(source)
	prior.generation++
	prior.denied = false
	prior.aliases[digest], b.tokens[digest] = permission.ExpiresAt, prior
	return nil
}

// use follows signature, policy, source-IP, and request admission. an expired
// cookie is never a handle for selecting another prepared credential.
func (b *browserTokens) use(token visitortoken.Token, guard *visitorlease.Guard) (controlv1.VisitorTokenResponse, func(), bool) {
	digest := sha256.Sum256([]byte(token.Reveal()))
	view, enabled, _ := b.policy.Current()
	now := time.Now()
	b.mu.Lock()
	source := b.tokens[digest]
	if b.closed || !enabled || source == nil || source.denied || !source.aliases[digest].After(view.AuthorityTime(now)) {
		b.mu.Unlock()
		return controlv1.VisitorTokenResponse{}, func() {}, false
	}
	source.used = now
	if guard != nil {
		if err := guard.AllowRenewal(); err != nil {
			b.mu.Unlock()
			return controlv1.VisitorTokenResponse{}, func() {}, false
		}
		// renewal may have completed before this request began. use that
		// already verified same-source permission now, without waiting for the
		// next issuer cycle or resetting an authority deadline.
		_ = guard.Renew(source.permission)
		source.guards[guard] = struct{}{}
	}
	response := source.response
	b.mu.Unlock()
	release := sync.OnceFunc(func() {
		b.mu.Lock()
		delete(source.guards, guard)
		b.mu.Unlock()
	})
	return response, release, true
}

func (b *browserTokens) replacement(token visitortoken.Token, proof visitortoken.Permission) (visitortoken.Token, visitortoken.Permission, error) {
	response, release, found := b.use(token, nil)
	defer release()
	if !found || response.VisitorToken == token.Reveal() {
		return "", visitortoken.Permission{}, visitortoken.ErrToken
	}
	view, enabled, _ := b.policy.Current()
	if !enabled {
		return "", visitortoken.Permission{}, visitortoken.ErrPolicy
	}
	replacement := visitortoken.Token(response.VisitorToken)
	permission, err := visitortoken.VerifyBearer(replacement, view, time.Now())
	if err != nil || permission.Subject != proof.Subject || permission.Scope != proof.Scope || permission.Hostname != proof.Hostname || permission.Port != proof.Port {
		return "", visitortoken.Permission{}, visitortoken.ErrBinding
	}
	return replacement, permission, nil
}

// keep explicit renewal denials until the supplied tokens expire, including
// before the next policy snapshot observes that revocation.
func (b *browserTokens) rejects(token visitortoken.Token) bool {
	digest := sha256.Sum256([]byte(token.Reveal()))
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.closed || b.tokens[digest] != nil && b.tokens[digest].denied
}

func (b *browserTokens) refresh(ctx context.Context, report func(error)) {
	view, enabled, _ := b.policy.Current()
	if !enabled {
		return
	}
	now := time.Now()
	b.mu.Lock()
	var due []browserTokenRenewal
	for key, source := range b.sources {
		for digest, expires := range source.aliases {
			if !expires.After(view.AuthorityTime(now)) {
				delete(source.aliases, digest)
				delete(b.tokens, digest)
			}
		}
		if !source.parentDeadline.After(view.AuthorityTime(now)) || len(source.guards) == 0 && (source.denied && len(source.aliases) == 0 || !source.denied && !source.used.Add(5*time.Minute).After(now)) {
			for digest := range source.aliases {
				delete(b.tokens, digest)
			}
			clear(source.source)
			delete(b.sources, key)
			continue
		}
		if source.denied {
			clear(source.source)
			continue
		}
		if source.response.VisitorPolicyRevision != view.VisitorPolicyRevision || !source.response.ExpiresAt.After(view.AuthorityTime(now).Add(time.Minute)) {
			due = append(due, browserTokenRenewal{key: key, source: source, generation: source.generation,
				request: controlv1.VisitorTokenRequest{Resource: source.response.Resource, Source: bytes.Clone(source.source)}, permission: source.permission, parentDeadline: source.parentDeadline})
		}
	}
	b.mu.Unlock()
	if len(due) == 0 {
		return
	}
	sort.Slice(due, func(i, j int) bool { return due[i].permission.ExpiresAt.Before(due[j].permission.ExpiresAt) })
	batch, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	jobs := make(chan browserTokenRenewal)
	var workers sync.WaitGroup
	for range min(8, len(due)) {
		workers.Go(func() {
			for job := range jobs {
				b.renew(batch, job, report)
			}
		})
	}
	for _, job := range due {
		select {
		case jobs <- job:
		case <-batch.Done():
			close(jobs)
			workers.Wait()
			for _, pending := range due {
				clear(pending.request.Source)
			}
			return
		}
	}
	close(jobs)
	workers.Wait()
	for _, job := range due {
		clear(job.request.Source)
	}
}

func (b *browserTokens) renew(ctx context.Context, job browserTokenRenewal, report func(error)) {
	if ctx.Err() != nil {
		return
	}
	response, err := b.client.IssueVisitorToken(ctx, job.request)
	if err == nil {
		err = ctx.Err()
	}
	var permission visitortoken.Permission
	if err == nil {
		permission, err = b.verify(response, job.parentDeadline)
		if err == nil && permission.Subject != job.permission.Subject {
			err = visitortoken.ErrBinding
		}
	}
	var problem *clientcontrol.ProblemError
	terminal := errors.Is(err, clientcontrol.ErrUnauthenticated) || errors.As(err, &problem) && (problem.Status == http.StatusUnauthorized || problem.Status == http.StatusForbidden)
	var guards []*visitorlease.Guard
	b.mu.Lock()
	source := job.source
	current := !b.closed && b.sources[job.key] == source && !source.denied && source.generation == job.generation
	if current && (err == nil || terminal) {
		for guard := range source.guards {
			guards = append(guards, guard)
		}
		if terminal {
			source.denied = true
		} else {
			digest := sha256.Sum256([]byte(response.VisitorToken))
			if owner := b.tokens[digest]; owner != nil && owner != source {
				err = visitortoken.ErrBinding
			} else if _, exists := source.aliases[digest]; !exists && len(source.aliases) >= maximumBrowserTokenAliases {
				err = errors.New("browser token renewal aliases are full")
			} else {
				source.response, source.permission = response, permission
				source.aliases[digest], b.tokens[digest] = permission.ExpiresAt, source
				source.generation++
			}
		}
	}
	b.mu.Unlock()
	for _, guard := range guards {
		if terminal {
			guard.Revoke()
		} else if err == nil {
			_ = guard.Renew(permission)
		}
	}
	if current && err != nil && ctx.Err() == nil && report != nil {
		report(err)
	}
}

func (b *browserTokens) Close() {
	b.mu.Lock()
	b.closed = true
	b.mu.Unlock()
	b.cancel()
	<-b.done
	b.mu.Lock()
	for key, source := range b.sources {
		clear(source.source)
		delete(b.sources, key)
	}
	clear(b.tokens)
	b.mu.Unlock()
}

func canonicalBrowserTokenSource(source json.RawMessage) (json.RawMessage, error) {
	var kind struct {
		Kind string `json:"kind"`
	}
	if len(source) > 4096 || json.Unmarshal(source, &kind) != nil {
		return nil, visitortoken.ErrToken
	}
	decode := func(value any) error { return httpjson.Decode(json.NewDecoder(bytes.NewReader(source)), value) }
	validSecret := func(secret string) bool {
		raw, err := base64.RawURLEncoding.Strict().DecodeString(secret)
		return err == nil && len(raw) == 32
	}
	switch kind.Kind {
	case "browser_session":
		var value controlv1.VisitorTokenBrowserSessionSource
		if decode(&value) != nil || !validSecret(value.Secret) {
			return nil, visitortoken.ErrToken
		}
		return json.Marshal(value)
	case "share_session":
		var value controlv1.VisitorTokenShareSessionSource
		if decode(&value) != nil || !validSecret(value.Secret) || !opaqueid.Valid(value.ShareId, opaqueid.SharePrefix) {
			return nil, visitortoken.ErrToken
		}
		return json.Marshal(value)
	default:
		return nil, visitortoken.ErrToken
	}
}

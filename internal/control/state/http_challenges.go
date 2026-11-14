package state

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/control/turnstile"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/policy/httpprotection"
	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	"github.com/tnldotdev/tnl/internal/security/visitortoken"
)

var (
	ErrHTTPChallenge         = errors.New("challenge attempt or handoff is invalid")
	ErrHTTPChallengeCapacity = errors.New("challenge attempt capacity is occupied")
)

type HTTPChallengeAttempt struct {
	ID        string
	Scope     visitorscope.Scope
	Hostname  string
	Port      uint16
	ExpiresAt time.Time
}

type HTTPChallengeHandoff struct {
	Secret, Origin string
}

func (HTTPChallengeHandoff) String() string   { return "challenge handoff" }
func (HTTPChallengeHandoff) GoString() string { return "challenge handoff" }

func challengeAttempt(row controlstatedb.ControlHttpChallenge) HTTPChallengeAttempt {
	return HTTPChallengeAttempt{ID: row.ID, Scope: visitorscope.Scope{Kind: visitorscope.Kind(row.ResourceKind), ID: row.ResourceID}, Hostname: row.Hostname, Port: uint16(row.Port), ExpiresAt: row.ExpiresAt.Time}
}

func (d *Database) lockHTTPChallengeResource(ctx context.Context, tx pgx.Tx, scope visitorscope.Scope, now time.Time) (visitorResource, error) {
	resource, err := lockVisitorResource(ctx, tx, scope, now)
	if err != nil {
		return resource, err
	}
	q := controlstatedb.New(tx)
	if scope.Kind == visitorscope.Service {
		service, err := q.GetService(ctx, scope.ID)
		if err != nil {
			return resource, err
		}
		if service.Protocol != "http" || !service.Public {
			return resource, ErrHTTPChallenge
		}
		settings, err := d.serviceHTTPSettings(ctx, q, scope.ID)
		if err != nil {
			return resource, err
		}
		if settings != nil && settings.Protection != nil && settings.Protection.Challenge == httpprotection.Turnstile {
			return resource, nil
		}
		return resource, ErrHTTPChallenge
	}
	url, err := q.GetFeedbackPublicURL(ctx, scope.ID)
	if err != nil {
		return resource, err
	}
	if url.LifecycleState != string(PublicURLLifecycleEnabled) {
		return resource, ErrHTTPChallenge
	}
	runs, err := q.ListOpenPublishRuns(ctx, scope.ID)
	if err != nil {
		return resource, err
	}
	for _, run := range runs {
		var settings httpprotection.Settings
		if json.Unmarshal(run.HttpProtection, &settings) != nil || settings.Validate() != nil {
			return resource, ErrHTTPChallenge
		}
		if run.State != "ready" || !run.PublisherExpiresAt.Time.After(now) || settings.Challenge != httpprotection.Turnstile {
			continue
		}
		live, err := d.publisherRunLive(ctx, q, url, run, now)
		if err != nil {
			return resource, err
		}
		if live {
			return resource, nil
		}
	}
	return resource, ErrHTTPChallenge
}

func (d *Database) BeginHTTPChallenge(ctx context.Context, scope visitorscope.Scope, browserHash, publisherHash []byte, now time.Time) (result HTTPChallengeAttempt, retErr error) {
	if !scope.Valid() || len(browserHash) != 32 || len(publisherHash) != 32 {
		return result, ErrHTTPChallenge
	}
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "begin HTTP challenge", &retErr)()
	resource, err := d.lockHTTPChallengeResource(ctx, tx, scope, now)
	if err != nil {
		return result, err
	}
	q := controlstatedb.New(tx)
	if err := q.PruneHTTPResourceChallenges(ctx, controlstatedb.PruneHTTPResourceChallengesParams{ResourceKind: string(scope.Kind), ResourceID: scope.ID, Now: timestamptz(now)}); err != nil {
		return result, err
	}
	count, err := q.CountHTTPChallenges(ctx, controlstatedb.CountHTTPChallengesParams{ResourceKind: string(scope.Kind), ResourceID: scope.ID})
	if err != nil {
		return result, err
	}
	if count >= 256 {
		return result, ErrHTTPChallengeCapacity
	}
	id, err := opaqueid.New(opaqueid.HTTPChallengePrefix)
	if err != nil {
		return result, err
	}
	row, err := q.CreateHTTPChallenge(ctx, controlstatedb.CreateHTTPChallengeParams{ID: id, ResourceKind: string(scope.Kind), ResourceID: scope.ID,
		Hostname: resource.Hostname, Port: int32(resource.Port), BrowserBindingHash: browserHash, PublisherBindingHash: publisherHash,
		ExpiresAt: timestamptz(now.Add(httpprotection.ChallengeAttemptLifetime))})
	if err != nil {
		return result, err
	}
	return challengeAttempt(row), tx.Commit(ctx)
}

func (d *Database) ReadHTTPChallenge(ctx context.Context, id string, browserHash []byte, now time.Time) (HTTPChallengeAttempt, error) {
	if !opaqueid.Valid(id, opaqueid.HTTPChallengePrefix) || len(browserHash) != 32 {
		return HTTPChallengeAttempt{}, ErrHTTPChallenge
	}
	row, err := controlstatedb.New(d.pool).GetHTTPChallenge(ctx, id)
	if err != nil {
		return HTTPChallengeAttempt{}, publisherLookupError(err, ErrHTTPChallenge)
	}
	if subtle.ConstantTimeCompare(row.BrowserBindingHash, browserHash) != 1 || !row.ExpiresAt.Time.After(now) || row.VerificationStartedAt.Valid {
		return HTTPChallengeAttempt{}, ErrHTTPChallenge
	}
	return challengeAttempt(row), nil
}

// claiming precedes the provider call. replicas cannot verify or complete one
// attempt twice; an unavailable provider requires a new browser-bound attempt.
func (d *Database) ClaimHTTPChallenge(ctx context.Context, id string, browserHash []byte, now time.Time) error {
	if !opaqueid.Valid(id, opaqueid.HTTPChallengePrefix) || len(browserHash) != 32 {
		return ErrHTTPChallenge
	}
	_, err := controlstatedb.New(d.pool).ClaimHTTPChallenge(ctx, controlstatedb.ClaimHTTPChallengeParams{ID: id, BrowserBindingHash: browserHash, Now: timestamptz(now)})
	return publisherLookupError(err, ErrHTTPChallenge)
}

func (d *Database) CompleteHTTPChallenge(ctx context.Context, proof turnstile.VerifiedAttempt, now time.Time) (result HTTPChallengeHandoff, retErr error) {
	if !opaqueid.Valid(proof.ID(), opaqueid.HTTPChallengePrefix) {
		return result, ErrHTTPChallenge
	}
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "complete HTTP challenge", &retErr)()
	q := controlstatedb.New(tx)
	attempt, err := q.GetHTTPChallenge(ctx, proof.ID())
	if err != nil {
		return result, publisherLookupError(err, ErrHTTPChallenge)
	}
	scope := visitorscope.Scope{Kind: visitorscope.Kind(attempt.ResourceKind), ID: attempt.ResourceID}
	resource, err := d.lockHTTPChallengeResource(ctx, tx, scope, now)
	if err != nil {
		return result, err
	}
	if resource.Hostname != attempt.Hostname || int32(resource.Port) != attempt.Port {
		return result, ErrHTTPChallenge
	}
	var secret [32]byte
	if _, err := rand.Read(secret[:]); err != nil {
		return result, err
	}
	digest := sha256.Sum256(secret[:])
	changed, err := q.CompleteHTTPChallenge(ctx, controlstatedb.CompleteHTTPChallengeParams{ID: proof.ID(), Now: timestamptz(now), HandoffHash: digest[:], HandoffExpiresAt: timestamptz(now.Add(httpprotection.ChallengeHandoffLifetime))})
	if err != nil {
		return result, err
	}
	if changed != 1 {
		return result, ErrHTTPChallenge
	}
	result = HTTPChallengeHandoff{Secret: proof.ID() + "." + base64.RawURLEncoding.EncodeToString(secret[:]), Origin: visitortoken.ClearanceOrigin(resource.Hostname, resource.Port)}
	return result, tx.Commit(ctx)
}

func (d *Database) RedeemHTTPChallenge(ctx context.Context, scope visitorscope.Scope, run string, number int64, token, handoff, binding, issuer string, now time.Time) (result visitortoken.ClearanceToken, expires time.Time, retErr error) {
	if len(handoff) > 128 || len(binding) != 43 {
		return "", expires, ErrHTTPChallenge
	}
	id, secret, found := strings.Cut(handoff, ".")
	raw, err := base64.RawURLEncoding.Strict().DecodeString(secret)
	browser, bindingErr := base64.RawURLEncoding.Strict().DecodeString(binding)
	if !found || !opaqueid.Valid(id, opaqueid.HTTPChallengePrefix) || err != nil || bindingErr != nil || len(raw) != 32 || len(browser) != 32 {
		return "", expires, ErrHTTPChallenge
	}
	digest, publisherHash := sha256.Sum256(raw), sha256.Sum256(browser)
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return "", expires, err
	}
	defer rollback(ctx, tx, "redeem HTTP challenge", &retErr)()
	resource, err := d.lockHTTPChallengeResource(ctx, tx, scope, now)
	if err != nil {
		return "", expires, err
	}
	q := controlstatedb.New(tx)
	authority, err := d.authorizePublisherVisitorRun(ctx, tx, q, scope, run, number, token, now)
	if err != nil {
		return "", expires, err
	}
	if authority.protection.Challenge != httpprotection.Turnstile {
		return "", expires, ErrHTTPChallenge
	}
	attempt, err := q.RedeemHTTPChallenge(ctx, controlstatedb.RedeemHTTPChallengeParams{ID: id, ResourceKind: string(scope.Kind), ResourceID: scope.ID,
		HandoffHash: digest[:], PublisherBindingHash: publisherHash[:], Now: timestamptz(now)})
	if err != nil {
		return "", expires, publisherLookupError(err, ErrHTTPChallenge)
	}
	if resource.Hostname != attempt.Hostname || int32(resource.Port) != attempt.Port {
		return "", expires, ErrHTTPChallenge
	}
	expires = attempt.VerifiedAt.Time.Add(visitortoken.ClearanceLifetime).UTC().Truncate(time.Second)
	clearance := visitortoken.Clearance{Scope: scope, Hostname: resource.Hostname, Port: resource.Port, ExpiresAt: expires}
	signed, err := d.signVisitorCredential(ctx, tx, issuer, expires, now, func(keyID string, private ed25519.PrivateKey) (string, error) {
		token, err := visitortoken.SignClearance(issuer, keyID, private, clearance, now)
		return token.Reveal(), err
	})
	if err != nil {
		return "", expires, err
	}
	return visitortoken.ClearanceToken(signed), expires, tx.Commit(ctx)
}

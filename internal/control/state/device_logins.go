package state

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
)

var ErrDeviceLogin = errors.New("device login is invalid or expired")

type DeviceLogin struct {
	TeamID, PreviousSessionID, ExpectedIdentityID string
	CompanyIntent                                 *CompanyLoginIntent
	UserCode                                      string
	ExpiresAt                                     time.Time
	Status                                        DeviceLoginStatus
	State, Nonce, Verifier                        string
	Binding                                       []byte
	Identity                                      *OIDCIdentity
	Session                                       *ControlSession
}

type DeviceLoginStatus string

const (
	DevicePending   DeviceLoginStatus = "pending"
	DeviceApproved  DeviceLoginStatus = "approved"
	DeviceCancelled DeviceLoginStatus = "cancelled"
	DeviceDenied    DeviceLoginStatus = "denied"
)

type DeviceLoginOptions struct{ Team, RefreshToken string }

func (d *Database) CreateDeviceLogin(ctx context.Context, options DeviceLoginOptions, now time.Time) (result DeviceLogin, credential string, retErr error) {
	var material [32]byte
	if _, err := rand.Read(material[:]); err != nil {
		return DeviceLogin{}, "", err
	}
	credential = base64.RawURLEncoding.EncodeToString(material[:])
	digest := sha256.Sum256([]byte(credential))
	if _, err := rand.Read(material[:]); err != nil {
		return DeviceLogin{}, "", err
	}
	code := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(material[:8])
	login := DeviceLogin{UserCode: code, ExpiresAt: now.Add(10 * time.Minute), Status: DevicePending}
	team, err := d.ResolveLoginTeam(ctx, options.Team)
	if err != nil {
		return login, "", err
	}
	login.TeamID = team
	if options.RefreshToken != "" {
		login.PreviousSessionID, login.ExpectedIdentityID, err = (loginReauthentication{controlstatedb.New(d.pool)}).check(ctx, options.RefreshToken, now)
		if err != nil {
			return login, "", err
		}
	}
	bytes, err := json.Marshal(login)
	if err != nil {
		return login, "", err
	}
	payload, err := d.sealSecret(deviceLoginContext(digest[:]), bytes)
	if err != nil {
		return login, "", err
	}
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return login, "", err
	}
	defer rollback(ctx, tx, "create device login", &retErr)()
	q := controlstatedb.New(tx)
	if err := q.LockDeviceLoginCapacity(ctx); err != nil {
		return login, "", err
	}
	if err := q.DeleteExpiredDeviceLogins(ctx, timestamptz(now)); err != nil {
		return login, "", err
	}
	inserted, err := q.InsertDeviceLogin(ctx, controlstatedb.InsertDeviceLoginParams{CredentialDigest: digest[:], UserCode: code, ExpiresAt: timestamptz(login.ExpiresAt), Payload: payload, StorageKeyID: d.storageKey.CurrentID()})
	if err == nil && inserted != 1 {
		err = errors.New("device login capacity reached")
	}
	if err == nil {
		err = tx.Commit(ctx)
	}
	return login, credential, err
}

func (d *Database) ExpireDeviceLogins(ctx context.Context, now time.Time) error {
	return controlstatedb.New(d.pool).DeleteExpiredDeviceLogins(ctx, timestamptz(now))
}

func (d *Database) DenyDeviceBrowser(ctx context.Context, code string, binding []byte, now time.Time) error {
	_, err := d.mutateDeviceLogin(ctx, func(q *controlstatedb.Queries) (controlstatedb.ControlDeviceLogin, error) {
		return q.LockDeviceLoginByCode(ctx, code)
	}, now, func(l *DeviceLogin, _ *controlstatedb.Queries) error {
		if l.Status != DevicePending || !deviceBindingMatches(l.Binding, binding) {
			return ErrDeviceLogin
		}
		l.clearBrowser(DeviceDenied)
		return nil
	})
	return err
}

func deviceLoginContext(digest []byte) string { return "device-login:" + hex.EncodeToString(digest) }

// every transition is serialized in PostgreSQL, including session creation and
// cancellation. a repeated private poll returns the same encrypted result.
func (d *Database) mutateDeviceLogin(ctx context.Context, lookup func(*controlstatedb.Queries) (controlstatedb.ControlDeviceLogin, error), now time.Time, mutate func(*DeviceLogin, *controlstatedb.Queries) error) (result DeviceLogin, retErr error) {
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "device login", &retErr)()
	q := controlstatedb.New(tx)
	row, err := lookup(q)
	if errors.Is(err, pgx.ErrNoRows) {
		return result, ErrDeviceLogin
	}
	if err != nil {
		return result, err
	}
	if !row.ExpiresAt.Time.After(now) {
		return result, ErrDeviceLogin
	}
	bytes, _, err := d.openSecret(row.StorageKeyID, deviceLoginContext(row.CredentialDigest), row.Payload)
	if err != nil {
		return result, err
	}
	if err := json.Unmarshal(bytes, &result); err != nil {
		return result, err
	}
	if _, err := result.stage(); err != nil {
		return result, err
	}
	if err := mutate(&result, q); err != nil {
		return result, err
	}
	if _, err := result.stage(); err != nil {
		return result, err
	}
	bytes, err = json.Marshal(result)
	if err != nil {
		return result, err
	}
	payload, err := d.sealSecret(deviceLoginContext(row.CredentialDigest), bytes)
	if err != nil {
		return result, err
	}
	var state []byte
	if result.State != "" {
		sum := sha256.Sum256([]byte(result.State))
		state = sum[:]
	}
	if err := q.UpdateDeviceLogin(ctx, controlstatedb.UpdateDeviceLoginParams{CredentialDigest: row.CredentialDigest, Payload: payload, StorageKeyID: d.storageKey.CurrentID(), StateDigest: state}); err != nil {
		return result, err
	}
	return result, tx.Commit(ctx)
}

func (d *Database) PollDeviceLogin(ctx context.Context, credential string, now time.Time) (DeviceLogin, error) {
	if len(credential) != 43 {
		return DeviceLogin{}, ErrDeviceLogin
	}
	digest := sha256.Sum256([]byte(credential))
	return d.mutateDeviceLogin(ctx, func(q *controlstatedb.Queries) (controlstatedb.ControlDeviceLogin, error) {
		return q.LockDeviceLoginByCredential(ctx, digest[:])
	}, now, func(*DeviceLogin, *controlstatedb.Queries) error { return nil })
}

func (d *Database) CancelDeviceLogin(ctx context.Context, credential string, now time.Time) error {
	if len(credential) != 43 {
		return ErrDeviceLogin
	}
	digest := sha256.Sum256([]byte(credential))
	_, err := d.mutateDeviceLogin(ctx, func(q *controlstatedb.Queries) (controlstatedb.ControlDeviceLogin, error) {
		return q.LockDeviceLoginByCredential(ctx, digest[:])
	}, now, func(l *DeviceLogin, q *controlstatedb.Queries) error {
		stage, err := l.stage()
		if err != nil {
			return err
		}
		if issued, ok := stage.(deviceIssuedSession); ok {
			if _, err := q.RevokeControlSession(ctx, controlstatedb.RevokeControlSessionParams{ID: issued.session.SessionID, RevokedAt: timestamptz(now), RevokedBy: text(issued.session.Identity.Identity.ID)}); err != nil {
				return err
			}
		}
		l.clearBrowser(DeviceCancelled)
		return nil
	})
	return err
}

func (d *Database) ReadDeviceBrowser(ctx context.Context, code string, now time.Time) (DeviceLogin, error) {
	if len(code) != 13 {
		return DeviceLogin{}, ErrDeviceLogin
	}
	return d.mutateDeviceLogin(ctx, func(q *controlstatedb.Queries) (controlstatedb.ControlDeviceLogin, error) {
		return q.LockDeviceLoginByCode(ctx, code)
	}, now, func(l *DeviceLogin, _ *controlstatedb.Queries) error {
		if l.Status != DevicePending {
			return ErrDeviceLogin
		}
		return nil
	})
}

func (d *Database) BeginDeviceBrowser(ctx context.Context, code, state, nonce, verifier string, binding []byte, team string, intent *CompanyLoginIntent, now time.Time) error {
	if len(code) != 13 || len(state) != 43 || len(nonce) != 43 || len(verifier) < 43 || len(binding) != 32 {
		return ErrDeviceLogin
	}
	_, err := d.mutateDeviceLogin(ctx, func(q *controlstatedb.Queries) (controlstatedb.ControlDeviceLogin, error) {
		return q.LockDeviceLoginByCode(ctx, code)
	}, now, func(l *DeviceLogin, _ *controlstatedb.Queries) error {
		return l.beginBrowser(deviceBrowserExchange{state, nonce, verifier, binding}, team, intent)
	})
	return err
}

// consume before redeeming the one-use upstream code; an uncertain exchange
// requires a fresh browser attempt, never blind redemption of the same code.
func (d *Database) ConsumeDeviceBrowser(ctx context.Context, state string, binding []byte, now time.Time) (DeviceLogin, error) {
	if len(state) != 43 || len(binding) != 32 {
		return DeviceLogin{}, ErrDeviceLogin
	}
	digest := sha256.Sum256([]byte(state))
	return d.mutateDeviceLogin(ctx, func(q *controlstatedb.Queries) (controlstatedb.ControlDeviceLogin, error) {
		return q.LockDeviceLoginByState(ctx, digest[:])
	}, now, func(l *DeviceLogin, _ *controlstatedb.Queries) error {
		return l.consumeBrowser(binding)
	})
}

func (d *Database) VerifyDeviceBrowser(ctx context.Context, code string, binding []byte, identity OIDCIdentity, now time.Time) error {
	_, err := d.mutateDeviceLogin(ctx, func(q *controlstatedb.Queries) (controlstatedb.ControlDeviceLogin, error) {
		return q.LockDeviceLoginByCode(ctx, code)
	}, now, func(l *DeviceLogin, _ *controlstatedb.Queries) error {
		return l.verifyBrowser(binding, identity)
	})
	return err
}

func (d *Database) ApproveDeviceLogin(ctx context.Context, code string, binding []byte, managedDomain string, access, refresh time.Duration, now time.Time) error {
	_, err := d.mutateDeviceLogin(ctx, func(q *controlstatedb.Queries) (controlstatedb.ControlDeviceLogin, error) {
		return q.LockDeviceLoginByCode(ctx, code)
	}, now, func(l *DeviceLogin, q *controlstatedb.Queries) error {
		stage, err := l.stage()
		verified, ok := stage.(deviceVerifiedIdentity)
		if err != nil || !ok || !deviceBindingMatches(verified.binding, binding) || !verified.identity.AssertionExpiry.After(now) {
			return ErrDeviceLogin
		}
		session, err := d.createOIDCControlSession(ctx, q, managedDomain, verified.identity, access, refresh, now)
		if err != nil {
			return err
		}
		if l.ExpectedIdentityID != "" && session.Identity.Identity.ID != l.ExpectedIdentityID {
			return ErrControlAuthentication
		}
		if l.PreviousSessionID != "" {
			if err := q.CopyCompanySessionContexts(ctx, controlstatedb.CopyCompanySessionContextsParams{SourceSessionID: l.PreviousSessionID, DestinationSessionID: session.SessionID, ExpiresAt: timestamptz(session.RefreshExpiresAt), Now: timestamptz(now)}); err != nil {
				return err
			}
		}
		deadline, err := q.GetCompanyAuthenticationDeadline(ctx, session.SessionID)
		if err != nil {
			return err
		}
		session.CompanyAuthenticationExpiresAt = optionalTime(deadline)
		if l.TeamID != "" {
			session.Identity.DefaultTeamID = l.TeamID
		}
		l.issueSession(session)
		return nil
	})
	return err
}

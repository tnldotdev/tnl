package state

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/internal/state/statedb"
)

func TestControlSessionLifecycleAndRotation(t *testing.T) {
	db, err := Open(context.Background(), filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	now := time.Unix(1_700_000_000, 0).UTC()
	session, access, refresh := newStoredControlSession(t, 1, now)
	if err := CreateControlSession(context.Background(), db, session, nil, time.Time{}); err != nil {
		t.Fatal(err)
	}

	accessID, accessHash, _ := credentials.ParseAccessToken(access)
	authenticated, err := AuthenticateControlSession(context.Background(), db, accessID, accessHash, now)
	if err != nil {
		t.Fatal(err)
	}
	if authenticated.SessionID != session.ID || authenticated.Identity != session.Identity ||
		len(authenticated.Grants) != 2 || authenticated.Grants[0] != "publish" || authenticated.Grants[1] != "admin" {
		t.Fatalf("authenticated session = %#v", authenticated)
	}
	stored, err := statedb.New(db).GetControlSession(context.Background(), session.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(stored.AccessTokenHash, session.AccessTokenHash[:]) ||
		!bytes.Equal(stored.RefreshTokenHash, session.RefreshTokenHash[:]) {
		t.Fatal("stored credential hashes differ")
	}

	newAccess, newAccessID, newAccessHash, err := credentials.NewAccessToken()
	if err != nil {
		t.Fatal(err)
	}
	newRefresh, newRefreshID, newRefreshHash, err := credentials.NewRefreshToken()
	if err != nil {
		t.Fatal(err)
	}
	refreshID, refreshHash, _ := credentials.ParseRefreshToken(refresh)
	rotation, err := RotateControlSession(
		context.Background(), db, refreshID, refreshHash, newAccessID, newAccessHash,
		now.Add(2*time.Hour), newRefreshID, newRefreshHash, now.Add(time.Minute),
	)
	if err != nil {
		t.Fatal(err)
	}
	if rotation.SessionID != session.ID || rotation.RefreshExpiresAt != session.RefreshExpiresAt ||
		rotation.AccessExpiresAt != now.Add(2*time.Hour) || len(rotation.Grants) != 2 {
		t.Fatalf("rotation = %#v", rotation)
	}
	if _, err := AuthenticateControlSession(context.Background(), db, accessID, accessHash, now); !errors.Is(err, credentials.ErrInvalidAccessToken) {
		t.Fatalf("replaced access token error = %v", err)
	}
	newID, newHash, _ := credentials.ParseAccessToken(newAccess)
	if _, err := AuthenticateControlSession(context.Background(), db, newID, newHash, now); err != nil {
		t.Fatalf("rotated access token: %v", err)
	}
	if count, err := statedb.New(db).CountControlSessionRefreshHistory(context.Background(), session.ID); err != nil || count != 1 {
		t.Fatalf("refresh history count = %d, error = %v", count, err)
	}

	// Exact reuse of any replaced refresh token revokes the whole session family.
	_, err = RotateControlSession(
		context.Background(), db, refreshID, refreshHash, newAccessID, newAccessHash,
		now.Add(2*time.Hour), newRefreshID, newRefreshHash, now.Add(2*time.Minute),
	)
	if !errors.Is(err, credentials.ErrInvalidRefreshToken) {
		t.Fatalf("replayed refresh token error = %v", err)
	}
	if _, err := AuthenticateControlSession(context.Background(), db, newID, newHash, now); !errors.Is(err, credentials.ErrInvalidAccessToken) {
		t.Fatalf("access after refresh replay error = %v", err)
	}
	newRefreshID, newRefreshHash, _ = credentials.ParseRefreshToken(newRefresh)
	_, err = RotateControlSession(
		context.Background(), db, newRefreshID, newRefreshHash, accessID, accessHash,
		now.Add(time.Hour), refreshID, refreshHash, now.Add(3*time.Minute),
	)
	if !errors.Is(err, credentials.ErrInvalidRefreshToken) {
		t.Fatalf("refresh after family revocation error = %v", err)
	}
}

func TestControlSessionCapRevokesOldest(t *testing.T) {
	db, err := Open(context.Background(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	now := time.Unix(1_700_000_000, 0).UTC()
	var first credentials.AccessToken
	for index := 0; index < MaxActiveControlSessions+1; index++ {
		session, access, _ := newStoredControlSession(t, index+1, now.Add(time.Duration(index)*time.Second))
		if index == 0 {
			first = access
		}
		if err := CreateControlSession(context.Background(), db, session, nil, time.Time{}); err != nil {
			t.Fatal(err)
		}
	}
	count, err := statedb.New(db).CountActiveControlSessions(context.Background(), now.UnixNano())
	if err != nil || count != MaxActiveControlSessions {
		t.Fatalf("active sessions = %d, error = %v", count, err)
	}
	firstID, firstHash, _ := credentials.ParseAccessToken(first)
	if _, err := AuthenticateControlSession(context.Background(), db, firstID, firstHash, now); !errors.Is(err, credentials.ErrInvalidAccessToken) {
		t.Fatalf("oldest access token error = %v", err)
	}
}

func TestControlSessionCapRetainsNewSessionWhenTimestampsTie(t *testing.T) {
	db, err := Open(context.Background(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	now := time.Unix(1_700_000_000, 0).UTC()
	for index := MaxActiveControlSessions + 1; index > 1; index-- {
		session, _, _ := newStoredControlSession(t, index, now)
		if err := CreateControlSession(context.Background(), db, session, nil, time.Time{}); err != nil {
			t.Fatal(err)
		}
	}
	newest, access, _ := newStoredControlSession(t, 1, now)
	if err := CreateControlSession(context.Background(), db, newest, nil, time.Time{}); err != nil {
		t.Fatal(err)
	}
	accessID, accessHash, _ := credentials.ParseAccessToken(access)
	if _, err := AuthenticateControlSession(context.Background(), db, accessID, accessHash, now); err != nil {
		t.Fatalf("new control session was revoked by cap: %v", err)
	}
	count, err := statedb.New(db).CountActiveControlSessions(context.Background(), now.UnixNano())
	if err != nil || count != MaxActiveControlSessions {
		t.Fatalf("active sessions = %d, error = %v", count, err)
	}
}

func TestWrongReplacedRefreshSecretDoesNotRevokeSession(t *testing.T) {
	db, err := Open(context.Background(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	now := time.Unix(1_700_000_000, 0).UTC()
	session, _, refresh := newStoredControlSession(t, 1, now)
	if err := CreateControlSession(context.Background(), db, session, nil, time.Time{}); err != nil {
		t.Fatal(err)
	}
	refreshID, refreshHash, _ := credentials.ParseRefreshToken(refresh)
	access, accessID, accessHash, _ := credentials.NewAccessToken()
	_, newRefreshID, newRefreshHash, _ := credentials.NewRefreshToken()
	if _, err := RotateControlSession(context.Background(), db, refreshID, refreshHash, accessID, accessHash,
		now.Add(time.Hour), newRefreshID, newRefreshHash, now); err != nil {
		t.Fatal(err)
	}
	refreshHash[0] ^= 1
	_, err = RotateControlSession(context.Background(), db, refreshID, refreshHash, accessID, accessHash,
		now.Add(time.Hour), newRefreshID, newRefreshHash, now.Add(time.Minute))
	if !errors.Is(err, credentials.ErrInvalidRefreshToken) {
		t.Fatalf("wrong refresh secret error = %v", err)
	}
	accessID, accessHash, _ = credentials.ParseAccessToken(access)
	if _, err := AuthenticateControlSession(context.Background(), db, accessID, accessHash, now); err != nil {
		t.Fatalf("wrong refresh secret revoked session: %v", err)
	}
}

func TestInactiveControlSessionsPruneRefreshHistory(t *testing.T) {
	for _, test := range []struct {
		name   string
		revoke bool
	}{
		{name: "revoked", revoke: true},
		{name: "expired"},
	} {
		t.Run(test.name, func(t *testing.T) {
			db, err := Open(context.Background(), t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = db.Close() })
			now := time.Unix(1_700_000_000, 0).UTC()
			session, _, refresh := newStoredControlSession(t, 1, now)
			session.Grants = []string{"admin", "publish"}
			if err := CreateControlSession(context.Background(), db, session, nil, time.Time{}); err != nil {
				t.Fatal(err)
			}
			stored, err := statedb.New(db).GetControlSession(context.Background(), session.ID)
			if err != nil || stored.Grants != "publish,admin" {
				t.Fatalf("stored grants = %q, error = %v", stored.Grants, err)
			}
			refreshID, refreshHash, _ := credentials.ParseRefreshToken(refresh)
			_, accessID, accessHash, _ := credentials.NewAccessToken()
			currentRefresh, currentRefreshID, currentRefreshHash, _ := credentials.NewRefreshToken()
			if _, err := RotateControlSession(
				context.Background(), db, refreshID, refreshHash, accessID, accessHash,
				now.Add(2*time.Hour), currentRefreshID, currentRefreshHash, now.Add(time.Minute),
			); err != nil {
				t.Fatal(err)
			}
			if test.revoke {
				if err := RevokeControlSession(context.Background(), db, session.Identity.ID, session.ID, now.Add(2*time.Minute)); err != nil {
					t.Fatal(err)
				}
			} else {
				currentID, currentHash, _ := credentials.ParseRefreshToken(currentRefresh)
				_, nextAccessID, nextAccessHash, _ := credentials.NewAccessToken()
				_, nextRefreshID, nextRefreshHash, _ := credentials.NewRefreshToken()
				_, err := RotateControlSession(
					context.Background(), db, currentID, currentHash, nextAccessID, nextAccessHash,
					session.RefreshExpiresAt.Add(time.Hour), nextRefreshID, nextRefreshHash,
					session.RefreshExpiresAt,
				)
				if !errors.Is(err, credentials.ErrInvalidRefreshToken) {
					t.Fatalf("expired refresh error = %v", err)
				}
			}
			count, err := statedb.New(db).CountControlSessionRefreshHistory(context.Background(), session.ID)
			if err != nil || count != 0 {
				t.Fatalf("refresh history count = %d, error = %v", count, err)
			}
		})
	}
}

func newStoredControlSession(t *testing.T, number int, now time.Time) (ControlSession, credentials.AccessToken, credentials.RefreshToken) {
	t.Helper()
	access, accessID, accessHash, err := credentials.NewAccessToken()
	if err != nil {
		t.Fatal(err)
	}
	refresh, refreshID, refreshHash, err := credentials.NewRefreshToken()
	if err != nil {
		t.Fatal(err)
	}
	return ControlSession{
		ID:                   fmt.Sprintf("control_session_%032x", number),
		Identity:             Identity{ID: "identity", DisplayName: "Identity", Email: "identity@example.com"},
		AuthenticationMethod: AuthenticationMethodLoginToken, AuthenticationSourceRevision: 1,
		Grants: []string{"publish", "admin"}, CreatedAt: now, RefreshExpiresAt: now.Add(30 * 24 * time.Hour),
		AccessTokenID: accessID, AccessTokenHash: accessHash, AccessExpiresAt: now.Add(time.Hour),
		RefreshTokenID: refreshID, RefreshTokenHash: refreshHash,
	}, access, refresh
}

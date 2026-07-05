package tnldruntime

import (
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/clientstate"
)

func TestIntegrationBinaryControlSessionRefreshAndLogout(t *testing.T) {
	fixture := startIntegrationBinaryStandalone(t)
	const controlOrigin = "https://control.127.0.0.1.nip.io"

	state, err := clientstate.Open(t.Context(), fixture.stateDirectory)
	if err != nil {
		t.Fatal(err)
	}
	profile, err := state.Server(t.Context(), controlOrigin)
	if err != nil {
		t.Fatal(err)
	}
	before, found, err := profile.ControlSession(t.Context())
	if err != nil || !found {
		t.Fatalf("read initial control session: found %t, error %v", found, err)
	}
	before.AccessExpiresAt = time.Now().Add(-time.Minute)
	if err := profile.SaveControlSession(t.Context(), before); err != nil {
		t.Fatal(err)
	}
	if err := state.Close(); err != nil {
		t.Fatal(err)
	}

	runIntegrationBinaryCommand(t, fixture.repositoryRoot, fixture.environment, fixture.tnlPath, "team", "current")

	state, err = clientstate.Open(t.Context(), fixture.stateDirectory)
	if err != nil {
		t.Fatal(err)
	}
	profile, err = state.Server(t.Context(), controlOrigin)
	if err != nil {
		t.Fatal(err)
	}
	after, found, err := profile.ControlSession(t.Context())
	if err != nil || !found {
		t.Fatalf("read refreshed control session: found %t, error %v", found, err)
	}
	if after.SessionID != before.SessionID || after.AccessToken == before.AccessToken ||
		after.RefreshToken == before.RefreshToken || !after.AccessExpiresAt.After(time.Now()) ||
		!after.RefreshExpiresAt.Equal(before.RefreshExpiresAt) {
		t.Fatalf("refreshed control session = %#v; before %#v", after, before)
	}
	if err := state.Close(); err != nil {
		t.Fatal(err)
	}

	runIntegrationBinaryCommand(t, fixture.repositoryRoot, fixture.environment, fixture.tnlPath, "logout")
	state, err = clientstate.Open(t.Context(), fixture.stateDirectory)
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	profile, err = state.Server(t.Context(), controlOrigin)
	if err != nil {
		t.Fatal(err)
	}
	if _, found, err := profile.ControlSession(t.Context()); err != nil || found {
		t.Fatalf("control session after logout: found %t, error %v", found, err)
	}

	database := inspectStandaloneTestDatabase(t, fixture.databaseURL)
	var revoked bool
	if err := database.QueryRowContext(t.Context(), `
		SELECT revoked_at IS NOT NULL
		FROM control.control_sessions
		WHERE id = $1
	`, before.SessionID).Scan(&revoked); err != nil {
		t.Fatal(err)
	}
	if !revoked {
		t.Fatal("authority control session remained active after logout")
	}
}

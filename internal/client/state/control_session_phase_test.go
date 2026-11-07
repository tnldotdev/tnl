package state

import (
	"testing"
	"time"
)

func TestControlSessionRefreshPhases(t *testing.T) {
	now := time.Now()
	for _, test := range []struct {
		name    string
		session ControlSession
		want    ControlSessionRefreshPhase
	}{
		{"available", ControlSession{RefreshExpiresAt: now.Add(time.Minute)}, RefreshAvailable},
		{"expired", ControlSession{RefreshExpiresAt: now}, RefreshExpired},
		{"uncertain", ControlSession{RefreshPending: true, RefreshExpiresAt: now.Add(time.Minute)}, RefreshRecoveryRequired},
		{"uncertain after expiry", ControlSession{RefreshPending: true, RefreshExpiresAt: now}, RefreshRecoveryRequired},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := test.session.RefreshPhase(now); got != test.want {
				t.Fatal("refresh checkpoint did not retain the one-use token fence", got)
			}
		})
	}
}

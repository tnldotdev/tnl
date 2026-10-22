// Package controltest creates named OIDC session fixtures for tests whose
// boundary is authorization or publishing. device authentication has its own
// discovery, authorization-code, browser approval, and polling integration test.
package controltest

import (
	"context"
	"crypto/rand"
	"time"

	controlstate "github.com/tnldotdev/tnl/internal/control/state"
)

func Session(ctx context.Context, d *controlstate.Database, domain string, access, refresh time.Duration, now time.Time) (controlstate.ControlSession, error) {
	const issuer = "https://identity.fixture.test"
	const subject = "operator"
	if err := d.SeedHumanAuthentication(ctx, domain, controlstate.HumanAuthenticationSeeds{Issuer: issuer, Administrators: []string{subject}}, now); err != nil {
		return controlstate.ControlSession{}, err
	}
	var digest [32]byte
	if _, err := rand.Read(digest[:]); err != nil {
		return controlstate.ControlSession{}, err
	}
	return d.CreateOIDCControlSession(ctx, domain, controlstate.OIDCIdentity{Issuer: issuer, Subject: subject, DisplayName: subject, AssertionDigest: digest, AssertionExpiry: now.Add(time.Hour)}, access, refresh, now)
}

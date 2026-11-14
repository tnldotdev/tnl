package config

import (
	"errors"
	"testing"

	"github.com/tnldotdev/tnl/internal/control/turnstile"
)

func TestTurnstileRequiresBothKeysOnlyOnControlRoles(t *testing.T) {
	for _, keys := range [][2]string{{"site", ""}, {"", "secret"}} {
		c := Config{TurnstileSiteKey: keys[0], TurnstileSecretKey: keys[1]}
		if err := c.validateControl(); !errors.Is(err, turnstile.ErrConfiguration) {
			t.Fatal("partial Turnstile configuration did not fail startup", err)
		}
	}
	for _, role := range []Role{RoleControl, RoleStandalone, RoleIngress, RoleRelay} {
		base := validCertificateConfig(t, role)
		for _, configured := range []bool{false, true} {
			c := base
			if configured {
				c.TurnstileSiteKey, c.TurnstileSecretKey = "site", "secret"
			}
			err := c.Validate()
			if (err == nil) != (!configured || role.RunsControl()) {
				t.Fatal("Turnstile configuration escaped its control role", role, err)
			}
		}
	}
}

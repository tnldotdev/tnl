package tnldconfig

import (
	"errors"
	"net/url"
	"strings"

	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/naming"
)

func (c Config) OIDCEnabled() bool { return c.OIDCIssuer != "" }

func (c Config) EffectiveOIDCScopes() []string {
	if len(c.OIDCScopes) == 0 {
		return []string{"openid"}
	}
	return append([]string(nil), c.OIDCScopes...)
}

func (c Config) validateOIDC() (retErr error) {
	defer func() {
		if retErr != nil {
			retErr = failure.Wrap("validate OIDC settings", failure.ServerOIDCInvalid, retErr)
		}
	}()
	if c.OIDCIssuer == "" || c.OIDCClientID == "" {
		return errors.New("OIDC configuration is incomplete")
	}
	issuer, err := url.Parse(c.OIDCIssuer)
	if err != nil || issuer.Scheme != "https" || issuer.Host == "" || issuer.User != nil ||
		issuer.RawQuery != "" || issuer.Fragment != "" {
		return errors.New("OIDC issuer must be an HTTPS URL without credentials, query, or fragment")
	}
	if strings.TrimSpace(c.OIDCClientID) != c.OIDCClientID || c.OIDCClientID == "" || len(c.OIDCClientID) > 128 {
		return errors.New("OIDC client ID is invalid")
	}
	if len(c.OIDCClientSecret) > 4096 || len(c.OIDCScopes) > 32 {
		return errors.New("OIDC client settings exceed their bounds")
	}
	for _, subject := range append(append([]string(nil), c.InitialAdministrators...), c.DefaultTeamMembers...) {
		if strings.TrimSpace(subject) != subject || subject == "" || len(subject) > 256 || strings.ContainsAny(subject, "\r\n\x00") {
			return errors.New("OIDC seed subject is invalid")
		}
	}
	for team, subject := range c.InitialTeamOwners {
		if !naming.ValidAuthorityLabel(team) || subject == "" || strings.TrimSpace(subject) != subject || len(subject) > 256 || strings.ContainsAny(subject, "\r\n\x00") {
			return errors.New("OIDC team owner seed is invalid")
		}
	}
	if c.DefaultTeam != "" && !naming.ValidAuthorityLabel(c.DefaultTeam) || len(c.DefaultTeamMembers) > 0 && c.DefaultTeam == "" {
		return errors.New("OIDC default team is invalid")
	}
	seen := make(map[string]struct{})
	hasOpenID := false
	for _, scope := range c.EffectiveOIDCScopes() {
		if scope == "openid" {
			hasOpenID = true
		}
		if scope == "" || len(scope) > 128 || strings.TrimSpace(scope) != scope || strings.ContainsAny(scope, " \t\r\n") {
			return errors.New("OIDC scopes are invalid")
		}
		if _, exists := seen[scope]; exists {
			return errors.New("OIDC scopes contain a duplicate")
		}
		seen[scope] = struct{}{}
	}
	if !hasOpenID {
		return errors.New("OIDC scopes must include openid")
	}
	return nil
}

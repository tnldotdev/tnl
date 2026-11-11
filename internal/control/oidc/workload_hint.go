package oidc

import (
	"encoding/base64"
	"encoding/json"
	"strings"

	"github.com/tnldotdev/tnl/internal/config"
)

// WorkloadIdentityHint is untrusted lookup input, not a verified execution. it
// may narrow saved policies, but cannot supply a JWKS endpoint or authorize work.
type WorkloadIdentityHint struct{ Issuer, Subject, Audience string }

func UnverifiedWorkloadIdentity(raw string) (hint WorkloadIdentityHint, err error) {
	if len(raw) == 0 || len(raw) > 32768 {
		return hint, ErrUnauthenticated
	}
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return hint, ErrUnauthenticated
	}
	payload, err := base64.RawURLEncoding.Strict().DecodeString(parts[1])
	if err != nil {
		return hint, ErrUnauthenticated
	}
	var claims struct {
		Issuer   string          `json:"iss"`
		Subject  string          `json:"sub"`
		Audience json.RawMessage `json:"aud"`
	}
	if json.Unmarshal(payload, &claims) != nil || !config.WorkloadHTTPS(claims.Issuer) || !config.ExactWorkloadValue(claims.Subject) {
		return hint, ErrUnauthenticated
	}
	var audience string
	if json.Unmarshal(claims.Audience, &audience) != nil {
		var audiences []string
		if json.Unmarshal(claims.Audience, &audiences) != nil || len(audiences) != 1 {
			return hint, ErrUnauthenticated
		}
		audience = audiences[0]
	}
	if !config.ExactWorkloadValue(audience) {
		return hint, ErrUnauthenticated
	}
	return WorkloadIdentityHint{Issuer: claims.Issuer, Subject: claims.Subject, Audience: audience}, nil
}

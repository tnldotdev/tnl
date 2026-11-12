package machineproof

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/security/workloadproof"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
)

var ErrSourceChallenge = errors.New("identity source challenge is invalid or expired")

func ValidSourceKeyID(key string) bool {
	return len(key) > 0 && len(key) <= 128 && utf8.ValidString(key) && !strings.ContainsAny(key, "\x00\r\n")
}

func ValidSource(source authorityv1.IdentitySourceSelection) bool {
	if !opaqueid.Valid(source.MachineId, "mci_") {
		return false
	}
	return source.Kind == "oidc" && source.KeyId == "" || source.Kind == "registered_key" && ValidSourceKeyID(source.KeyId)
}

func sourceHex(value string, size int) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == size && value == strings.ToLower(value)
}

// validateSourceChallenge checks the defining shared wire and recomputes the
// existing proof scope/audience for either native owner. callers must also match
// the source and selection against their prepared intent before signing.
func ValidateSourceChallenge(c authorityv1.IdentitySourceChallenge, now time.Time) error {
	server, err := naming.CanonicalControlURL(c.Server)
	if err != nil || server != c.Server || c.Schema != 1 || !ValidSource(c.Source) || !sourceHex(c.Id, 16) || !sourceHex(c.BindingDigest, 32) || !c.ExpiresAt.After(now) || c.ExpiresAt.After(now.Add(time.Minute)) {
		return ErrSourceChallenge
	}
	public, err := base64.RawURLEncoding.Strict().DecodeString(c.NativePublicKey)
	if err != nil || len(public) != 32 {
		return ErrSourceChallenge
	}
	var scope, audience string
	switch c.Operation {
	case "publication_exchange", "publication_refresh":
		p := c.Publication
		if p == nil || c.Selection != nil || (p.Resource == "") == (p.Namespace == "") {
			return ErrSourceChallenge
		}
		if p.Resource != "" && !opaqueid.Valid(p.Resource, opaqueid.PublicURLPrefix) {
			return ErrSourceChallenge
		}
		if p.Namespace != "" {
			namespace, err := naming.CanonicalizeHostname(p.Namespace)
			if err != nil || namespace != p.Namespace {
				return ErrSourceChallenge
			}
		}
		operation, nonce := "exchange", c.Nonce
		audience = server + "/v1/machine-publication-sessions/exchange"
		if c.Operation == "publication_refresh" {
			if c.Nonce != "" || !opaqueid.Valid(c.SessionId, "mps_") {
				return ErrSourceChallenge
			}
			operation, nonce = "refresh", c.SessionId
			audience = server + "/v1/machine-publication-sessions/" + c.SessionId + "/refresh"
		} else if c.SessionId != "" || !workloadproof.ValidNonce(c.Nonce) {
			return ErrSourceChallenge
		}
		scope = Publication(p.Resource, p.Namespace, operation, c.NativePublicKey, nonce)
	case "visitor_prepare", "visitor_attach":
		s := c.Selection
		if s == nil || c.Publication != nil || s.Environment.Server != server || !naming.ValidProjectKey(s.Environment.ProjectKey) || !opaqueid.Valid(s.Environment.EnvironmentId, opaqueid.EnvironmentPrefix) || !opaqueid.Valid(s.PermissionId, "mwp_") || len(s.Services) < 1 || len(s.Services) > 32 {
			return ErrSourceChallenge
		}
		services := make(map[string]string, len(s.Services))
		for name, protocol := range s.Services {
			if !naming.ValidServiceName(name) || !protocol.Valid() {
				return ErrSourceChallenge
			}
			services[name] = string(protocol)
		}
		operation, nonce := "prepare", c.Nonce
		audience = server + "/v1/projects/" + s.Environment.ProjectKey + "/environments/" + s.Environment.EnvironmentId + "/visitors/prepare"
		if c.Operation == "visitor_attach" {
			if c.Nonce != "" || !opaqueid.Valid(c.SessionId, "wls_") {
				return ErrSourceChallenge
			}
			operation, nonce = "attach", c.SessionId
			audience = server + "/v1/environment-visitor-sessions/" + c.SessionId + "/assertions"
		} else if c.SessionId != "" || !workloadproof.ValidNonce(c.Nonce) {
			return ErrSourceChallenge
		}
		scope = EnvironmentVisitor(s.PermissionId, s.Environment.EnvironmentId, operation, c.NativePublicKey, nonce, services)
	default:
		return ErrSourceChallenge
	}
	if c.Scope != scope || c.Audience != audience {
		return ErrSourceChallenge
	}
	return nil
}

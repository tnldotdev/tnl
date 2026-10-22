package authorityapi

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"

	oidcauth "github.com/tnldotdev/tnl/internal/control/oidc"
	"github.com/tnldotdev/tnl/internal/httpjson"
	"github.com/tnldotdev/tnl/pkg/api/authorityv1"
)

// verifiedHumanRequest authenticates the website and configured issuer, then
// binds a fresh assertion to this operation. state consumes it transactionally.
func (h *handler) verifiedHumanRequest(w http.ResponseWriter, r *http.Request, body any, nonceFor func(string, string, []byte) string, bindQuery bool) (oidcauth.Identity, string, bool) {
	w.Header().Set("Cache-Control", "no-store")
	if !h.authenticateWebService(w, r) {
		return oidcauth.Identity{}, "", false
	}
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	raw, err := io.ReadAll(r.Body)
	if err != nil || body == nil && len(raw) != 0 {
		writeProblem(w, 400, authorityv1.InvalidRequest, "invalid human request")
		return oidcauth.Identity{}, "", false
	}
	if body != nil {
		if err = httpjson.Decode(json.NewDecoder(bytes.NewReader(raw)), body); err != nil {
			writeProblem(w, 400, authorityv1.InvalidRequest, "invalid human request")
			return oidcauth.Identity{}, "", false
		}
	}
	if h.config.OIDCVerifier == nil {
		writeAuthenticationUnavailable(w, "verify human request", nil)
		return oidcauth.Identity{}, "", false
	}
	i, err := h.config.OIDCVerifier.Verify(r.Context(), r.Header.Get("X-Tnl-Actor-Token"))
	if err != nil {
		companyError(w, "verify human request", err)
		return oidcauth.Identity{}, "", false
	}
	if i.Issuer != h.config.OIDCIssuer || i.ClientID != h.config.OIDCClientID || h.config.OIDCClientID == "" {
		writeBearerProblem(w)
		return oidcauth.Identity{}, "", false
	}
	target := r.URL.EscapedPath()
	if bindQuery && r.URL.RawQuery != "" {
		target += "?" + r.URL.RawQuery
	}
	nonce := nonceFor(r.Method, target, raw)
	if i.Nonce != nonce {
		writeBearerProblem(w)
		return oidcauth.Identity{}, "", false
	}
	return i, nonce, true
}

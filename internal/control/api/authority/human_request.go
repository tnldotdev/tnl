package authority

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"

	"github.com/tnldotdev/tnl/internal/control/oidc"
	"github.com/tnldotdev/tnl/internal/httpjson"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
)

// verifiedHumanRequest authenticates the website and configured issuer, then
// binds a fresh assertion to this operation. state consumes it transactionally.
func (h *handler) verifiedHumanRequest(w http.ResponseWriter, r *http.Request, body any, nonceFor func(string, string, []byte) string, bindQuery bool) (oidc.Identity, string, bool) {
	w.Header().Set("Cache-Control", "no-store")
	if !h.authenticateWebService(w, r) {
		return oidc.Identity{}, "", false
	}
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	raw, err := io.ReadAll(r.Body)
	if err != nil || body == nil && len(raw) != 0 {
		writeProblem(w, 400, authorityv1.InvalidRequest, "invalid human request")
		return oidc.Identity{}, "", false
	}
	if body != nil {
		if err = httpjson.Decode(json.NewDecoder(bytes.NewReader(raw)), body); err != nil {
			writeProblem(w, 400, authorityv1.InvalidRequest, "invalid human request")
			return oidc.Identity{}, "", false
		}
	}
	if h.config.OIDCVerifier == nil {
		writeAuthenticationUnavailable(w, "verify human request", nil)
		return oidc.Identity{}, "", false
	}
	i, err := h.config.OIDCVerifier.Verify(r.Context(), r.Header.Get("X-Tnl-Actor-Token"))
	if err != nil {
		companyError(w, "verify human request", err)
		return oidc.Identity{}, "", false
	}
	if i.Issuer != h.config.OIDCIssuer || i.ClientID != h.config.OIDCClientID || h.config.OIDCClientID == "" {
		writeBearerProblem(w)
		return oidc.Identity{}, "", false
	}
	target := r.URL.EscapedPath()
	if bindQuery && r.URL.RawQuery != "" {
		target += "?" + r.URL.RawQuery
	}
	nonce := nonceFor(r.Method, target, raw)
	if i.Nonce != nonce {
		writeBearerProblem(w)
		return oidc.Identity{}, "", false
	}
	return i, nonce, true
}

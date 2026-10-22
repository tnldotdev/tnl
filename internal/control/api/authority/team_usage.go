package authority

import (
	"context"
	"errors"
	"net/http"
	"time"

	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
)

type teamUsageStore interface {
	ResolveCompanyAccount(context.Context, string, string) (string, error)
	AuthorizeWebsiteTeamUsage(context.Context, string, string, time.Time) error
}

func (h *handler) AuthorizeWebsiteTeamUsage(w http.ResponseWriter, r *http.Request, team authorityv1.TeamID, _ authorityv1.AuthorizeWebsiteTeamUsageParams) {
	i, nonce, ok := h.verifiedHumanRequest(w, r, nil, controlstate.TeamUsageActorNonce, true)
	if !ok {
		return
	}
	s, ok := h.store.(teamUsageStore)
	if !ok {
		writeProblem(w, 503, authorityv1.Unavailable, "team usage authorization is unavailable")
		return
	}
	actor, err := s.ResolveCompanyAccount(r.Context(), i.Issuer, i.Subject)
	if err != nil {
		if errors.Is(err, controlstate.ErrControlIdentity) || errors.Is(err, controlstate.ErrAuthorityAccess) {
			writeBearerProblem(w)
		} else {
			companyError(w, "resolve team usage actor", err)
		}
		return
	}
	ctx := controlstate.WithServiceActorProof(r.Context(), companyOIDCIdentity(i), nonce)
	if err = s.AuthorizeWebsiteTeamUsage(ctx, team, actor, time.Now()); err != nil {
		if errors.Is(err, controlstate.ErrServiceSourceSignInRequired) {
			writeProblem(w, 403, authorityv1.SourceSignInRequired, "sign in through the current company source")
		} else {
			companyError(w, "authorize team usage", err)
		}
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

package workloadsetup

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/tnldotdev/tnl/internal/config"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

var ErrGoogleAuthentication = errors.New("Google workload approval needs gcloud authentication with permission to describe the selected service account")

func (r resolver) google(ctx context.Context, o Options, g *config.WorkloadGoogle, previous controlv1.ProjectWorkload) (controlv1.WorkloadTrust, *controlv1.ProjectWorkloadGoogle, error) {
	t := controlv1.WorkloadTrust{Provider: controlv1.WorkloadGoogle, Issuer: config.GoogleWorkloadIssuer, JwksUrl: config.GoogleWorkloadJWKS, Audience: o.Server, Claims: map[string]string{}}
	if g.Audience != "" {
		t.Audience = g.Audience
	}
	selected := &controlv1.ProjectWorkloadGoogle{ServiceAccount: g.ServiceAccount}
	old := previous.Trust
	if previous.Provider == t.Provider && previous.Google != nil && config.ValidWorkloadNumericID(old.Claims["sub"]) && (g.ServiceAccount == previous.Google.ServiceAccount || g.ServiceAccount == old.Claims["sub"]) {
		t.Claims["sub"] = old.Claims["sub"]
		return t, selected, nil
	}
	id := g.ServiceAccount
	if !config.ValidWorkloadNumericID(id) {
		output, err := r.run(ctx, o.Directory, "gcloud", "iam", "service-accounts", "describe", g.ServiceAccount, "--format=json", "--quiet")
		if err != nil {
			return t, nil, errors.Join(ErrGoogleAuthentication, err)
		}
		var account struct {
			ID       string `json:"uniqueId"`
			Email    string `json:"email"`
			Disabled bool   `json:"disabled"`
		}
		if json.Unmarshal(output, &account) != nil || account.Email != g.ServiceAccount || account.Disabled || !config.ValidWorkloadNumericID(account.ID) {
			return t, nil, ErrBinding
		}
		id = account.ID
	}
	if previous.Provider == t.Provider && old.Claims["sub"] != id {
		return t, nil, ErrRebinding
	}
	t.Claims["sub"] = id
	return t, selected, nil
}

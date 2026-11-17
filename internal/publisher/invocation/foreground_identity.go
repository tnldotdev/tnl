package invocation

import (
	"context"
	"encoding/json"
	"slices"
	"strings"

	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/policy/applicationlimits"
	publisheridentity "github.com/tnldotdev/tnl/internal/publisher/identity"
	targetplan "github.com/tnldotdev/tnl/internal/publisher/target"
	"github.com/tnldotdev/tnl/internal/security/targettrust"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

// foreground publication changes only selected policy fields. its listener is a
// runtime target, not a replacement for the saved service's configured target.
func prepareForegroundService(ctx context.Context, services publisherServices, flags PublicOptions, policy resolvedVisitorAccess, plan targetplan.TargetPlan) (*publisheridentity.Native, controlv1.Service, targetplan.TargetPlan, error) {
	declaration, err := foregroundServiceDeclaration(flags, policy, plan, nil)
	if err != nil {
		return nil, controlv1.Service{}, plan, err
	}
	saved, err := reserveConfiguredService(ctx, services, declaration, func(current controlv1.Service, configured *controlv1.ProjectServiceConfiguration) (*controlv1.ProjectServiceConfiguration, error) {
		if !policy.explicit && flags.Limits == (applicationlimits.Limits{}) && flags.RequirePostQuantum == nil && !foregroundTrustSelected(flags) {
			return nil, nil
		}
		captured := plan
		if !foregroundTrustSelected(flags) {
			var err error
			captured.Trust, err = publisheridentity.ServiceTrust(current)
			if err != nil {
				return nil, err
			}
		}
		if configured == nil {
			targetTLS, err := foregroundTargetTLS(captured.Trust)
			if err != nil {
				return nil, err
			}
			configured = &controlv1.ProjectServiceConfiguration{Target: "app", TargetTls: targetTLS,
				RequirePostQuantum: new(current.RequirePostQuantum),
				Http:               &controlv1.ProjectServiceHTTP{Limits: current.HttpLimits}}
		}
		desired, err := foregroundServiceDeclaration(flags, policy, captured, configured)
		return &desired, err
	})
	if err != nil {
		return nil, saved, plan, err
	}
	if !foregroundTrustSelected(flags) {
		plan.Trust, err = publisheridentity.ServiceTrust(saved)
		if err != nil {
			return nil, saved, plan, err
		}
		if plan.Trust != nil && !strings.Contains(flags.Target, "://") {
			plan.Target = "https://" + strings.TrimPrefix(strings.TrimPrefix(plan.Target, "http://"), "https://")
		}
	}
	if err := plan.Normalize(); err != nil {
		return nil, saved, plan, err
	}
	if err := publisheridentity.MatchServiceDeclaration(saved, "http", plan.Trust); err != nil {
		return nil, saved, plan, failure.Wrap("match service declaration", failure.ServerConflict, err)
	}
	native, _, err := publisheridentity.EnsureServiceOwner(ctx, services.state, services.authenticated.Control, services.authenticated.Authority, saved)
	return native, saved, plan, err
}

func foregroundTrustSelected(flags PublicOptions) bool {
	return flags.Service != "" || flags.TargetCAFile != "" || flags.TargetTLSName != ""
}

func foregroundTargetTLS(trust *targettrust.Snapshot) (*controlv1.ProjectTargetTLS, error) {
	if trust == nil {
		return nil, nil
	}
	captured, err := trust.Declaration()
	if err != nil {
		return nil, err
	}
	tls := &controlv1.ProjectTargetTLS{Hostname: captured.Hostname, Digest: captured.Digest, HostnameFromTarget: captured.HostnameFromTarget}
	if len(captured.CAPEM) != 0 {
		tls.CaPem = new(string(captured.CAPEM))
	}
	return tls, nil
}

func foregroundServiceDeclaration(flags PublicOptions, policy resolvedVisitorAccess, plan targetplan.TargetPlan, current *controlv1.ProjectServiceConfiguration) (controlv1.ProjectServiceConfiguration, error) {
	declaration := controlv1.ProjectServiceConfiguration{Target: "app", Protocol: new(controlv1.ServiceProtocolHTTP), Public: new(true), Ephemeral: new(false)}
	if current != nil {
		encoded, err := json.Marshal(current)
		if err != nil {
			return declaration, err
		}
		declaration = controlv1.ProjectServiceConfiguration{}
		if err := json.Unmarshal(encoded, &declaration); err != nil {
			return declaration, err
		}
	}
	if current == nil || foregroundTrustSelected(flags) {
		var err error
		declaration.TargetTls, err = foregroundTargetTLS(plan.Trust)
		if err != nil {
			return declaration, err
		}
	}
	if flags.RequirePostQuantum != nil {
		declaration.RequirePostQuantum = new(*flags.RequirePostQuantum)
	}
	if err := flags.Limits.Validate(); err != nil {
		return declaration, err
	}
	limits := flags.Limits
	if policy.explicit || limits.Requests != 0 || limits.Concurrency != 0 || limits.RateRequests != 0 || limits.RateBurst != 0 {
		if declaration.Http == nil {
			declaration.Http = &controlv1.ProjectServiceHTTP{}
		}
		if policy.explicit {
			access := &controlv1.ProjectHTTPAccess{Mode: new(policy.access)}
			if len(policy.prefixes) != 0 {
				prefixes := slices.Clone(policy.prefixes)
				access.Ip = &prefixes
			}
			declaration.Http.Access = access
		}
		if limits.Requests != 0 || limits.Concurrency != 0 || limits.RateRequests != 0 || limits.RateBurst != 0 {
			if declaration.Http.Limits == nil {
				declaration.Http.Limits = &controlv1.ProjectHTTPApplicationLimits{}
			}
			selected := declaration.Http.Limits
			if limits.Requests != 0 {
				selected.Total = new(limits.Requests)
			}
			if limits.Concurrency != 0 {
				selected.Concurrency = new(limits.Concurrency)
			}
			if limits.RateRequests != 0 {
				rate := &controlv1.ProjectApplicationRate{Count: limits.RateRequests, Per: limits.RatePer.String()}
				if selected.Rate != nil {
					rate.Burst = selected.Rate.Burst
				}
				selected.Rate = rate
			}
			if limits.RateBurst != 0 && selected.Rate != nil {
				selected.Rate.Burst = new(limits.RateBurst)
			}
		}
	}
	return declaration, nil
}

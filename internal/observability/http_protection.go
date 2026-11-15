package observability

import (
	"context"

	policy "github.com/tnldotdev/tnl/internal/policy/httpprotection"
	"go.opentelemetry.io/otel/trace"
)

var (
	wafMode    = stringKey{keyName{"tnl.waf_mode"}}
	wafRuleset = stringKey{keyName{"tnl.waf_ruleset"}}
	wafRuleID  = intKey{keyName{"tnl.waf_rule_id"}}
)

// HTTPProtection adds only managed identifiers to the existing request trace.
// request data and Coraza's expanded match messages never enter this boundary.
func HTTPProtection(ctx context.Context, mode policy.Mode, status int, rules []int) {
	if mode != policy.Block && mode != policy.Detect && mode != policy.Off {
		return
	}
	span := trace.SpanFromContext(ctx)
	span.SetAttributes(wafMode.String(string(mode)), wafRuleset.String(policy.Ruleset))
	for _, id := range rules[:min(len(rules), 32)] {
		if id < 900000 || id > 999999 {
			continue
		}
		span.AddEvent("http.protection.match", trace.WithAttributes(wafRuleID.Int(id)))
	}
	if status != 0 {
		span.AddEvent("http.protection.rejected", trace.WithAttributes(HTTPStatus.Int(status)))
	}
}

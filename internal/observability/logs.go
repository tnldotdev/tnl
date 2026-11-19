//go:build !js || !wasm

package observability

import (
	"context"
	"strings"
	"time"

	"github.com/tnldotdev/tnl/internal/failure"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/log"
)

// OperationalFailure exports authored failure copy with scoped identity and trace
// correlation. it never accepts a free-form log body or exports cause.Error().
func OperationalFailure(ctx context.Context, operation failure.Operation, reason failure.Reason, requestID string, cause error) {
	m := FromContext(ctx)
	if m == nil || m.loggerProvider == nil || cause == nil {
		return
	}
	if specific, ok := failure.ReasonOf(cause); ok {
		reason = specific
	}
	def, ok := failure.DefinitionFor(reason)
	if !ok {
		reason = failure.Unexpected
		def, _ = failure.DefinitionFor(reason)
	}
	var record log.Record
	record.SetTimestamp(time.Now())
	record.SetObservedTimestamp(time.Now())
	record.SetSeverity(log.SeverityError)
	record.SetSeverityText("error")
	record.SetBody(attribute.StringValue(def.Message))
	record.AddAttributes(Operation.Value(operationID(operation)), Event.Value(EventOperationalFailure), OutcomeKey.Value(ErrorOutcome(cause)), ErrorType.String(string(reason)))
	if requestID != "" && len(requestID) <= 128 {
		record.AddAttributes(RequestID.String(requestID))
	}
	for _, a := range identityAttributes(ctx) {
		record.AddAttributes(a)
	}
	m.loggerProvider.Logger(scope).Emit(ctx, record)
}

// failure adapters still accept failure.Operation. narrow against the compiled
// log vocabulary before exporting; a syntactically plausible input is not proof
// that its words were authored. unknown operations use the existing fallback.
func operationID(operation failure.Operation) operationName {
	if name, ok := operationalNames[operation]; ok {
		return name
	}
	return "operational_failure"
}

var operationalNames = func() map[failure.Operation]operationName {
	names := make(map[failure.Operation]operationName)
	for _, words := range []failure.Operation{
		"advance DNS work", "advance certificate work", "authenticate publish run",
		"authenticate device browser", "read admin server status", "list admin relays",
		"drain admin relay", "list maintenance controls", "set maintenance control",
		"read identity context", "list teams", "get team", "list team domains",
		"clean up routing history", "clean up guest private state", "expire publish runs",
		"renew relay lease", "serve relay publisher", "forward through relay",
		"serve relay QUIC session", "clean up service audit", "renew ingress lease",
		"report ingress recovery", "close ingress relay session",
		"read ingress public URL", "serve ingress connection", "refresh service port capacity",
		"serve standalone relay publisher", "clean up ephemeral public URLs",
		"read feedback thread", "encode feedback thread", "list feedback threads",
		"encode feedback list", "append feedback event", "encode feedback event",
		"list feedback thread events", "encode feedback events", "watch feedback events",
		"read watched feedback", "encode watched feedback", "replace visitor access",
		"read share public URL", "create share", "check guest IP", "create guest share",
		"list shares", "list team shares", "revoke share", "read share", "enable share access",
		"read publisher shares", "read preview team access", "redeem share",
		"select publish-run traffic limits", "verify feedback reviewer", "encode feedback report",
		"list page feedback", "encode page feedback", "encode reviewer feedback",
		"encode reviewer feedback thread", "list reviewer feedback events",
		"encode reviewer feedback events", "read reviewer feedback", "service audit",
		"read publisher editor", "create preview", "read preview public URL",
		"add preview public URL", "read preview", "create certificate issuance",
		"get certificate issuance", "get project public metadata", "read browser preview",
		"read browser public URL", "create browser nonce", "create browser binding",
		"select company browser sign-in", "start browser sign-in", "discover browser identity provider",
		"consume browser sign-in", "verify browser identity", "save browser sign-in",
		"authorize browser identity", "read signed-in browser public URL", "redeem browser handoff",
		"check browser access", "create demo feedback", "read team preview public URL",
		"set preview team access", "list public URLs", "create public URL", "read public URL for update",
		"update public URL", "get public URL", "read public URL for deletion", "delete public URL",
		"read public URL for publish run", "read created publish run", "heartbeat publish run",
		"mark public URL certificate installed", "mark publish run ready", "close publish run",
		"resolve website identity", "accept website invitation", "preview website invitation",
		"create team", "list team memberships", "set membership role", "remove membership",
		"list team invitations", "create team invitation", "revoke team invitation", "accept invitation",
		"claim team domain", "set team default domain", "release team domain", "authorize workload session",
		"read feedback author policy", "set feedback author policy",
		"renew private publisher", "renew publisher lease", "renew publisher",
	} {
		name := strings.ToLower(strings.Join(strings.Fields(string(words)), "_"))
		names[words] = operationName(name)
	}
	return names
}()

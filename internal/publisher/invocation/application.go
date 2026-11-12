package invocation

import (
	"context"
	"encoding/json"

	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/publisher"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

// ApplicationAuthority is supplied by the identity-source owner. it checks the
// current exact resource or namespace grant before registration is accepted.
// selection must reject group-owned resources and reserved group namespaces.
// allocation retries use InvocationID, including recovery after an uncertain
// allocation reply. control's ephemeral expiry owns crash cleanup before a run.
type ApplicationAuthority interface {
	ResolveApplicationPublication(context.Context, ApplicationSelection) (ApplicationGrant, error)
}

type ApplicationSelection struct {
	ServerURL, InvocationID, Target string
	ResourceID, Namespace           string
	Publication                     *clientstate.ApplicationPublication
	// auth is valid only during ResolveApplicationPublication. the identity
	// source parses any retained refresh state before returning.
	Auth               json.RawMessage
	AccessMode         *controlv1.VisitorAccessMode
	RequirePostQuantum *bool
	IP                 *[]string
	Limits             *controlv1.PublisherApplicationLimits
}

// ApplicationControl supplies the grant-scoped capabilities needed by the
// application publisher; no capability is recovered through a runtime assertion.
type ApplicationControl interface {
	publisher.PublicURLControlClient
	publisher.PublisherIdentityClient
	publisher.PublisherAuditClient
	publisher.VisitorPolicyClient
	publisher.BrowserControlClient
	publisher.ShareAccessClient
}

// ApplicationGrant carries validated authority facts explicitly. Control owns
// current checks and credential refresh; native publication owns drain/join.
// Cleanup is required for temporary resources and must be safe to retry. it must
// never delete a saved resource. no credential enters the local app journal.
// if selection fails after allocating, return its cleanup obligation with the
// error so native setup can release it without starting a publication worker.
type ApplicationGrant struct {
	Control             ApplicationControl
	PublisherIdentityID string
	PublicURL           controlv1.PublicURL
	// refresh accepts a new proof for the same identity and exact grant. the
	// adapter must reject attempts to transfer an accepted publication to another
	// identity or grant. source bytes are valid only for the duration of the call.
	RefreshAuth func(context.Context, json.RawMessage) error
	Cleanup     func(context.Context) error
	// release retires private session state without deleting a saved URL.
	Release      func(context.Context) error
	CheckServing func() error
	Run          func(context.Context, func(context.Context) error) error
}

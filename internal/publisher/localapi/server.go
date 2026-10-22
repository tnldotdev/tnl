// package localpublisher owns the private HTTP boundary for one native project
// owner. capabilities restrict operations before project or publisher work runs.
package localapi

import (
	"context"
	"errors"
	"net/http"
	"path/filepath"
	"slices"
	"strings"

	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/observability"
	clientruntime "github.com/tnldotdev/tnl/internal/publisher/app"
	publisheridentity "github.com/tnldotdev/tnl/internal/publisher/identity"
	"github.com/tnldotdev/tnl/internal/publisher/identity/credentialfile"
	publisherprotocol "github.com/tnldotdev/tnl/internal/publisher/localapi/protocol"
)

type Server struct {
	Capabilities        *publisherprotocol.Capabilities
	Manager             *clientruntime.Manager
	Database            *clientstate.Database
	Project             string
	Prepare             func(context.Context, publisherprotocol.Prepare) (publisherprotocol.Assignment, error)
	Register            func(publisherprotocol.Registration) error
	RegisterContext     func(context.Context, publisherprotocol.Registration) error
	Acquire             func(context.Context, publisherprotocol.Lease) (publisherprotocol.Registration, error)
	Invocation          func(context.Context, publisherprotocol.Invocation) (publisherprotocol.Registration, error)
	Check               func(context.Context, []string) (clientruntime.Snapshot, error)
	AppService          func(string) bool
	ConfigurationDigest func() (string, error)
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/health", func(w http.ResponseWriter, r *http.Request) {
		if digest := r.URL.Query().Get("configuration_digest"); digest != "" {
			if publisherprotocol.Grant(r).Scope != "owner" || s.ConfigurationDigest == nil {
				Problem(w, publisherprotocol.ErrForbidden)
				return
			}
			current, err := s.ConfigurationDigest()
			if err != nil {
				Problem(w, err)
				return
			}
			if digest != current {
				Problem(w, failure.Wrap("reuse project owner", failure.AppConfigurationConflict, clientruntime.ErrOwnerConflict))
				return
			}
		}
		w.WriteHeader(204)
	})
	mux.HandleFunc("POST /v1/capabilities", func(w http.ResponseWriter, r *http.Request) {
		if publisherprotocol.Grant(r).Scope != "owner" {
			Problem(w, publisherprotocol.ErrForbidden)
			return
		}
		var request publisherprotocol.CapabilityRequest
		if err := publisherprotocol.Decode(w, r, &request); err != nil {
			Problem(w, err)
			return
		}
		if request.Scope == "app" && (request.Service == nil || s.AppService == nil || !s.AppService(*request.Service)) {
			Problem(w, publisherprotocol.ErrForbidden)
			return
		}
		endpoint, err := s.Capabilities.Issue(request)
		if err != nil {
			Problem(w, err)
			return
		}
		publisherprotocol.Write(w, 200, endpoint)
	})
	mux.HandleFunc("POST /v1/prepare", func(w http.ResponseWriter, r *http.Request) {
		grant := publisherprotocol.Grant(r)
		if grant.Scope != "app" || s.Prepare == nil {
			Problem(w, publisherprotocol.ErrForbidden)
			return
		}
		var request publisherprotocol.Prepare
		if err := publisherprotocol.Decode(w, r, &request); err != nil {
			Problem(w, err)
			return
		}
		if request.Service != "" && request.Service != *grant.Service {
			Problem(w, publisherprotocol.ErrForbidden)
			return
		}
		request.Service = *grant.Service
		assignment, err := s.Prepare(r.Context(), request)
		if err != nil {
			Problem(w, err)
			return
		}
		publisherprotocol.Write(w, 200, assignment)
	})
	mux.HandleFunc("POST /v1/leases", func(w http.ResponseWriter, r *http.Request) {
		if publisherprotocol.Grant(r).Scope != "owner" || s.Acquire == nil {
			Problem(w, publisherprotocol.ErrForbidden)
			return
		}
		var request publisherprotocol.Lease
		if err := publisherprotocol.Decode(w, r, &request); err != nil {
			Problem(w, err)
			return
		}
		if !publisherprotocol.ValidOwner(request.Owner) || request.Pid <= 0 {
			Problem(w, errors.New("invalid lease"))
			return
		}
		registration, err := s.Acquire(r.Context(), request)
		if err != nil {
			Problem(w, err)
			return
		}
		publisherprotocol.Write(w, 200, registration)
	})
	mux.HandleFunc("POST /v1/ad-hoc/register", func(w http.ResponseWriter, r *http.Request) {
		grant := publisherprotocol.Grant(r)
		if grant.Scope != "invocation" || s.Invocation == nil {
			Problem(w, publisherprotocol.ErrForbidden)
			return
		}
		var request publisherprotocol.Invocation
		if err := publisherprotocol.Decode(w, r, &request); err != nil {
			Problem(w, err)
			return
		}
		if request.Version != 1 || request.InvocationId != *grant.InvocationId || !publisherprotocol.ValidOwner(request.Owner) || request.Pid <= 0 || request.PublisherCredentialFile != "" && request.PublisherIdentityId != "" {
			Problem(w, publisherprotocol.ErrForbidden)
			return
		}
		if request.PublisherCredentialFile != "" && (!filepath.IsAbs(request.PublisherCredentialFile) || len(request.PublisherCredentialFile) > 4096 || strings.ContainsRune(request.PublisherCredentialFile, 0)) {
			Problem(w, credentialfile.ErrInvalid)
			return
		}
		registration, err := s.Invocation(r.Context(), request)
		if err != nil {
			Problem(w, err)
			return
		}
		if err := publisherprotocol.Write(w, 200, registration); err != nil || r.Context().Err() != nil {
			// a failed acknowledgment cannot leave an unrenewable invocation
			// running. unregister joins its worker and allocation cleanup.
			_ = s.Manager.UnregisterTarget(registration.RegistrationID, registration.Owner, registration.Target)
		}
	})
	for _, operation := range []string{"register", "renew", "unregister"} {
		mux.HandleFunc("POST /v1/"+operation, func(w http.ResponseWriter, r *http.Request) {
			var request publisherprotocol.Registration
			if err := publisherprotocol.Decode(w, r, &request); err != nil {
				Problem(w, err)
				return
			}
			if request.Version != 1 || !publisherprotocol.ValidOwner(request.Owner) {
				Problem(w, publisherprotocol.ErrForbidden)
				return
			}
			service, found := s.Manager.ServiceForRegistration(request.RegistrationID)
			grant := publisherprotocol.Grant(r)
			if !found || grant.Scope == "app" && service.Name != *grant.Service || grant.Scope == "invocation" && service.Name != *grant.InvocationId {
				Problem(w, clientruntime.ErrRegistrationStale)
				return
			}
			var err error
			switch operation {
			case "register":
				if grant.Scope != "app" {
					Problem(w, publisherprotocol.ErrForbidden)
					return
				}
				if s.RegisterContext != nil {
					err = s.RegisterContext(r.Context(), request)
				} else if s.Register != nil {
					err = s.Register(request)
				} else {
					err = s.Manager.RegisterContext(r.Context(), request.RegistrationID, request.Owner, request.Target, service.Framework)
				}
			case "renew":
				err = s.Manager.RenewTarget(request.RegistrationID, request.Owner, request.Target)
			case "unregister":
				err = s.Manager.UnregisterTarget(request.RegistrationID, request.Owner, request.Target)
			}
			if err != nil {
				Problem(w, err)
				return
			}
			w.WriteHeader(204)
		})
	}
	mux.HandleFunc("GET /v1/status", func(w http.ResponseWriter, r *http.Request) {
		snapshot := s.Manager.Snapshot()
		grant := publisherprotocol.Grant(r)
		if grant.Scope != "owner" {
			name := ""
			if grant.Service != nil {
				name = *grant.Service
			} else if grant.InvocationId != nil {
				name = *grant.InvocationId
			}
			snapshot.Services = slices.DeleteFunc(snapshot.Services, func(service clientruntime.Service) bool { return service.Name != name })
			snapshot.Publications = slices.DeleteFunc(slices.Clone(snapshot.Publications), func(publication clientstate.TunnelInfo) bool {
				if grant.Scope == "invocation" {
					return !slices.ContainsFunc(snapshot.Services, func(service clientruntime.Service) bool { return service.TunnelID == publication.ID })
				}
				return publication.Service != name
			})
			snapshot.Events = nil
		}
		publisherprotocol.Write(w, 200, snapshot)
	})
	mux.HandleFunc("GET /v1/events", func(w http.ResponseWriter, r *http.Request) {
		if publisherprotocol.Grant(r).Scope != "owner" {
			Problem(w, publisherprotocol.ErrForbidden)
			return
		}
		cursor := r.URL.Query().Get("after")
		if cursor == "" || len(cursor) > 128 {
			Problem(w, clientruntime.ErrCursorExpired)
			return
		}
		events, err := clientruntime.EventsAfterFrom(r.Context(), s.Database, s.Project, cursor)
		if err != nil {
			Problem(w, err)
			return
		}
		publisherprotocol.Write(w, 200, events)
	})
	mux.HandleFunc("POST /v1/check", func(w http.ResponseWriter, r *http.Request) {
		if publisherprotocol.Grant(r).Scope != "owner" || s.Check == nil {
			Problem(w, publisherprotocol.ErrForbidden)
			return
		}
		var request publisherprotocol.Check
		if err := publisherprotocol.Decode(w, r, &request); err != nil {
			Problem(w, err)
			return
		}
		var names []string
		if request.Services != nil {
			names = *request.Services
		}
		if len(names) > 32 {
			Problem(w, errors.New("too many services"))
			return
		}
		snapshot, err := s.Check(r.Context(), names)
		if err != nil {
			Problem(w, err)
			return
		}
		publisherprotocol.Write(w, 200, snapshot)
	})
	return observability.LocalRequests(s.Capabilities.Handler(mux))
}

func Problem(w http.ResponseWriter, err error) {
	status, code, message := 400, "runtime.request_invalid", "local publisher request is invalid"
	reason, _ := failure.ReasonOf(err)
	switch {
	case reason == failure.AppConfigurationConflict:
		definition, _ := failure.DefinitionFor(failure.AppConfigurationConflict)
		status, code, message = 409, string(failure.AppConfigurationConflict), definition.Message
	case errors.Is(err, publisherprotocol.ErrUnauthorized):
		status, code, message = 401, "runtime.unauthorized", "read the current private endpoint descriptor"
	case errors.Is(err, publisherprotocol.ErrForbidden):
		status, code, message = 403, "runtime.forbidden", "use a capability for this service and operation"
	case errors.Is(err, clientruntime.ErrOwnerConflict):
		status, code, message = 409, "runtime.owner_conflict", "another live app owns this service; stop it before starting another"
	case errors.Is(err, clientruntime.ErrRegistrationStale):
		status, code, message = 409, "runtime.registration_stale", "prepare and register the listener again"
	case errors.Is(err, clientruntime.ErrCursorExpired):
		status, code, message = 410, "runtime.cursor_expired", "read a new status snapshot before resuming events"
	case errors.Is(err, clientcontrol.ErrUnauthenticated):
		status, code, message = 401, "runtime.authentication_required", "run tnl auth login, then start the app again"
	case errors.Is(err, publisheridentity.ErrSetupRequired):
		status, code, message = 409, "runtime.publisher_setup_required", "run tnl publisher setup --namespace, then start the app again"
	case errors.Is(err, credentialfile.ErrInvalid):
		status, code, message = 400, "runtime.publisher_credential_file_invalid", "check the publisher file, its permissions, and its control URL"
	default:
		if reason, ok := failure.ReasonOf(err); ok {
			definition, _ := failure.DefinitionFor(reason)
			code, message = string(reason), definition.Message
		}
	}
	publisherprotocol.Write(w, status, publisherprotocol.Problem{Code: code, Message: message})
}

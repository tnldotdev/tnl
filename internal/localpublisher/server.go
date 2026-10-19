// package localpublisher owns the private HTTP boundary for one native project
// owner. capabilities restrict operations before project or publisher work runs.
package localpublisher

import (
	"context"
	"errors"
	"net/http"
	"path/filepath"
	"slices"
	"strings"

	"github.com/tnldotdev/tnl/internal/clientruntime"
	"github.com/tnldotdev/tnl/internal/clientstate"
	"github.com/tnldotdev/tnl/internal/controlclient"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/privateprotocol"
	"github.com/tnldotdev/tnl/internal/publisheridentity/credentialfile"
	nativeauth "github.com/tnldotdev/tnl/internal/publisheridentity/native"
)

type Server struct {
	Capabilities *privateprotocol.Capabilities
	Manager      *clientruntime.Manager
	Database     *clientstate.Database
	Project      string
	Prepare      func(context.Context, privateprotocol.Prepare) (privateprotocol.Assignment, error)
	Register     func(privateprotocol.Registration) error
	Acquire      func(context.Context, privateprotocol.Lease) (privateprotocol.Registration, error)
	Invocation   func(context.Context, privateprotocol.Invocation) (privateprotocol.Registration, error)
	Check        func(context.Context, []string) (clientruntime.Snapshot, error)
	AppService   func(string) bool
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/health", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) })
	mux.HandleFunc("POST /v1/capabilities", func(w http.ResponseWriter, r *http.Request) {
		if privateprotocol.Grant(r).Scope != "owner" {
			Problem(w, privateprotocol.ErrForbidden)
			return
		}
		var request privateprotocol.CapabilityRequest
		if err := privateprotocol.Decode(w, r, &request); err != nil {
			Problem(w, err)
			return
		}
		if request.Scope == "app" && (request.Service == nil || s.AppService == nil || !s.AppService(*request.Service)) {
			Problem(w, privateprotocol.ErrForbidden)
			return
		}
		endpoint, err := s.Capabilities.Issue(request)
		if err != nil {
			Problem(w, err)
			return
		}
		privateprotocol.Write(w, 200, endpoint)
	})
	mux.HandleFunc("POST /v1/prepare", func(w http.ResponseWriter, r *http.Request) {
		grant := privateprotocol.Grant(r)
		if grant.Scope != "app" || s.Prepare == nil {
			Problem(w, privateprotocol.ErrForbidden)
			return
		}
		var request privateprotocol.Prepare
		if err := privateprotocol.Decode(w, r, &request); err != nil {
			Problem(w, err)
			return
		}
		if request.Service != "" && request.Service != *grant.Service {
			Problem(w, privateprotocol.ErrForbidden)
			return
		}
		request.Service = *grant.Service
		assignment, err := s.Prepare(r.Context(), request)
		if err != nil {
			Problem(w, err)
			return
		}
		privateprotocol.Write(w, 200, assignment)
	})
	mux.HandleFunc("POST /v1/leases", func(w http.ResponseWriter, r *http.Request) {
		if privateprotocol.Grant(r).Scope != "owner" || s.Acquire == nil {
			Problem(w, privateprotocol.ErrForbidden)
			return
		}
		var request privateprotocol.Lease
		if err := privateprotocol.Decode(w, r, &request); err != nil {
			Problem(w, err)
			return
		}
		if !privateprotocol.ValidOwner(request.Owner) || request.Pid <= 0 {
			Problem(w, errors.New("invalid lease"))
			return
		}
		registration, err := s.Acquire(r.Context(), request)
		if err != nil {
			Problem(w, err)
			return
		}
		privateprotocol.Write(w, 200, registration)
	})
	mux.HandleFunc("POST /v1/ad-hoc/register", func(w http.ResponseWriter, r *http.Request) {
		grant := privateprotocol.Grant(r)
		if grant.Scope != "invocation" || s.Invocation == nil {
			Problem(w, privateprotocol.ErrForbidden)
			return
		}
		var request privateprotocol.Invocation
		if err := privateprotocol.Decode(w, r, &request); err != nil {
			Problem(w, err)
			return
		}
		if request.Version != 1 || request.InvocationId != *grant.InvocationId || !privateprotocol.ValidOwner(request.Owner) || request.Pid <= 0 || request.PublisherFile != "" && request.PublisherId != "" {
			Problem(w, privateprotocol.ErrForbidden)
			return
		}
		if request.PublisherFile != "" && (!filepath.IsAbs(request.PublisherFile) || len(request.PublisherFile) > 4096 || strings.ContainsRune(request.PublisherFile, 0)) {
			Problem(w, credentialfile.ErrInvalid)
			return
		}
		registration, err := s.Invocation(r.Context(), request)
		if err != nil {
			Problem(w, err)
			return
		}
		privateprotocol.Write(w, 200, registration)
	})
	for _, operation := range []string{"register", "renew", "unregister"} {
		mux.HandleFunc("POST /v1/"+operation, func(w http.ResponseWriter, r *http.Request) {
			var request privateprotocol.Registration
			if err := privateprotocol.Decode(w, r, &request); err != nil {
				Problem(w, err)
				return
			}
			if request.Version != 1 || !privateprotocol.ValidOwner(request.Owner) {
				Problem(w, privateprotocol.ErrForbidden)
				return
			}
			service, found := s.Manager.ServiceForRegistration(request.RegistrationID)
			grant := privateprotocol.Grant(r)
			if !found || grant.Scope == "app" && service.Name != *grant.Service || grant.Scope == "invocation" && service.Name != *grant.InvocationId {
				Problem(w, clientruntime.ErrRegistrationStale)
				return
			}
			var err error
			switch operation {
			case "register":
				if grant.Scope != "app" {
					Problem(w, privateprotocol.ErrForbidden)
					return
				}
				if s.Register != nil {
					err = s.Register(request)
				} else {
					err = s.Manager.Register(request.RegistrationID, request.Owner, request.Target, service.Framework)
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
		grant := privateprotocol.Grant(r)
		if grant.Scope != "owner" {
			name := ""
			if grant.Service != nil {
				name = *grant.Service
			} else if grant.InvocationId != nil {
				name = *grant.InvocationId
			}
			snapshot.Services = slices.DeleteFunc(snapshot.Services, func(service clientruntime.Service) bool { return service.Name != name })
			snapshot.Publications = slices.DeleteFunc(slices.Clone(snapshot.Publications), func(publication clientstate.TunnelInfo) bool { return publication.Service != name })
			snapshot.Events = nil
		}
		privateprotocol.Write(w, 200, snapshot)
	})
	mux.HandleFunc("GET /v1/events", func(w http.ResponseWriter, r *http.Request) {
		if privateprotocol.Grant(r).Scope != "owner" {
			Problem(w, privateprotocol.ErrForbidden)
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
		privateprotocol.Write(w, 200, events)
	})
	mux.HandleFunc("POST /v1/check", func(w http.ResponseWriter, r *http.Request) {
		if privateprotocol.Grant(r).Scope != "owner" || s.Check == nil {
			Problem(w, privateprotocol.ErrForbidden)
			return
		}
		var request privateprotocol.Check
		if err := privateprotocol.Decode(w, r, &request); err != nil {
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
		privateprotocol.Write(w, 200, snapshot)
	})
	return s.Capabilities.Handler(mux)
}

func Problem(w http.ResponseWriter, err error) {
	status, code, message := 400, "runtime.request_invalid", "local publisher request is invalid"
	switch {
	case errors.Is(err, privateprotocol.ErrUnauthorized):
		status, code, message = 401, "runtime.unauthorized", "read the current private endpoint descriptor"
	case errors.Is(err, privateprotocol.ErrForbidden):
		status, code, message = 403, "runtime.forbidden", "use a capability for this service and operation"
	case errors.Is(err, clientruntime.ErrOwnerConflict):
		status, code, message = 409, "runtime.owner_conflict", "another live app owns this service; stop it before starting another"
	case errors.Is(err, clientruntime.ErrRegistrationStale):
		status, code, message = 409, "runtime.registration_stale", "prepare and register the listener again"
	case errors.Is(err, clientruntime.ErrCursorExpired):
		status, code, message = 410, "runtime.cursor_expired", "read a new status snapshot before resuming events"
	case errors.Is(err, controlclient.ErrUnauthenticated):
		status, code, message = 401, "runtime.authentication_required", "run tnl auth login, then start the app again"
	case errors.Is(err, nativeauth.ErrSetupRequired):
		status, code, message = 409, "runtime.publisher_setup_required", "run tnl publisher setup --namespace, then start the app again"
	case errors.Is(err, credentialfile.ErrInvalid):
		status, code, message = 400, "runtime.publisher_file_invalid", "check the publisher file, its permissions, and its control URL"
	default:
		if reason, ok := failure.ReasonOf(err); ok {
			definition, _ := failure.DefinitionFor(reason)
			code, message = string(reason), definition.Message
		}
	}
	privateprotocol.Write(w, status, privateprotocol.Problem{Code: code, Message: message})
}

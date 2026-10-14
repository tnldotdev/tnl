package main

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/tnldotdev/tnl/internal/clientruntime"
	"github.com/tnldotdev/tnl/internal/privateprotocol"
	"github.com/tnldotdev/tnl/internal/projectmeta"
	"github.com/tnldotdev/tnl/pkg/api/localpublisherv1"
)

// localHandler is the authenticated project API on loopback. app service
// credentials cannot access owner-only ad-hoc or observation operations.
func (a *appRuntime) localHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/health", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	mux.HandleFunc("POST /v1/prepare", func(w http.ResponseWriter, r *http.Request) {
		var request localpublisherv1.AppPreparation
		if err := decodeLocalRequest(w, r, &request); err != nil {
			runtimeProblem(w, err)
			return
		}
		if request.Service != localPublisherService(r.Context()) {
			localUnauthorized(w)
			return
		}
		assignment, err := a.prepare(r.Context(), privateprotocol.Prepare{
			Version: privateprotocol.Version, Directory: request.Directory, Service: request.Service,
			Framework: privateprotocol.Framework(request.Framework), Owner: request.Owner, PID: request.Pid,
		})
		if err != nil {
			runtimeProblem(w, err)
			return
		}
		privateprotocol.Write(w, http.StatusOK, struct {
			RegistrationID string                     `json:"registration_id"`
			Service        string                     `json:"service"`
			Hostname       string                     `json:"hostname"`
			PublicURL      string                     `json:"public_url"`
			Project        projectmeta.PublicMetadata `json:"project"`
		}{assignment.RegistrationID, assignment.Service, assignment.Hostname, assignment.PublicURL, assignment.Project})
	})
	mux.HandleFunc("PUT /v1/registrations/{registration_id}", func(w http.ResponseWriter, r *http.Request) {
		var bound localpublisherv1.BoundListener
		if err := decodeLocalRequest(w, r, &bound); err != nil {
			runtimeProblem(w, err)
			return
		}
		id := r.PathValue("registration_id")
		framework, ok := a.localRegistration(id, localPublisherService(r.Context()))
		if !ok {
			runtimeProblem(w, clientruntime.ErrRegistrationStale)
			return
		}
		if err := a.manager.Register(id, bound.Owner, bound.Target, framework); err != nil {
			runtimeProblem(w, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	for _, operation := range []string{"renew", "stop"} {
		pattern := "POST /v1/registrations/{registration_id}/renew"
		if operation == "stop" {
			pattern = "DELETE /v1/registrations/{registration_id}"
		}
		mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
			id := r.PathValue("registration_id")
			owner := r.Header.Get("X-Registration-Owner")
			if _, ok := a.localRegistration(id, localPublisherService(r.Context())); !ok || !privateprotocol.ValidOwner(owner) {
				runtimeProblem(w, clientruntime.ErrRegistrationStale)
				return
			}
			var err error
			if operation == "renew" {
				err = a.manager.Renew(id, owner)
			} else {
				err = a.manager.Unregister(id, owner)
				if err == nil {
					a.mu.Lock()
					delete(a.prepared, id)
					a.mu.Unlock()
				}
			}
			if err != nil {
				runtimeProblem(w, err)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		})
	}
	mux.HandleFunc("GET /v1/status", func(w http.ResponseWriter, _ *http.Request) {
		snapshot, err := a.manager.JournalSnapshot()
		if err != nil {
			runtimeProblem(w, err)
			return
		}
		privateprotocol.Write(w, http.StatusOK, localProjectSnapshot(snapshot))
	})
	mux.HandleFunc("GET /v1/events", a.localEvents)
	// the owner credential can observe readiness and manage ad-hoc invocations;
	// app service credentials cannot reach these private operations.
	mux.Handle("POST /v1/observe", a.ownerOperations())
	mux.Handle("POST /v1/ad-hoc/", a.ownerOperations())
	return mux
}

func (a *appRuntime) localRegistration(id, service string) (string, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	prepared, ok := a.prepared[id]
	return string(prepared.framework), ok && service != "" && prepared.assignment.Service == service
}

func decodeLocalRequest(w http.ResponseWriter, r *http.Request, value any) error {
	if r.Header.Get("Content-Type") != "application/json" {
		return errors.New("local publisher request needs application/json")
	}
	r.Body = http.MaxBytesReader(w, r.Body, privateprotocol.MaxBytes)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return err
	}
	if decoder.Decode(new(any)) != io.EOF {
		return errors.New("trailing local publisher request data")
	}
	return nil
}

func localProjectSnapshot(snapshot clientruntime.Snapshot) localpublisherv1.ProjectSnapshot {
	result := localpublisherv1.ProjectSnapshot{Project: snapshot.Project, Cursor: snapshot.Cursor, Services: make([]localpublisherv1.ServiceStatus, 0, len(snapshot.Services))}
	for _, service := range snapshot.Services {
		result.Services = append(result.Services, localServiceStatus(service))
	}
	return result
}

func localServiceStatus(service clientruntime.Service) localpublisherv1.ServiceStatus {
	protocol := service.ServiceProtocol
	if protocol == "" {
		protocol = "http"
	}
	state := localpublisherv1.ServiceStatusStateNotStarted
	switch {
	case service.Ready:
		state = localpublisherv1.ServiceStatusStateReady
	case service.Routable:
		state = localpublisherv1.ServiceStatusStateRoutable
	case service.Registered:
		state = localpublisherv1.ServiceStatusStatePublishing
	case service.Failure != "":
		state = localpublisherv1.ServiceStatusStateFailed
	}
	result := localpublisherv1.ServiceStatus{Service: service.Name, Protocol: localpublisherv1.ServiceStatusProtocol(protocol), State: state}
	if service.PublicURL != "" {
		result.PublicUrl = &service.PublicURL
	}
	if service.Target != "" {
		result.Target = &service.Target
	}
	if service.RegistrationID != "" {
		result.RegistrationId = &service.RegistrationID
	}
	if service.PublishRunNumber != 0 {
		number := int64(service.PublishRunNumber)
		result.PublishRunNumber = &number
	}
	if service.Failure != "" {
		result.Reason = &service.Failure
	}
	return result
}

func (a *appRuntime) localEvents(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	if len(query["after"]) != 1 || len(query.Get("after")) > 128 || len(query["wait_seconds"]) > 1 {
		runtimeProblem(w, errors.New("invalid event cursor or wait"))
		return
	}
	wait := 0
	if query.Has("wait_seconds") {
		var err error
		wait, err = strconv.Atoi(query.Get("wait_seconds"))
		if err != nil || wait < 0 || wait > 30 {
			runtimeProblem(w, errors.New("invalid event wait"))
			return
		}
	}
	deadline := time.Now().Add(time.Duration(wait) * time.Second)
	for {
		snapshot, err := a.manager.JournalSnapshot()
		if err != nil {
			runtimeProblem(w, err)
			return
		}
		events, err := clientruntime.EventsAfter(snapshot, query.Get("after"))
		if errors.Is(err, clientruntime.ErrCursorExpired) {
			privateprotocol.Write(w, http.StatusGone, localpublisherv1.Problem{Code: "runtime.cursor_expired", Message: "local event cursor expired; read status and resume"})
			return
		}
		if err != nil {
			runtimeProblem(w, err)
			return
		}
		if len(events) > 0 || wait == 0 || time.Now().After(deadline) {
			page := localpublisherv1.ProjectEventPage{Cursor: query.Get("after"), Events: make([]localpublisherv1.ProjectEvent, 0, min(len(events), 32))}
			for _, event := range events {
				entry := localpublisherv1.ProjectEvent{Cursor: event.Cursor, Type: event.Type}
				if event.Service != nil {
					entry.Service = &event.Service.Name
					status := localServiceStatus(*event.Service)
					entry.Status = &status
				}
				page.Events = append(page.Events, entry)
				page.Cursor = event.Cursor
				if len(page.Events) == 32 {
					break
				}
			}
			privateprotocol.Write(w, http.StatusOK, page)
			return
		}
		timer := time.NewTimer(100 * time.Millisecond)
		select {
		case <-r.Context().Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

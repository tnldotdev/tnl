package integrationurls

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/tnldotdev/tnl/internal/clientstate"
	"github.com/tnldotdev/tnl/internal/diagnostic"
	"github.com/tnldotdev/tnl/internal/opaqueid"
	"github.com/tnldotdev/tnl/internal/publisher"
)

// AliasPublisher uses the same elected lifecycle as OAuth and webhooks, but only
// the selected entry-service tunnel may prepare its run. every request rechecks
// selection and destination identity before reaching the local proxy.
func AliasPublisher(state *clientstate.Database, store *clientstate.Store, selection clientstate.AliasSelection, tunnelID string, base publisher.Config, report func(publisher.Event, error)) Publisher {
	candidate := func(ctx context.Context) (clientstate.AliasSelection, clientstate.TunnelInfo, error) {
		current, receiver, err := state.AliasCandidate(ctx, selection.ID)
		if err != nil {
			return current, receiver, err
		}
		if receiver.ID != tunnelID {
			return current, receiver, clientstate.ErrAliasNotSelected
		}
		if current.Hostname != base.Hostname || current.Fingerprint != selection.Fingerprint {
			return current, receiver, clientstate.ErrAliasPolicyConflict
		}
		return current, receiver, nil
	}
	revision := func(selection clientstate.AliasSelection, receiver clientstate.TunnelInfo) string {
		return fmt.Sprintf("%d:%s:%s:%d", selection.Revision, receiver.ID, receiver.PublicURLID, receiver.PublishRunNumber)
	}
	return Publisher{
		State: state, Store: store, Server: selection.Scope.Server, Hostname: base.Hostname,
		Eligible: func(ctx context.Context) (bool, error) {
			_, _, err := candidate(ctx)
			if errors.Is(err, clientstate.ErrAliasNotSelected) || errors.Is(err, clientstate.ErrAliasReceiverUnavailable) {
				return false, nil
			}
			return err == nil, err
		},
		Prepare: func(ctx context.Context) (Snapshot, error) {
			current, receiver, err := candidate(ctx)
			if err != nil {
				return Snapshot{}, err
			}
			owner, err := opaqueid.New(opaqueid.InvocationPrefix)
			if err != nil {
				return Snapshot{}, err
			}
			config := base
			config.PreviewID, config.Feedback = "", false
			config.AdmitRequest = func(request *http.Request, run publisher.PublishRunIdentity) error {
				latest, target, err := candidate(request.Context())
				if err == nil && revision(latest, target) != revision(current, receiver) {
					err = clientstate.ErrAliasSelectionStale
				}
				if err != nil {
					return diagnostic.Wrap(diagnostic.AliasUnavailable, err)
				}
				query := request.URL.Query()
				if request.Method == http.MethodGet && len(query["state"]) == 1 {
					if err := state.AdmitAliasOAuthReturn(request.Context(), selection.Scope.Server, current.Hostname,
						query.Get("state"), request.URL.EscapedPath(), run.PublicURLID, run.Number); err != nil {
						return diagnostic.Wrap(diagnostic.OAuthCallbackExpired, err)
					}
				}
				return nil
			}
			config.Observe = func(event publisher.Event) error {
				switch event.Type {
				case publisher.EventReady:
					return state.MarkAliasRunReady(ctx, clientstate.AliasPublishRun{Selection: current, Receiver: receiver,
						Owner: owner, PublicURLID: event.PublicURLID, Number: event.PublishRunNumber})
				case publisher.EventProvisioning, publisher.EventDraining:
					cleanup, cancel := context.WithTimeout(context.Background(), 2*time.Second)
					defer cancel()
					return state.ClearAliasRun(cleanup, current.ID, owner)
				}
				return nil
			}
			return Snapshot{Config: config, Revision: revision(current, receiver)}, nil
		},
		Revision: func(ctx context.Context) (string, error) {
			current, receiver, err := candidate(ctx)
			return revision(current, receiver), err
		},
		Report: func(event publisher.Event, err error) {
			if report != nil && !errors.Is(err, clientstate.ErrAliasNotSelected) && !errors.Is(err, clientstate.ErrAliasReceiverUnavailable) {
				report(event, err)
			}
		},
	}
}

package integrations

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync"

	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/failure/diagnostic"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

// AliasPublisher uses the same elected lifecycle as OAuth and webhooks, but only
// the selected entry-service tunnel may prepare its run. every request rechecks
// selection and destination identity before reaching the local proxy.
func AliasPublisher(state *clientstate.Database, store *clientstate.Store, selection clientstate.AliasSelection, tunnelID string, prepare func(context.Context) (Snapshot, error), report func(bool, error)) Publisher {
	candidate := func(ctx context.Context) (clientstate.AliasSelection, clientstate.TunnelInfo, error) {
		current, receiver, err := state.AliasCandidate(ctx, selection.ID)
		if err != nil {
			return current, receiver, err
		}
		if receiver.ID != tunnelID {
			return current, receiver, clientstate.ErrAliasNotSelected
		}
		if current.Hostname != selection.Hostname || current.Fingerprint != selection.Fingerprint {
			return current, receiver, clientstate.ErrAliasPolicyConflict
		}
		if !opaqueid.Valid(receiver.ServiceID, opaqueid.ServicePrefix) {
			return current, receiver, clientstate.ErrAliasReceiverUnavailable
		}
		return current, receiver, nil
	}
	revision := func(selection clientstate.AliasSelection, receiver clientstate.TunnelInfo) string {
		return fmt.Sprintf("%d:%s:%s:%d", selection.Revision, receiver.ID, receiver.ServiceID, receiver.PublishRunNumber)
	}
	return Publisher{
		State: state, Store: store, Server: selection.Scope.Server, Hostname: selection.Hostname,
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
			snapshot, err := prepare(ctx)
			if err != nil {
				return Snapshot{}, err
			}
			if snapshot.Service.Endpoint == nil || snapshot.Service.Endpoint.Hostname != current.Hostname {
				return Snapshot{}, clientstate.ErrAliasPolicyConflict
			}
			owner, err := opaqueid.New(opaqueid.InvocationPrefix)
			if err != nil {
				return Snapshot{}, err
			}
			config := snapshot.Config
			config.PreviewID, config.Feedback = "", false
			admit, prepared, readiness := config.AdmitRequest, config.Prepared, snapshot.Readiness
			var mu sync.Mutex
			var run controlv1.ServiceRunPreparation
			config.Prepared = func(preparation controlv1.ServiceRunPreparation) error {
				if preparation.ServiceId != config.ServiceID || preparation.RunNumber < 1 || !opaqueid.Valid(preparation.ServiceRunId, opaqueid.ServiceRunPrefix) {
					return clientstate.ErrAliasSelectionStale
				}
				mu.Lock()
				if run.ServiceId != "" && (run.ServiceId != preparation.ServiceId || run.ServiceRunId != preparation.ServiceRunId || run.RunNumber != preparation.RunNumber) {
					mu.Unlock()
					return clientstate.ErrAliasSelectionStale
				}
				run = preparation
				mu.Unlock()
				if prepared != nil {
					return prepared(preparation)
				}
				return nil
			}
			config.AdmitRequest = func(request *http.Request) error {
				if admit != nil {
					if err := admit(request); err != nil {
						return err
					}
				}
				latest, target, err := candidate(request.Context())
				if err == nil && revision(latest, target) != revision(current, receiver) {
					err = clientstate.ErrAliasSelectionStale
				}
				if err != nil {
					return diagnostic.Wrap(diagnostic.AliasUnavailable, err)
				}
				query := request.URL.Query()
				if request.Method == http.MethodGet && len(query["state"]) == 1 {
					mu.Lock()
					captured := run
					mu.Unlock()
					if err := state.AdmitAliasOAuthReturn(request.Context(), selection.Scope.Server, current.Hostname,
						query.Get("state"), request.URL.EscapedPath(), captured.ServiceId, uint64(captured.RunNumber)); err != nil {
						return diagnostic.Wrap(diagnostic.OAuthCallbackExpired, err)
					}
				}
				return nil
			}
			snapshot.Readiness = func(ctx context.Context, ready bool) error {
				var err error
				if ready {
					mu.Lock()
					captured := run
					mu.Unlock()
					err = state.MarkAliasRunReady(ctx, clientstate.AliasPublishRun{Selection: current, Receiver: receiver,
						Owner: owner, ServiceID: captured.ServiceId, Number: uint64(captured.RunNumber)})
				} else {
					err = state.ClearAliasRun(ctx, current.ID, owner)
				}
				if readiness != nil {
					err = errors.Join(err, readiness(ctx, ready))
				}
				return err
			}
			snapshot.Config, snapshot.Revision = config, revision(current, receiver)
			return snapshot, nil
		},
		Revision: func(ctx context.Context) (string, error) {
			current, receiver, err := candidate(ctx)
			return revision(current, receiver), err
		},
		Report: func(ready bool, err error) {
			if report != nil && !errors.Is(err, clientstate.ErrAliasNotSelected) && !errors.Is(err, clientstate.ErrAliasReceiverUnavailable) {
				report(ready, err)
			}
		},
	}
}

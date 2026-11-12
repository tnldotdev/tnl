package runtime

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"testing"
	"time"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
)

type sdkCapabilityBackend struct{ fixtureBackend }

func (*sdkCapabilityBackend) IdentityChallenge() (authorityv1.IdentitySourceChallenge, error) {
	panic("unconfigured identity source must not be discovered")
}
func (*sdkCapabilityBackend) SDKPrepare(context.Context, Request) (SDKPrepared, error) {
	panic("unconfigured SDK owner selection must not be discovered")
}

func TestConnectionOwnerExposesOnlyConfiguredSDKOperations(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		t.Run(map[bool]string{false: "unconfigured", true: "configured"}[enabled], func(t *testing.T) {
			scope := fixtureScope(t)
			directory, err := NewDirectory(scope.Directory)
			if err != nil {
				t.Fatal(err)
			}
			backend := &sdkCapabilityBackend{fixtureBackend{deadline: time.Now().Add(time.Hour)}}
			backend.credential.Store(1)
			config := OwnerConfig{Backend: backend}
			var state Status
			if enabled {
				config.SDKPrepare = func(ctx context.Context, request Request) (SDKPrepared, error) {
					prepared, err := PrepareSnapshot(ctx, backend, request)
					return SDKPrepared{Schema: Schema, Owner: state.SDKOwner(), Prepared: prepared}, err
				}
			}
			ctx, cancel := context.WithCancel(t.Context())
			reader, writer := io.Pipe()
			defer reader.Close()
			done := make(chan error, 1)
			go func() { done <- Serve(ctx, scope, directory, "/test/tnl", config, writer) }()
			t.Cleanup(func() {
				cancel()
				if err := <-done; err != nil {
					t.Error(err)
				}
			})
			if err := json.NewDecoder(reader).Decode(&state); err != nil {
				t.Fatal(err)
			}
			request := Request{Schema: Schema, Directory: scope.Directory, ConfigDigest: scope.ConfigDigest, Service: "database"}
			handle, err := ReadHandle(state.ConnectionHandle)
			if err != nil {
				t.Fatal(err)
			}
			call := func(operation string, destination any) int {
				t.Helper()
				payload, err := json.Marshal(request)
				if err != nil {
					t.Fatal(err)
				}
				req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, handle.URL+"/v1/connections/"+operation, bytes.NewReader(payload))
				if err != nil {
					t.Fatal(err)
				}
				req.Header.Set("Authorization", "Bearer "+handle.Key)
				response, err := http.DefaultClient.Do(req)
				if err != nil {
					t.Fatal(err)
				}
				defer response.Body.Close()
				if response.StatusCode == http.StatusOK {
					if err := ReadJSON(response.Body, destination); err != nil {
						t.Fatal(err)
					}
				}
				return response.StatusCode
			}
			var prepared SDKPrepared
			status := call("sdk-prepare", &prepared)
			if !enabled {
				if status != http.StatusServiceUnavailable {
					t.Fatal("unconfigured SDK selection was exposed", status)
				}
			} else {
				want, snapshotErr := backend.SnapshotFor(request.Service, "")
				wantJSON, wantErr := json.Marshal(want)
				gotJSON, gotErr := json.Marshal(prepared.Prepared)
				if status != http.StatusOK || snapshotErr != nil || wantErr != nil || gotErr != nil || prepared.Owner != state.SDKOwner() || !bytes.Equal(gotJSON, wantJSON) {
					t.Fatal("SDK selection changed its exact owner or private snapshot", status, snapshotErr)
				}
			}
			// selecting a local owner does not opt into identity-source authority.
			if status := call("identity-challenge", new(authorityv1.IdentitySourceChallenge)); status != http.StatusServiceUnavailable {
				t.Fatal("identity source was discovered instead of configured", status)
			}
			if status := call("sdk-workload", new(any)); status != http.StatusNotFound {
				t.Fatal("retired workload selector remains exposed", status)
			}
		})
	}
}

func TestPersistentConnectionOwnerRequiresApplicationLiveness(t *testing.T) {
	backend := &fixtureBackend{deadline: time.Now().Add(time.Hour)}
	err := Serve(t.Context(), fixtureScope(t), t.TempDir(), "/test/tnl", OwnerConfig{Backend: backend, Persistent: true}, io.Discard)
	if !errors.Is(err, ErrInvalid) {
		t.Fatal("persistent owner has no declared application lifetime", err)
	}
}

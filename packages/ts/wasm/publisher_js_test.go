//go:build js && wasm && !tnlconnector

package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"syscall/js"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/client/auth"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func publisherRuntimeFixture(t *testing.T, temporary bool) (string, js.Value, string) {
	t.Helper()
	id := func(prefix string) string {
		t.Helper()
		value, err := opaqueid.New(prefix)
		if err != nil {
			t.Fatal(err)
		}
		return value
	}
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	approval := controlv1.DeploymentCredential{
		ClientId: id(opaqueid.PublisherIdentityPrefix), GrantId: id(opaqueid.PublisherGrantPrefix), KeyId: id(opaqueid.PublisherIdentityKeyPrefix),
		TeamId: id(opaqueid.TeamPrefix), ProjectKey: "project", ExpiresAt: time.Now().Add(time.Hour),
	}
	credential := auth.DeploymentCredential{Version: 1, ControlURL: "https://control.example.test", Team: "team",
		Approval: approval, PrivateKey: base64.RawURLEncoding.EncodeToString(key)}
	token, err := credential.Encode()
	if err != nil {
		t.Fatal(err)
	}
	options := publisherOptions{Credential: token, Project: "team/project", Deployment: "production", Service: "web"}
	if temporary {
		options.Service = ""
	}
	encoded, err := json.Marshal(options)
	if err != nil {
		t.Fatal(err)
	}
	service := controlv1.Service{
		Id: id(opaqueid.ServicePrefix), TeamId: approval.TeamId, DomainId: new(id(opaqueid.DomainPrefix)),
		Name: "web", Protocol: controlv1.ServiceProtocolHTTP, Enabled: true, Ephemeral: temporary,
		TrustRevision: 1, EndpointRevision: 1, Endpoint: &controlv1.ServiceEndpoint{Hostname: "web.example.test", Port: 443, Public: true},
	}
	if temporary {
		service.ExpiresAt = new(approval.ExpiresAt)
	}
	saved, err := json.Marshal(service)
	if err != nil {
		t.Fatal(err)
	}
	factory := publisherFunction(t, `(serviceJSON, serviceID, grantID) => {
		const calls = [], deletions = [], allocations = [];
		return {calls, deletions, allocations, host:{
			fetch: request => new Response("application"),
			controlFetch: async request => {
				const path = new URL(request.url).pathname;
				calls.push(request.method+" "+path);
				if (path === "/v1/publisher-token") return Response.json({
					access_token:"registered-deployment-access", token_type:"Bearer", expires_in:300, grant_id:grantID
				});
				if (path.endsWith("/publication") || request.method === "GET" && path.endsWith("/publisher/services/"+serviceID))
					return new Response(serviceJSON, {headers:{"content-type":"application/json"}});
				if (request.method === "DELETE" && path.endsWith("/publisher/services/"+serviceID)) {
					deletions.push(serviceID); return new Response(null,{status:204});
				}
				if (request.method === "POST" && path.endsWith("/services")) {
					allocations.push(await request.json());
					return new Response(serviceJSON, {status:201, headers:{"content-type":"application/json"}});
				}
				// deliberately stop before certificates or relay setup. the
				// service owner must surface the failure, then allocation cleanup
				// must still use the same explicit registered credential.
				return new Response(null,{status:400});
			},
			storage:{
				read() {throw Error("unexpected certificate read")},
				write() {throw Error("unexpected certificate write")},
				sync() {throw Error("unexpected certificate sync")},
				lock() {throw Error("unexpected certificate lock")}
			}
		}};
	}`)
	return string(encoded), factory.Invoke(string(saved), service.Id, approval.GrantId), service.Id
}

func TestPublisherRuntimeUsesSharedRunOwnerAndCleansTemporaryAllocation(t *testing.T) {
	for _, temporary := range []bool{false, true} {
		name := "named"
		if temporary {
			name = "temporary"
		}
		t.Run(name, func(t *testing.T) {
			options, state, serviceID := publisherRuntimeFixture(t, temporary)
			runtimeMu.Lock()
			before := len(runtimeResources)
			runtimeMu.Unlock()
			api := js.Global().Get("Object").New()
			registerPublisher(api)
			handle, err := publisherAwait(t.Context(), api.Call("publish", options, state.Get("host")), nil)
			if err != nil {
				t.Fatal("publisher did not prepare its explicit service authority", err)
			}
			if handle.Get("url").String() != "https://web.example.test" {
				t.Fatal("publisher lost its approved endpoint")
			}
			if _, err := publisherAwait(t.Context(), handle.Get("closed"), nil); err == nil {
				t.Fatal("service preparation failure was hidden")
			}
			if _, err := publisherAwait(t.Context(), handle.Get("ready"), nil); err == nil {
				t.Fatal("failed service became ready")
			}
			// close can observe the same failure while its bound method remains
			// live, or an idempotent success once the owner has retired.
			_, _ = publisherAwait(t.Context(), handle.Call("close"), nil)
			deletions := state.Get("deletions")
			want := 0
			if temporary {
				want = 1
			}
			if deletions.Length() != want || temporary && deletions.Index(0).String() != serviceID {
				t.Fatal("publisher deleted a retained service or lost temporary cleanup", deletions.Length())
			}
			if temporary {
				allocations := state.Get("allocations")
				if allocations.Length() != 1 || allocations.Index(0).Get("configuration").Get("target").String() != "app" {
					t.Fatal("publisher selected a dummy target or another allocation")
				}
			}
			runtimeMu.Lock()
			after := len(runtimeResources)
			runtimeMu.Unlock()
			if after != before {
				t.Fatal("publication survived its joined runtime cleanup", before, after)
			}
		})
	}
}

func TestPublisherSignalRemainsAttachedUntilCleanup(t *testing.T) {
	abort := js.Global().Get("AbortController").New()
	ctx, cancel := context.WithCancel(t.Context())
	stop, err := publisherSignal(abort.Get("signal"), cancel)
	if err != nil {
		t.Fatal(err)
	}
	abort.Call("abort")
	select {
	case <-ctx.Done():
	default:
		t.Fatal("publisher did not receive host cancellation")
	}
	stop()
}

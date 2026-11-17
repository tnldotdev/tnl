//go:build js && wasm

package main

import (
	"encoding/json"
	"strings"
	"syscall/js"
	"testing"
	"time"

	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestEnrolledPublisherRetriesAndPreparesExactAppRun(t *testing.T) {
	const server = "https://control.example.test"
	member := controlv1.DeploymentPublisherIdentity{
		TeamId: "team_" + strings.Repeat("T", 22), ProjectKey: "project",
		DeploymentId: "dpl_" + strings.Repeat("D", 22), DeploymentName: "production",
		PublisherIdentityId: "pub_" + strings.Repeat("P", 22), KeyId: "pkey_" + strings.Repeat("K", 22),
	}
	service := controlv1.Service{
		Id: "svc_" + strings.Repeat("S", 22), TeamId: member.TeamId, Name: "web",
		DomainId: new("dom_" + strings.Repeat("D", 22)),
		Protocol: controlv1.ServiceProtocolHTTP, Enabled: true, TrustRevision: 1, EndpointRevision: 1,
		Endpoint: &controlv1.ServiceEndpoint{Hostname: "web.example.test", Public: true, Port: 443},
	}
	grant := "pgrant_" + strings.Repeat("G", 22)
	assignment := controlv1.DeploymentPublisherServiceAssignment{
		Service: "web", ServiceId: service.Id, GrantId: grant, TrustRevision: 1,
		Configuration: controlv1.ProjectServiceConfiguration{Target: "app", Protocol: new(controlv1.ServiceProtocolHTTP)},
	}
	secret := "pen_" + strings.Repeat("E", 22) + ".private-bootstrap"
	encode := func(value any) string {
		t.Helper()
		data, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		return string(data)
	}
	state := publisherFunction(t, `(member, service, assignment, grant, secret, expires) => {
		const records = new Map();
		const state = {enrollments: [], calls: [], held: false};
		state.host = {
			fetch: () => new Response("application"),
			signal: new AbortController().signal,
			controlFetch: async request => {
				const url = new URL(request.url);
				const path = url.pathname;
				state.calls.push(request.method+" "+path);
				if (request.credentials !== "omit" || request.redirect !== "manual") throw Error("unexpected credential policy");
				if (path === "/v1/publisher/deployments/enroll") {
					const body = await request.json();
					if (body.enrollment_key !== secret || body.deployment_id !== member.deployment_id || body.project_key !== member.project_key ||
						"private_key" in body || !state.held || records.size !== 1)
						throw Error("enrollment escaped private staging");
					state.enrollments.push(body.public_key);
					if (state.enrollments.length === 1) throw Error("lost reply");
					return Response.json(member);
				}
				if (path === "/v1/publisher/deployments/verify" || path === "/v1/publisher/deployments/lease") {
					const body = await request.json();
					if (body.publisher_identity_id !== member.publisher_identity_id || body.deployment_id !== member.deployment_id || !body.assertion) throw Error("wrong signed member");
					return path.endsWith("/verify") ? Response.json({member,deployment_names:["production"]}) :
						Response.json({access_token:"dpl_lease_selected",expires_at:expires});
				}
				if (path === "/v1/publisher/deployments/assignments") {
					if (url.search !== "?app_owned=true" || request.headers.get("authorization") !== "Bearer dpl_lease_selected") throw Error("wrong assignment authority");
					return Response.json({member,revision:"1",configuration_hash:"a".repeat(64),services:[assignment],certificate_state_plans:[]});
				}
				if (path === "/v1/publisher-token") return Response.json({access_token:"pta_selected", token_type:"Bearer", expires_in:300, grant_id:grant});
				if (path === "/v1/publisher/services/"+service.id && request.method === "GET") return Response.json(service);
				// stop at run preparation. relay and visitor readiness are not simulated.
				return new Response(null,{status:400});
			},
			storage: {
				read(scope,key) {return records.get(scope+key)?.slice() ?? null},
				write(scope,key,value) {records.set(scope+key,value.slice())},
				sync() {},
				lock(scope,key) {
					if(state.held) throw Error("already held");
					state.held = true;
					return async () => {state.held = false};
				}
			}
		};
		return state;
	}`).Invoke(js.Global().Get("JSON").Call("parse", encode(member)), js.Global().Get("JSON").Call("parse", encode(service)),
		js.Global().Get("JSON").Call("parse", encode(assignment)), grant, secret, time.Now().Add(time.Minute).Format(time.RFC3339Nano))

	host := state.Get("host")
	api := js.Global().Get("Object").New()
	registerPublisher(api)
	options := map[string]string{"control_url": server, "project_key": member.ProjectKey, "deployment_id": member.DeploymentId, "instance": "browser", "enrollment_key": secret}
	open := func() (js.Value, error) {
		return publisherAwait(t.Context(), api.Call("enrollPublisher", encode(options), host), nil)
	}
	if _, err := open(); err == nil || state.Get("held").Bool() {
		t.Fatal("lost reply accepted or left the lock held", err)
	}
	owner, err := open()
	if err != nil || owner.Get("publisherIdentityID").String() != member.PublisherIdentityId || !state.Get("held").Bool() {
		t.Fatal("same-key recovery did not return a lock-owned identity", err)
	}
	keys := state.Get("enrollments")
	if keys.Length() != 2 || keys.Index(0).String() != keys.Index(1).String() {
		t.Fatal("retry used a different signing key")
	}
	if _, err := publisherAwait(t.Context(), owner.Call("publish", `{"service":"other"}`, host), nil); err == nil {
		t.Fatal("enrolled owner published a binding outside its assignment")
	}
	run, err := publisherAwait(t.Context(), owner.Call("publish", `{"service":"web"}`, host), nil)
	if err != nil || run.Get("url").String() != "https://web.example.test" {
		t.Fatal("enrolled publisher failed to compose shared service owner", err)
	}
	if _, err := publisherAwait(t.Context(), run.Get("closed"), nil); err == nil {
		t.Fatal("fixture run preparation failure was hidden")
	}
	want := "POST /v1/services/" + service.Id + "/runs"
	if !state.Get("calls").Call("includes", want).Bool() || !state.Get("held").Bool() {
		t.Fatal("enrolled publisher missed shared run preparation or released its live identity")
	}
	if _, err := publisherAwait(t.Context(), owner.Call("close"), nil); err != nil || state.Get("held").Bool() {
		t.Fatal("close failed to release joined owner", err)
	}
	delete(options, "enrollment_key")
	reloaded, err := open()
	if err != nil || reloaded.Get("publisherIdentityID").String() != member.PublisherIdentityId || keys.Length() != 2 {
		t.Fatal("reload without bootstrap changed identity or readmitted it", err)
	}
	if _, err := publisherAwait(t.Context(), reloaded.Call("close"), nil); err != nil {
		t.Fatal(err)
	}
}

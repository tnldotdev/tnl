package state

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	publisherdeployment "github.com/tnldotdev/tnl/internal/publisher/deployment"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestIntegrationDeploymentPublicURLAssignmentIgnoresRunLifecycle(t *testing.T) {
	d, now, _, _ := newPublishRunPrerequisites(t)
	ctx := t.Context()
	request := appliedProjectRequest(t, d, now)
	request.Configuration = ProjectConfiguration{Settings: &DeploymentSettings{}, Services: map[string]ProjectServiceConfiguration{
		"web": {Target: "http://web.internal:3000", PublicURL: &ProjectServicePublicURL{}},
		"api": {Target: "http://api.internal:3000", PublicURL: &ProjectServicePublicURL{}},
	}}
	request = selectedProjectRequest(request, "production")
	applied, err := d.ApplyProjectConfiguration(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	enrollment, err := testDeploymentPublisherEnrollment(d, ctx, request.TeamID, request.ProjectKey, "production", request.ActorID, 1, time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	replica := enrollAppliedDeployment(t, d, request, enrollment, now)
	if len(replica.assignments.Services) != 2 {
		t.Fatal("missing public URL assignments")
	}
	find := func(assignments DeploymentPublisherAssignments, name string) DeploymentPublisherServiceAssignment {
		t.Helper()
		for _, assignment := range assignments.Services {
			if assignment.Service == name {
				return assignment
			}
		}
		t.Fatal("missing binding", name)
		return DeploymentPublisherServiceAssignment{}
	}
	web := find(replica.assignments, "web")
	wire, err := json.Marshal(web)
	if err != nil || bytes.Contains(wire, []byte(`"trust_revision"`)) {
		t.Fatal("public URL assignment invented a saved-service trust revision", err)
	}
	access := deploymentAssignmentAccess(t, d, replica, web, now)
	publicURL, err := d.GetPublicURL(ctx, request.ActorID, web.ServiceID)
	if err != nil {
		t.Fatal(err)
	}
	run, err := d.CreatePublishRun(ctx, reviewRunRequest(t, d, access.PublisherIdentity, replica.private, publicURL, "steady-publication"), now, time.Minute, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	authentication := (publishRunFixture{setup: run}).authentication()
	for poll := range 3 {
		if _, err := d.HeartbeatPublishRun(ctx, authentication, now.Add(time.Duration(poll)*time.Second), time.Minute, time.Minute); err != nil {
			t.Fatal(err)
		}
		current, err := d.GetDeploymentPublisherAssignments(ctx, replica.lease.AccessToken, now)
		if err != nil || !reflect.DeepEqual(current.Services, replica.assignments.Services) {
			t.Fatal("publication lifecycle changed a configuration assignment", current.Services, err)
		}
	}
	request.ExpectedRevision = applied.Revision
	api := request.Configuration.Services["api"]
	api.Target = "http://replacement.internal:3000"
	request.Configuration.Services["api"] = api
	_, err = d.ApplyProjectConfiguration(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	current, err := d.GetDeploymentPublisherAssignments(ctx, replica.lease.AccessToken, now)
	if err != nil || !reflect.DeepEqual(find(current, "web"), web) || reflect.DeepEqual(find(current, "api"), find(replica.assignments, "api")) {
		t.Fatal("changing one binding changed its unchanged sibling or retained old configuration", err)
	}
	if _, err := d.HeartbeatPublishRun(ctx, authentication, now, time.Minute, time.Minute); err != nil {
		t.Fatal("sibling configuration change closed the steady publication", err)
	}
	webConfiguration := request.Configuration.Services["web"]
	webConfiguration.Target = "http://replacement-web.internal:3000"
	updated, err := d.UpdateDeployment(ctx, UpdateDeploymentRequest{
		DeploymentScope: DeploymentScope{TeamID: request.TeamID, ProjectKey: request.ProjectKey, ActorID: request.ActorID},
		Selector:        replica.member.DeploymentID, ExpectedRevision: current.Revision,
		Targets: map[string]DeploymentTarget{"web": {Address: webConfiguration.Target}}, Now: now,
	})
	if err != nil || updated.Services["web"].ID != web.ServiceID {
		t.Fatal("target change lost canonical public URL binding", err)
	}
	changed, err := d.GetDeploymentPublisherAssignments(ctx, replica.lease.AccessToken, now)
	if err != nil || reflect.DeepEqual(find(changed, "web"), web) || !reflect.DeepEqual(find(changed, "api"), find(current, "api")) {
		t.Fatal("target change did not isolate replacement to the changed binding", err)
	}
	closed, err := controlstatedb.New(d.pool).GetPublishRun(ctx, run.PublishRunID)
	if err != nil || !closed.ClosedAt.Valid || closed.State != "closed" {
		t.Fatal("real configuration change did not close the old run", err)
	}
	if _, err := d.HeartbeatPublishRun(ctx, authentication, now, time.Minute, time.Minute); !errors.Is(err, ErrPublishRunStale) && !errors.Is(err, ErrPublisherIdentity) {
		t.Fatal("real configuration change left its old run open", err)
	}
}

// bridge only wire conversion; real control owns leases, assignments and acks.
type deploymentAssignmentPollControl struct {
	d    *Database
	acks chan controlv1.DeploymentPublisherAcknowledgement
}

func (c deploymentAssignmentPollControl) ServerURL() string { return "https://control.example" }

func (c deploymentAssignmentPollControl) PublisherRuntime(ctx context.Context, r controlv1.PublisherRuntimeRequest) (result controlv1.PublisherRuntimeResponse, err error) {
	response, err := c.d.PublisherRuntime(ctx, PublisherRuntimeRequest{
		PublisherIdentityID: r.PublisherIdentityId, ScopeID: r.ScopeId, ProcessRunID: r.ProcessRunId, Action: string(r.Action),
		Assertion: r.Assertion, ExpectedEpoch: r.ExpectedEpoch, Deployment: r.Deployment,
		Audience: c.ServerURL() + "/v1/publisher/runtimes/" + r.PublisherIdentityId + "/" + string(r.Action), SourceIP: "8.8.8.8", Now: time.Now(),
	})
	if err != nil {
		return result, err
	}
	data, err := json.Marshal(response)
	if err != nil {
		return result, err
	}
	err = json.Unmarshal(data, &result)
	return result, err
}

func (c deploymentAssignmentPollControl) Assignments(ctx context.Context, token string) (result controlv1.DeploymentPublisherAssignments, err error) {
	assignments, err := c.d.GetDeploymentPublisherAssignments(ctx, token, time.Now())
	if err != nil {
		return result, err
	}
	data, err := json.Marshal(assignments)
	if err != nil {
		return result, err
	}
	err = json.Unmarshal(data, &result)
	return result, err
}

func (c deploymentAssignmentPollControl) Acknowledge(ctx context.Context, token string, ack controlv1.DeploymentPublisherAcknowledgement) error {
	if err := c.d.AcknowledgeDeploymentPublisherConfiguration(ctx, token, ack.Revision, ack.ConfigurationHash, ack.Healthy, time.Now()); err != nil {
		return err
	}
	select {
	case c.acks <- ack:
	default:
	}
	return nil
}

func TestIntegrationDeploymentPublicURLWorkerSurvivesAssignmentPolls(t *testing.T) {
	d, now, _, _ := newPublishRunPrerequisites(t)
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	request := appliedProjectRequest(t, d, now)
	request.Configuration = ProjectConfiguration{Settings: &DeploymentSettings{}, Services: map[string]ProjectServiceConfiguration{
		"web": {Target: "https://web.internal:3000", PublicURL: &ProjectServicePublicURL{}, TargetTLS: &ProjectTargetTLS{Hostname: "web.internal"}},
		"api": {Target: "http://api.internal:3000", PublicURL: &ProjectServicePublicURL{}},
	}}
	request = selectedProjectRequest(request, "production")
	applied, err := d.ApplyProjectConfiguration(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	enrollment, err := testDeploymentPublisherEnrollment(d, ctx, request.TeamID, request.ProjectKey, "production", request.ActorID, 1, time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	replica := enrollAppliedDeployment(t, d, request, enrollment, now)
	poll := deploymentAssignmentPollControl{d: d, acks: make(chan controlv1.DeploymentPublisherAcknowledgement, 32)}
	initial, err := poll.Assignments(ctx, replica.lease.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	type event struct {
		start      bool
		assignment controlv1.DeploymentPublisherServiceAssignment
	}
	events, done := make(chan event, 16), make(chan error, 1)
	go func() {
		done <- (publisherdeployment.Runtime{Control: poll, Member: initial.Member, Private: replica.private, PollInterval: time.Millisecond,
			Publish: func(ctx context.Context, assignment controlv1.DeploymentPublisherServiceAssignment, health func(bool)) error {
				health(true)
				events <- event{true, assignment}
				<-ctx.Done()
				events <- event{false, assignment}
				return ctx.Err()
			},
		}).Serve(ctx)
	}()
	defer func() {
		cancel()
		if err := <-done; err != nil {
			t.Error("native deployment runtime failed", err)
		}
	}()
	next := func() event {
		t.Helper()
		select {
		case value := <-events:
			return value
		case <-ctx.Done():
			t.Fatal("native worker boundary did not complete", context.Cause(ctx))
			return event{}
		}
	}
	bindings := map[string]controlv1.DeploymentPublisherServiceAssignment{}
	for range 2 {
		first := next()
		if !first.start || bindings[first.assignment.Service].ServiceId != "" {
			t.Fatal("public URL workers did not start independently")
		}
		bindings[first.assignment.Service] = first.assignment
	}
	steady := func() {
		t.Helper()
		// observe fresh acknowledgements after run creation, not earlier polls.
		for len(poll.acks) > 0 {
			<-poll.acks
		}
		for polls := 0; polls < 3; {
			select {
			case ack := <-poll.acks:
				if ack.Healthy {
					polls++
				}
			case unexpected := <-events:
				t.Fatal("healthy public URL worker restarted without a binding change", unexpected)
			case <-ctx.Done():
				t.Fatal("native assignments did not remain healthy", context.Cause(ctx))
			}
		}
		select {
		case unexpected := <-events:
			t.Fatal("steady polling replaced a public URL worker", unexpected)
		default:
		}
	}
	configuration := request.Configuration.Services["web"]
	var active PublishRunSetup
	var activeAccess PublisherAccess
	for _, change := range []string{"initial", "target", "trust", "policy"} {
		if change != "initial" {
			previous := bindings["web"]
			switch change {
			case "target":
				configuration.Target = "https://replacement.internal:3000"
			case "trust":
				configuration.TargetTLS = &ProjectTargetTLS{Hostname: "replacement.internal"}
			case "policy":
				configuration.PublicURL = &ProjectServicePublicURL{Access: &ProjectPublicAccess{Mode: "anonymous"}}
			}
			request.ExpectedRevision = applied.Revision
			request.Now = time.Now()
			request.Configuration.Services["web"] = configuration
			applied, err = d.ApplyProjectConfiguration(ctx, request)
			if err != nil {
				t.Fatal("binding mutation failed", change, err)
			}
			closed, err := controlstatedb.New(d.pool).GetPublishRun(ctx, active.PublishRunID)
			if err != nil || !closed.ClosedAt.Valid || closed.State != "closed" {
				t.Fatal("binding change did not close the previous run", change, err)
			}
			if _, err := d.AuthenticatePublisherAccess(ctx, activeAccess.Token, "", time.Now()); !errors.Is(err, ErrPublisherIdentity) {
				t.Fatal("binding change retained the previous exact grant", change, err)
			}
			stopped, started := next(), next()
			if stopped.start || stopped.assignment.Service != "web" || !reflect.DeepEqual(stopped.assignment, previous) || !started.start || started.assignment.Service != "web" || started.assignment.ServiceId != previous.ServiceId || reflect.DeepEqual(started.assignment, previous) {
				t.Fatal("native runtime did not join only the changed canonical binding", change)
			}
			bindings["web"] = started.assignment
		}
		web := bindings["web"]
		stateAssignment := DeploymentPublisherServiceAssignment{ServiceID: web.ServiceId, GrantID: web.GrantId}
		access := deploymentAssignmentAccess(t, d, replica, stateAssignment, time.Now())
		publicURL, err := d.GetPublicURL(ctx, request.ActorID, web.ServiceId)
		if err != nil {
			t.Fatal(err)
		}
		setup, err := d.CreatePublishRun(ctx, reviewRunRequest(t, d, access.PublisherIdentity, replica.private, publicURL, fmt.Sprintf("native-%s", change)), time.Now(), time.Minute, time.Minute)
		if err != nil {
			t.Fatal("assigned exact grant could not start its run", change, err)
		}
		steady()
		if _, err := d.HeartbeatPublishRun(ctx, (publishRunFixture{setup: setup}).authentication(), time.Now(), time.Minute, time.Minute); err != nil {
			t.Fatal("steady assignment polling closed its active run", change, err)
		}
		active, activeAccess = setup, access
	}
}

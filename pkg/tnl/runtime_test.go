package tnl

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/publisher/httpaccess"
	"github.com/tnldotdev/tnl/internal/publisher/identity/publishingtest"
	"github.com/tnldotdev/tnl/internal/testutil"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func preparedSDKOptions(t *testing.T, fixture *publishingtest.Fixture) Options {
	t.Helper()
	enrollment, err := fixture.NamespaceEnrollment(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	options := Options{EnrollmentKey: enrollment, ServerURL: fixture.URL, HTTPClient: fixture.HTTP,
		StateDir: filepath.Join(t.TempDir(), "state"), StateProtection: ProtectionFile}
	identity, err := PreparePublisherIdentity(t.Context(), options)
	if err != nil {
		t.Fatal(err)
	}
	options.EnrollmentKey, options.ServerURL, options.PublisherIdentity = "", "", identity
	return options
}

func awaitSDK[T any](t *testing.T, ctx context.Context, events <-chan T) T {
	t.Helper()
	select {
	case event := <-events:
		return event
	case <-ctx.Done():
		t.Fatal("SDK operation did not complete", context.Cause(ctx))
		var zero T
		return zero
	}
}

func TestOpenConcurrentPublicationsForkOpaquePreparedIdentity(t *testing.T) {
	if !testutil.IsolatedPublishingTest(t) {
		return
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	atReady, releaseReady := make(chan testutil.PublishingRun, 2), make(chan struct{})
	release := sync.OnceFunc(func() { close(releaseReady) })
	fixture := publishingtest.New(t, testutil.PublishingHooks{Ready: func(ctx context.Context, run testutil.PublishingRun) error {
		atReady <- run
		select {
		case <-releaseReady:
			return nil
		case <-ctx.Done():
			return context.Cause(ctx)
		}
	}})
	options := preparedSDKOptions(t, fixture)
	type result struct {
		index  int
		tunnel *Tunnel
		err    error
	}
	results := make(chan result, 2)
	var tunnels [2]*Tunnel
	var handlers [2]atomic.Int32
	var openings sync.WaitGroup
	for index := range 2 {
		openings.Go(func() {
			tunnel, err := Open(ctx, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				handlers[index].Add(1)
				_, _ = fmt.Fprintf(w, "handler-%d", index)
			}), options)
			tunnels[index] = tunnel
			results <- result{index, tunnel, err}
		})
	}
	defer func() {
		release()
		cancel()
		openings.Wait()
		for _, tunnel := range tunnels {
			if err := tunnel.Close(); err != nil {
				t.Error("concurrent publication cleanup", err)
			}
		}
	}()
	// both real run owners must reach readiness before either Open can return.
	first, second := awaitSDK(t, ctx, atReady), awaitSDK(t, ctx, atReady)
	if first.Service.Id == second.Service.Id || first.Service.Endpoint.Hostname == second.Service.Endpoint.Hostname ||
		first.Preparation.PublisherIdentityId != second.Preparation.PublisherIdentityId ||
		first.Preparation.PublisherGrantId != second.Preparation.PublisherGrantId ||
		first.Preparation.PublisherKeyId != second.Preparation.PublisherKeyId {
		t.Fatal("concurrent opens shared an allocation or replaced the prepared signing identity")
	}
	release()
	for range 2 {
		result := awaitSDK(t, ctx, results)
		if result.err != nil || result.tunnel == nil {
			t.Fatal("concurrent Open failed", result.index, result.err)
		}
	}
	openings.Wait()
	var permissions [2]controlv1.VisitorTokenResponse
	for index, tunnel := range tunnels {
		service := tunnel.Service()
		if service.Endpoint == nil || service.Endpoint.Port != 443 || !service.Endpoint.Public || !service.Ephemeral {
			t.Fatal("concurrent Open lost its ordinary shared-443 endpoint")
		}
		status, _, err := fixture.Visit(ctx, tunnel.URL())
		if err != nil || status >= 200 && status < 300 || handlers[index].Load() != 0 {
			t.Fatal("prepared publisher identity granted anonymous visitor access", status, err)
		}
		permissions[index], err = fixture.OwnerVisitorToken(ctx, service.Id)
		if err != nil {
			t.Fatal(err)
		}
	}
	for index, tunnel := range tunnels {
		status, _, body, err := fixture.VisitWithHeaders(ctx, tunnel.URL(), http.Header{httpaccess.VisitorTokenHeader: {permissions[index].VisitorToken}})
		if err != nil || status != http.StatusOK || string(body) != fmt.Sprintf("handler-%d", index) || handlers[index].Load() != 1 {
			t.Fatal("concurrent publication selected another handler", index, status, string(body), err)
		}
		status, _, _, err = fixture.VisitWithHeaders(ctx, tunnel.URL(), http.Header{httpaccess.VisitorTokenHeader: {permissions[1-index].VisitorToken}})
		if err != nil || status >= 200 && status < 300 || handlers[index].Load() != 1 {
			t.Fatal("another invocation's visitor permission crossed service scope", index, status, err)
		}
	}
	firstID, secondID := tunnels[0].Service().Id, tunnels[1].Service().Id
	if err := tunnels[0].Close(); err != nil {
		t.Fatal(err)
	}
	if err := tunnels[0].Close(); err != nil || !slices.Equal(fixture.DeletedIDs(), []string{firstID}) {
		t.Fatal("repeated Close deleted another invocation", err, fixture.DeletedIDs())
	}
	status, _, body, err := fixture.VisitWithHeaders(ctx, tunnels[1].URL(), http.Header{httpaccess.VisitorTokenHeader: {permissions[1].VisitorToken}})
	if err != nil || status != http.StatusOK || string(body) != "handler-1" {
		t.Fatal("closing one invocation stopped its sibling", status, err)
	}
	if err := tunnels[1].Close(); err != nil {
		t.Fatal(err)
	}
	deleted := fixture.DeletedIDs()
	slices.Sort(deleted)
	expected := []string{firstID, secondID}
	slices.Sort(expected)
	if !slices.Equal(deleted, expected) || fixture.Enrollments.Load() != 1 || fixture.Allocations.Load() != 2 || fixture.Runs.Load() != 2 {
		t.Fatal("concurrent SDK cleanup changed allocation or identity ownership", deleted)
	}
}

func TestOpenTotalBudgetWaitJoinsFinalLoopbackResponse(t *testing.T) {
	if !testutil.IsolatedPublishingTest(t) {
		return
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	fixture := publishingtest.New(t, testutil.PublishingHooks{})
	options := preparedSDKOptions(t, fixture)
	options.Limits.Requests = 1
	entered, returned, finish := make(chan struct{}), make(chan struct{}), make(chan struct{})
	release := sync.OnceFunc(func() { close(finish) })
	defer release()
	var requests atomic.Int32
	tunnel, err := Open(ctx, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer close(returned)
		requests.Add(1)
		address, ok := r.Context().Value(http.LocalAddrContextKey).(net.Addr)
		if !ok {
			t.Error("SDK handler has no owned HTTP listener address")
			return
		}
		host, _, err := net.SplitHostPort(address.String())
		if err != nil || host != "127.0.0.1" || r.TLS != nil {
			t.Error("SDK handler was moved out of its owned HTTP loopback listener", address, err)
		}
		_, _ = io.WriteString(w, "first")
		if err := http.NewResponseController(w).Flush(); err != nil {
			t.Error(err)
		}
		close(entered)
		<-finish
		_, _ = io.WriteString(w, "-last")
	}), options)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { release(); cancel(); _ = tunnel.Close() }()
	for _, visit := range []struct {
		path    string
		headers http.Header
	}{
		{path: "/"},
		{path: "/", headers: http.Header{"Authorization": {"Bearer " + fixture.OwnerToken}}},
		{path: "/", headers: http.Header{httpaccess.VisitorTokenHeader: {"invalid-token"}}},
		{path: "/__tnl/missing"},
	} {
		status, _, _, err := fixture.VisitWithHeaders(ctx, tunnel.URL()+visit.path, visit.headers)
		if err != nil || status >= 200 && status < 300 || requests.Load() != 0 {
			t.Fatal("internal or rejected work reached the SDK handler", visit.path, status, err)
		}
		select {
		case <-tunnel.done:
			t.Fatal("rejected visitor work spent the application request total", tunnel.Wait())
		default:
		}
	}
	permission, err := fixture.OwnerVisitorToken(ctx, tunnel.Service().Id)
	if err != nil {
		t.Fatal(err)
	}
	type response struct {
		status int
		body   []byte
		err    error
	}
	replied := make(chan response, 1)
	go func() {
		status, _, body, err := fixture.VisitWithHeaders(ctx, tunnel.URL(), http.Header{httpaccess.VisitorTokenHeader: {permission.VisitorToken}})
		replied <- response{status, body, err}
	}()
	awaitSDK(t, ctx, entered)
	select {
	case <-tunnel.done:
		t.Fatal("Tunnel.Wait finished before its final application response")
	default:
	}
	release()
	reply := awaitSDK(t, ctx, replied)
	if reply.err != nil || reply.status != http.StatusOK || string(reply.body) != "first-last" {
		t.Fatal("normal budget completion cut off the final SDK response", reply.status, string(reply.body), reply.err)
	}
	awaitSDK(t, ctx, tunnel.done)
	if err := tunnel.Wait(); err != nil || ctx.Err() != nil {
		t.Fatal("total-budget completion needed cancellation or failed", err, context.Cause(ctx))
	}
	select {
	case <-returned:
	default:
		t.Fatal("Tunnel.Wait left a local application handler running")
	}
	if err := tunnel.Close(); err != nil || requests.Load() != 1 ||
		!slices.Equal(fixture.DeletedIDs(), []string{tunnel.Service().Id}) {
		t.Fatal("normal completion did not join and remove the exact allocation", err, fixture.DeletedIDs())
	}
}

func TestOpenRestrictedVisitorCredentialsStaySeparate(t *testing.T) {
	if !testutil.IsolatedPublishingTest(t) {
		return
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	fixture := publishingtest.New(t, testutil.PublishingHooks{})
	options := preparedSDKOptions(t, fixture)
	var requests atomic.Int32
	tunnel, err := Open(ctx, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.Header.Get(httpaccess.VisitorTokenHeader) != "" || strings.Contains(r.Header.Get("Cookie"), "__Host-tnl-") {
			t.Error("SDK handler received visitor credentials")
		}
		_, _ = io.WriteString(w, "restricted handler")
	}), options)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { cancel(); _ = tunnel.Close() }()
	for _, headers := range []http.Header{nil, {"Authorization": {"Bearer " + fixture.OwnerToken}}} {
		status, _, _, err := fixture.VisitWithHeaders(ctx, tunnel.URL(), headers)
		if err != nil || status >= 200 && status < 300 || requests.Load() != 0 {
			t.Fatal("control or publisher identity substituted for visitor permission", status, err)
		}
	}
	permission, err := fixture.OwnerVisitorToken(ctx, tunnel.Service().Id)
	if err != nil {
		t.Fatal(err)
	}
	status, _, body, err := fixture.VisitWithHeaders(ctx, tunnel.URL(), http.Header{httpaccess.VisitorTokenHeader: {permission.VisitorToken}})
	if err != nil || status != http.StatusOK || string(body) != "restricted handler" {
		t.Fatal("owner visitor permission did not reach the SDK handler", status, err)
	}
	owner, err := fixture.Owner()
	if err != nil {
		t.Fatal(err)
	}
	grant, err := owner.CreateServiceHTTPGrant(ctx, tunnel.Service().Id, controlv1.CreateVisitorCredentialRequest{
		Kind: controlv1.CreateVisitorCredentialRequestKind("token"), ExpiresAt: time.Now().Add(time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	status, _, _, err = fixture.VisitWithHeaders(ctx, tunnel.URL(), http.Header{httpaccess.VisitorTokenHeader: {grant.RefreshCredential}})
	if err != nil || status >= 200 && status < 300 || requests.Load() != 1 {
		t.Fatal("a refresh credential became a visitor token", status, err)
	}
	status, _, _, err = fixture.VisitWithHeaders(ctx, tunnel.URL(), http.Header{httpaccess.VisitorTokenHeader: {grant.Permission.VisitorToken}})
	if err != nil || status != http.StatusOK || requests.Load() != 2 {
		t.Fatal("explicit service visitor token was not admitted", status, err)
	}
	ticket := fixture.BrowserHandoff(tunnel.Service().Id)
	status, headers, _, err := fixture.VisitWithHeaders(ctx, tunnel.URL()+"/__tnl/team/handoff/"+ticket, nil)
	if err != nil || status != http.StatusSeeOther || requests.Load() != 2 {
		t.Fatal("browser handoff reached the app instead of preparing visitor access", status, err)
	}
	var cookies []string
	for _, cookie := range (&http.Response{Header: headers}).Cookies() {
		if cookie.Value != "" {
			cookies = append(cookies, cookie.Name+"="+cookie.Value)
		}
	}
	if len(cookies) == 0 {
		t.Fatal("browser handoff installed no visitor cookies")
	}
	status, _, _, err = fixture.VisitWithHeaders(ctx, tunnel.URL(), http.Header{"Cookie": {strings.Join(cookies, "; ")}})
	if err != nil || status != http.StatusOK || requests.Load() != 3 {
		t.Fatal("browser visitor permission did not reach the SDK handler", status, err)
	}
	if err := tunnel.Close(); err != nil || !slices.Equal(fixture.DeletedIDs(), []string{tunnel.Service().Id}) {
		t.Fatal("restricted SDK publication did not clean up", err, fixture.DeletedIDs())
	}
}

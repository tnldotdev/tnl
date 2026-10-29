package main

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/client/project/resolve"
)

func TestIntegrationCLIWorkflowPreparesVisitorPolicyBeforeIssuance(t *testing.T) {
	if !cliWorkflowInChild(t) {
		return
	}
	f := newCLIWorkflow(t)
	connection, err := pgx.Connect(t.Context(), f.databaseURL)
	if err != nil {
		t.Fatal("workflow policy database connection failed")
	}
	defer connection.Close(context.Background())
	// constructing the fixture must prepare anonymous policy reads without a
	// first login, visitor token, allocation, or publisher readiness override.
	var issuer, key, emptyRetentions bool
	if err := connection.QueryRow(t.Context(), `SELECT
	    EXISTS(SELECT 1 FROM control.visitor_token_issuer WHERE issuer=$1),
	    EXISTS(SELECT 1 FROM control.visitor_token_keys WHERE retired_at IS NULL AND octet_length(public_key)=32),
	    NOT EXISTS(SELECT 1 FROM control.visitor_token_keys WHERE retain_until>created_at)`, f.url).Scan(&issuer, &key, &emptyRetentions); err != nil {
		t.Fatal("workflow policy startup facts could not be read")
	}
	if !issuer || !key || !emptyRetentions {
		t.Fatal("workflow startup did not prepare its issuer and verification key independently of visitor issuance")
	}
}

func TestIntegrationCLIWorkflowForwardsPreparedVisitorReservation(t *testing.T) {
	if !cliWorkflowInChild(t) {
		return
	}
	f := newCLIWorkflow(t)
	person := f.state(t, "prepared-visitor")
	f.loginPerson(t, person)
	session, err := openTeamSession(t.Context(), remoteFlags{ServerURL: f.url, StateDir: person}, "prepared visitor workflow", io.Discard)
	if err != nil {
		t.Fatal("workflow team session failed")
	}
	defer session.Close()
	current, err := session.CurrentWithDomains(t.Context())
	if err != nil {
		t.Fatal("workflow team domain selection failed")
	}
	hostname, _, _, err := resolve.PublishHostname("", "prepared", "", current)
	if err != nil {
		t.Fatal("workflow public hostname selection failed")
	}
	var applicationRequests atomic.Int64
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/prepared-visitor" {
			applicationRequests.Add(1)
		}
		_, _ = io.WriteString(w, "prepared visitor reached the app")
	}))
	t.Cleanup(target.Close)
	publisherCtx, stopPublisher := context.WithCancel(t.Context())
	f.command(t, publisherCtx, stopPublisher, []string{"--no-config", "publish", target.URL, "--name", "prepared", "--anonymous", "--foreground", "--team", session.Identity().PersonalTeamId, "--server", f.url, "--state-dir", person})
	visitor := &http.Client{Transport: http.DefaultTransport, Timeout: 2 * time.Second}
	// a successful public application GET must pass the publisher's existing
	// exact-run reservation checks; a raw routing entry cannot satisfy them.
	workflowWait(t, 25*time.Second, func() bool {
		response, err := visitor.Get("https://" + hostname + "/prepared-visitor")
		if err != nil {
			return false
		}
		defer response.Body.Close()
		body, err := io.ReadAll(response.Body)
		return err == nil && response.StatusCode == http.StatusOK && string(body) == "prepared visitor reached the app"
	})
	if applicationRequests.Load() == 0 {
		t.Fatal("workflow public visitor did not reach the application")
	}
	connection, err := pgx.Connect(t.Context(), f.databaseURL)
	if err != nil {
		t.Fatal("workflow allocation database connection failed")
	}
	defer connection.Close(context.Background())
	// require positive preparation evidence for this hostname's exact live run,
	// not just a ready event or an empty query without an error.
	var observed bool
	if err := connection.QueryRow(t.Context(), `SELECT EXISTS (
	    SELECT 1 FROM control.stream_capacity_allocations a
	    JOIN control.publish_runs r ON r.id=a.run_id AND r.public_url_id=a.resource_id AND r.publish_run_number=a.run_number
	    JOIN control.public_urls u ON u.id=r.public_url_id
	    WHERE u.canonical_hostname=$1 AND a.resource_kind='public_url'
	        AND r.closed_at IS NULL AND a.retired_at IS NULL
	        AND a.valid_until>clock_timestamp() AND a.publisher_observed_at IS NOT NULL
	)`, hostname).Scan(&observed); err != nil {
		t.Fatal("workflow prepared allocation facts could not be read")
	}
	if !observed {
		t.Fatal("workflow visitor had no current publisher-observed exact-run allocation")
	}
}

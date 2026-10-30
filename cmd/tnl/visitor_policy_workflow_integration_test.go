package main

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5"
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

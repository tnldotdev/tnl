package controlstate

import (
	"errors"
	"testing"
	"time"
)

func TestIntegrationDatabasePublicURLClaimsPortWithCreation(t *testing.T) {
	database, now := newControlStateIntegrationDatabase(t, "database_public_url")
	request := builtinRouteRequest(t, database, now)
	if err := database.EnsurePrimaryIngressPool(t.Context(), "192.0.2.10", "", []int32{5432}, now); err != nil {
		t.Fatal(err)
	}
	request.Target, request.ServiceProtocol = "", PublicURLServicePostgres
	first, err := database.CreatePublicURL(t.Context(), request, now)
	if err != nil || first.ServiceProtocol != PublicURLServicePostgres || first.Target != "" || first.PublicPort == nil || *first.PublicPort != 5432 {
		t.Fatalf("saved PostgreSQL address = %#v, %v", first, err)
	}
	repeated, err := database.CreatePublicURL(t.Context(), request, now.Add(time.Minute))
	if err != nil || repeated.PublicPort == nil || *repeated.PublicPort != 5432 || repeated.ID != first.ID {
		t.Fatalf("idempotent address = %#v, %v", repeated, err)
	}
	second := request
	second.IdempotencyKey = "second-db-endpoint"
	second.CanonicalHostname = "other." + request.CanonicalHostname
	if _, err := database.CreatePublicURL(t.Context(), second, now); !errors.Is(err, ErrTCPPortPoolFull) {
		t.Fatalf("exhausted pool saved an unusable URL: %v", err)
	}
	var count int
	if err := database.pool.QueryRow(t.Context(), `SELECT count(*) FROM control.public_urls WHERE canonical_hostname = $1`, second.CanonicalHostname).Scan(&count); err != nil || count != 0 {
		t.Fatalf("failed allocation left a saved URL: count=%d err=%v", count, err)
	}
	if err := database.EnsurePrimaryIngressPool(t.Context(), "192.0.2.10", "", []int32{5432, 15432}, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	created, err := database.CreatePublicURL(t.Context(), second, now.Add(time.Hour))
	if err != nil || created.PublicPort == nil || *created.PublicPort != 15432 {
		t.Fatalf("expanded pool address = %#v, %v", created, err)
	}
	if err := database.EnsurePrimaryIngressPool(t.Context(), "192.0.2.10", "", []int32{5432, 15432, 3306}, now.Add(2*time.Hour)); err != nil {
		t.Fatal(err)
	}
	mysql := request
	mysql.IdempotencyKey, mysql.CanonicalHostname, mysql.ServiceProtocol = "mysql-endpoint", "mysql."+request.CanonicalHostname, PublicURLServiceMySQL
	mysqlURL, err := database.CreatePublicURL(t.Context(), mysql, now.Add(2*time.Hour))
	if err != nil || mysqlURL.ServiceProtocol != PublicURLServiceMySQL || mysqlURL.PublicPort == nil || *mysqlURL.PublicPort != 3306 {
		t.Fatalf("saved MySQL address = %#v, %v", mysqlURL, err)
	}
	if err := database.EnsurePrimaryIngressPool(t.Context(), "192.0.2.10", "", []int32{5432, 15432, 3306, 6379}, now.Add(3*time.Hour)); err != nil {
		t.Fatal(err)
	}
	redis := request
	redis.IdempotencyKey, redis.CanonicalHostname, redis.ServiceProtocol = "redis-endpoint", "redis."+request.CanonicalHostname, PublicURLServiceRedis
	redisURL, err := database.CreatePublicURL(t.Context(), redis, now.Add(3*time.Hour))
	if err != nil || redisURL.ServiceProtocol != PublicURLServiceRedis || redisURL.Target != "" || redisURL.PublicPort == nil || *redisURL.PublicPort != 6379 {
		t.Fatalf("saved Redis address = %#v, %v", redisURL, err)
	}
	if err := database.EnsurePrimaryIngressPool(t.Context(), "192.0.2.10", "", []int32{5432, 15432, 3306, 6379, 2222}, now.Add(4*time.Hour)); err != nil {
		t.Fatal(err)
	}
	ssh := request
	ssh.IdempotencyKey, ssh.CanonicalHostname, ssh.ServiceProtocol = "ssh-endpoint", "ssh."+request.CanonicalHostname, PublicURLServiceSSH
	ssh.SSHHostKey = testSSHHostKey(t, 1)
	sshURL, err := database.CreatePublicURL(t.Context(), ssh, now.Add(4*time.Hour))
	if err != nil || sshURL.ServiceProtocol != PublicURLServiceSSH || sshURL.Target != "" || sshURL.PublicPort == nil || *sshURL.PublicPort != 2222 || sshURL.SSHHostKey != ssh.SSHHostKey || sshURL.AccessMode != VisitorAccessRestricted {
		t.Fatalf("saved SSH address = %#v, %v", sshURL, err)
	}
	retriedSSH, err := database.CreatePublicURL(t.Context(), ssh, now.Add(4*time.Hour+time.Minute))
	if err != nil || retriedSSH.ID != sshURL.ID || retriedSSH.SSHHostKey != ssh.SSHHostKey || retriedSSH.PublicPort == nil || *retriedSSH.PublicPort != 2222 {
		t.Fatalf("idempotent SSH address = %#v, %v", retriedSSH, err)
	}
	ssh.SSHHostKey = testSSHHostKey(t, 2)
	if _, err := database.CreatePublicURL(t.Context(), ssh, now.Add(4*time.Hour+2*time.Minute)); !errors.Is(err, ErrPublicURLIdempotency) {
		t.Fatalf("idempotent SSH key replacement = %v", err)
	}
	loadedSSH, err := database.GetPublicURL(t.Context(), ssh.ActingIdentityID, sshURL.ID)
	if err != nil || loadedSSH.SSHHostKey != sshURL.SSHHostKey {
		t.Fatalf("loaded SSH key = %q, %v", loadedSSH.SSHHostKey, err)
	}
	page, err := database.ListAuthorizedPublicURLs(t.Context(), ssh.TeamID, "")
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, url := range page.PublicURLs {
		if url.ID == sshURL.ID {
			found = true
			if url.SSHHostKey != sshURL.SSHHostKey {
				t.Fatal("listed SSH host key changed")
			}
		}
	}
	if !found {
		t.Fatal("SSH public URL missing from list")
	}
	update := AuthorizedPublicURLUpdateRequest{
		PublicURLID: sshURL.ID, TeamID: sshURL.TeamID, ActingIdentityID: ssh.ActingIdentityID,
		AllowedIPPrefixes: []string{}, PolicyRevision: uint64(sshURL.PolicyRevision), ExpectedMutationRevision: sshURL.MutationRevision,
	}
	updatedSSH, err := database.UpdateAuthorizedPublicURL(t.Context(), update, now.Add(5*time.Hour))
	if err != nil || updatedSSH.Target != "" || updatedSSH.SSHHostKey != sshURL.SSHHostKey {
		t.Fatalf("updated SSH shape = %#v, %v", updatedSSH, err)
	}
	update.Target, update.ExpectedMutationRevision = "http://127.0.0.1:22", updatedSSH.MutationRevision
	if _, err := database.UpdateAuthorizedPublicURL(t.Context(), update, now.Add(5*time.Hour+time.Minute)); !errors.Is(err, ErrPublicURLInvalid) {
		t.Fatalf("SSH private target mutation = %v", err)
	}
}

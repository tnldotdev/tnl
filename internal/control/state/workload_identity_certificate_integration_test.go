package state

import (
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/policy/visitorlease"
	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	"github.com/tnldotdev/tnl/internal/security/visitorcert"
	"github.com/tnldotdev/tnl/internal/security/visitortoken"
)

func TestIntegrationWorkloadIdentityCertificateUsesCurrentControlPermission(t *testing.T) {
	for _, terminal := range []string{"provider expiry", "selection removal", "revocation"} {
		t.Run(terminal, func(t *testing.T) {
			d, now := newControlStateIntegrationDatabase(t, "workload_identity")
			request := appliedProjectRequest(t, d, now)
			request.Configuration = workloadConfiguration()
			request = selectedProjectRequest(request, "production")
			policy := request.Configuration.Workloads["test"]
			policy.MaxDurationSeconds = 0
			request.Configuration.Workloads["test"] = policy
			applied, err := d.ApplyProjectConfiguration(t.Context(), request)
			if err != nil {
				t.Fatal(err)
			}
			exchange, key := workloadExchange(t, request, now)
			session, err := d.ExchangeWorkload(t.Context(), exchange, now)
			if err != nil || session.ExpiresAt != nil {
				t.Fatal("uncapped workload exchange", err)
			}
			service := ""
			for _, saved := range applied.Services {
				if saved.Service == "api" {
					service = saved.ServiceID
				}
			}
			scope := visitorscope.Scope{Kind: visitorscope.Service, ID: service}
			csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
			if err != nil {
				t.Fatal(err)
			}
			issued, err := d.IssueVisitorClientCertificate(t.Context(), testVisitorIssuer, scope, WorkloadTokenSource{Credential: session.Credential}, csr, now)
			if err != nil || !issued.ExpiresAt.Equal(now.Add(visitorcert.MaxWorkloadLifetime).Truncate(time.Second)) {
				t.Fatal("uncapped identity did not use the existing native credential lifetime", err)
			}
			block, _ := pem.Decode([]byte(issued.CertificatePEM))
			leaf, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				t.Fatal(err)
			}
			token, err := visitortoken.CertificateToken(leaf)
			if err != nil {
				t.Fatal(err)
			}
			client := tls.ConnectionState{HandshakeComplete: true, PeerCertificates: []*x509.Certificate{leaf}}
			read := func(at time.Time) visitortoken.View {
				t.Helper()
				tx, err := d.pool.BeginTx(t.Context(), pgx.TxOptions{IsoLevel: pgx.RepeatableRead})
				if err != nil {
					t.Fatal(err)
				}
				defer tx.Rollback(t.Context())
				wire, err := d.readVisitorPolicy(t.Context(), tx, scope, 0, at)
				if err != nil {
					t.Fatal(err)
				}
				if err := tx.Commit(t.Context()); err != nil {
					t.Fatal(err)
				}
				update, err := visitorlease.Decode(wire)
				if err != nil {
					t.Fatal(err)
				}
				return update.View
			}
			first, err := visitortoken.VerifyCertificate(token, read(now), client, now)
			if err != nil || !first.Facts().ExpiresAt.Equal(session.LeaseExpiresAt) {
				t.Fatal("fixed identity did not require actual current workload permission", err)
			}
			identity, ok := first.WorkloadPermission()
			if !ok {
				t.Fatal("new identity profile was not explicitly typed")
			}
			var retained time.Time
			if err := d.pool.QueryRow(t.Context(), `SELECT retain_until FROM control.visitor_token_keys WHERE id=$1`,
				first.Facts().SigningKeyID).Scan(&retained); err != nil || retained.Before(leaf.NotAfter) {
				t.Fatal("identity signing key was not retained to the actual certificate expiry", err)
			}
			if err := d.RotateVisitorSigningKey(t.Context(), testVisitorIssuer, false, now.Add(time.Second)); err != nil {
				t.Fatal(err)
			}
			current := session
			for round := 1; round <= 9; round++ {
				at := now.Add(time.Duration(round) * 30 * time.Second)
				current, err = d.RenewWorkloadSession(t.Context(), current.ID, current.Credential, signWorkloadRenewal(current, key), at)
				if err != nil || current.ID != session.ID {
					t.Fatal("renew same workload", err)
				}
				permission, err := visitortoken.VerifyCertificate(token, read(at), client, at)
				if err != nil || permission.Facts().ExpiresAt.After(current.LeaseExpiresAt) ||
					permission.Facts().ExpiresAt.After(current.IdentityExpiresAt) {
					t.Fatal("current permission escaped its actual workload/provider bounds", err)
				}
				got, ok := permission.WorkloadPermission()
				if !ok || got.Identity() != identity.Identity() {
					t.Fatal("renewal or ordinary signing-key rotation changed original certificate identity")
				}
			}
			at := session.IdentityExpiresAt
			switch terminal {
			case "selection removal":
				at = now.Add(280 * time.Second)
				policy.Services = []string{"db"}
				request.Configuration.Workloads["test"] = policy
				request.ExpectedRevision, request.Now = applied.Revision, at
				if _, err := d.ApplyProjectConfiguration(t.Context(), request); err != nil {
					t.Fatal(err)
				}
			case "revocation":
				at = now.Add(280 * time.Second)
				if err := d.RevokeWorkloadSession(t.Context(), session.ID, session.Credential, at); err != nil {
					t.Fatal(err)
				}
			}
			if !at.Before(leaf.NotAfter) {
				t.Fatal("test did not distinguish current permission from certificate expiry")
			}
			if _, err := visitortoken.VerifyCertificate(token, read(at), client, at); err == nil {
				t.Fatal("valid fixed credential bypassed actual terminal control authority", terminal)
			}
		})
	}
}

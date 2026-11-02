package publisher_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/publisher"
	"github.com/tnldotdev/tnl/internal/testutil"
)

func TestIntegrationManagedPostgresConnectorCredentialLifetime(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	for _, renew := range []bool{false, true} {
		name := "original-credential-decision-expires"
		if renew {
			name = "original-subject-decision-renews"
		}
		t.Run(name, func(t *testing.T) {
			server, certificates := postgresManagedFixture(t)
			replacement := serviceCertificates(t).client
			var originalDeadline atomic.Int64
			var originalChecks, replacementChecks atomic.Int64
			server.Visitor = publisher.CertificateVisitor{Check: func(_ context.Context, leaf *x509.Certificate) (publisher.ServiceVisitorDecision, error) {
				switch {
				case bytes.Equal(leaf.Raw, certificates.client.Certificate[0]):
					originalDeadline.CompareAndSwap(0, time.Now().Add(1200*time.Millisecond).UnixNano())
					originalChecks.Add(1)
					until := time.Unix(0, originalDeadline.Load())
					if renew {
						until = time.Now().Add(1200 * time.Millisecond)
					}
					return publisher.ServiceVisitorDecision{Allowed: true, ValidUntil: until}, nil
				case bytes.Equal(leaf.Raw, replacement.Certificate[0]):
					replacementChecks.Add(1)
					return publisher.ServiceVisitorDecision{Allowed: true, ValidUntil: time.Now().Add(time.Minute)}, nil
				default:
					return publisher.ServiceVisitorDecision{}, publisher.ErrEndpoint
				}
			}}
			address := managedIngressListener(t, server)
			verification := &tls.Config{RootCAs: certificates.roots, ServerName: server.Hostname, Certificates: []tls.Certificate{certificates.client}, MinVersion: tls.VersionTLS12}
			original := managedPGConnect(t, address, verification)
			pid := original.PgConn().PID()
			if _, err := original.Exec(t.Context(), "CREATE TEMP TABLE original_session(value int); INSERT INTO original_session VALUES (42)"); err != nil {
				t.Fatal(err)
			}
			// a new credential now selects another subject for new connections.
			// a live stream must continue checking its original TLS leaf instead.
			verification = verification.Clone()
			verification.Certificates = []tls.Certificate{replacement}
			current := managedPGConnect(t, address, verification)
			checksBeforeReplacement := originalChecks.Load()
			time.Sleep(time.Until(time.Unix(0, originalDeadline.Load())) + 200*time.Millisecond)
			var value int
			err := original.QueryRow(t.Context(), "SELECT value FROM original_session").Scan(&value)
			if renew {
				if err != nil || value != 42 || original.PgConn().PID() != pid {
					t.Fatal("renewal replaced or closed the original selected session", value, err)
				}
			} else if err == nil {
				t.Fatal("new credential prolonged an expired original session")
			}
			if err := current.QueryRow(t.Context(), "SELECT 1").Scan(&value); err != nil || value != 1 {
				t.Fatal("original expiry damaged the replacement subject's session", err)
			}
			if originalChecks.Load() <= checksBeforeReplacement || replacementChecks.Load() != 1 {
				t.Fatal("native lifetime did not recheck the fixed original subject")
			}
			t.Log("native PostgreSQL over ingress and both TLS legs: original leaf rechecked; replacement credential isolated; renewal retains backend PID and temporary session state")
		})
	}
}

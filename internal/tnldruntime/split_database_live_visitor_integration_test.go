package tnldruntime

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/opaqueid"
	"github.com/tnldotdev/tnl/internal/proxyproto"
	"github.com/tnldotdev/tnl/internal/testutil"
	"github.com/tnldotdev/tnl/internal/tnldconfig"
	"github.com/tnldotdev/tnl/internal/visitorcert"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func TestIntegrationSplitDatabaseLiveVisitorRevocation(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	for _, mode := range []controlv1.VisitorAccessMode{controlv1.Restricted, controlv1.Anonymous} {
		t.Run(string(mode), func(t *testing.T) {
			seed := make([]byte, 32)
			f := newSplitPublishFixtureWithOptions(t, "live-db", splitPublishOptions{proxyIngress: true, configureProcess: func(c *tnldconfig.Config) {
				if c.Role == tnldconfig.RoleControl {
					c.VisitorIssuerSeed = base64.RawURLEncoding.EncodeToString(seed)
				}
				if c.Role == tnldconfig.RoleIngress {
					c.RequireProxyHeader = true
				}
			}})
			_, portText, err := net.SplitHostPort(unusedTCPAddress(t))
			if err != nil {
				t.Fatal(err)
			}
			port, err := strconv.ParseUint(portText, 10, 16)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := f.inspect.ExecContext(t.Context(), `UPDATE control.ingress_pools SET ipv4_address='127.0.0.1'::inet,state='enabled' WHERE id='ingress-a'`); err != nil {
				t.Fatal(err)
			}
			if _, err := f.inspect.ExecContext(t.Context(), `INSERT INTO control.ingress_pool_ports(ingress_pool_id,port,enabled) VALUES ('ingress-a',$1,true)`, port); err != nil {
				t.Fatal(err)
			}
			backend, err := url.Parse(testutil.PostgresURL(t))
			if err != nil {
				t.Fatal(err)
			}
			quic, tcp := f.connectors()
			publication := f.identity.publisherConfig(backend.Host, quic, tcp)
			publication.ServiceProtocol, publication.AccessMode = controlv1.Postgres, mode
			publication.AllowedIPPrefixes = []string{"127.0.0.1/32"}
			handle := startOwnedIntegrationPublisher(t, f.owner, publication, func() string { return integrationPublisherDiagnostics(f.inspect, f.pebble.logPath) })
			ready := waitForPublisherReady(t, handle)
			waitForReadyPublisherConnections(t, f.inspect, ready.PublicURLID, ready.PublishRunNumber, 2)
			waitForIngressRoutingCurrent(t, f.inspect, 1)

			config, err := pgx.ParseConfig("postgres://postgres:postgres@" + ready.PublicURL + "/postgres?sslmode=verify-full&channel_binding=disable")
			if err != nil {
				t.Fatal(err)
			}
			config.TLSConfig.RootCAs = f.pebble.roots
			config.Fallbacks = nil
			config.LookupFunc = func(context.Context, string) ([]string, error) { return []string{"127.0.0.1"}, nil }
			config.DialFunc = func(ctx context.Context, _, _ string) (net.Conn, error) {
				c, err := (&net.Dialer{}).DialContext(ctx, "tcp", f.ingressConfig.IngressListen)
				if err != nil {
					return nil, err
				}
				header, err := proxyproto.Encode(proxyproto.Header{Source: netip.MustParseAddrPort("127.0.0.1:40001"), Destination: netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(port))})
				if err == nil {
					_, err = c.Write(header)
				}
				if err != nil {
					_ = c.Close()
					return nil, err
				}
				return c, nil
			}
			var revoke func()
			if mode == controlv1.Restricted {
				// seed a nonmember's accepted identity grant, then use the real
				// control-only issuer and authorization API for its TLS proof.
				identity, err := opaqueid.New(opaqueid.IdentityPrefix)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := f.inspect.ExecContext(t.Context(), `INSERT INTO control.identities(id,kind,display_name,created_at,updated_at) VALUES ($1,'authority','database visitor',now(),now())`, identity); err != nil {
					t.Fatal(err)
				}
				grant := "live-database-identity-grant"
				if _, err := f.inspect.ExecContext(t.Context(), `INSERT INTO control.visitor_grants(id,public_url_id,team_id,kind,identity_id,created_by_identity_id,idempotency_key,request_digest,created_at)
					SELECT $1,id,team_id,'identity',$2,created_by_identity_id,$1,decode(repeat('00',32),'hex'),now() FROM control.public_urls WHERE id=$3`, grant, identity, ready.PublicURLID); err != nil {
					t.Fatal(err)
				}
				config.TLSConfig.Certificates = []tls.Certificate{liveDatabaseVisitorCertificate(t, seed, ready.PublicURLID, identity)}
				revoke = func() {
					if err := f.identity.routes.RevokeVisitorGrant(t.Context(), ready.PublicURLID, grant); err != nil {
						t.Fatal(err)
					}
				}
			} else {
				revoke = func() {
					current, err := f.identity.routes.GetPublicURL(t.Context(), ready.PublicURLID)
					if err != nil {
						t.Fatal(err)
					}
					// replace the allowed source rather than clearing the optional
					// IP filter, which would permit every source.
					if _, err := f.identity.routes.ReplaceVisitorAccess(t.Context(), ready.PublicURLID, controlv1.ReplaceVisitorAccessRequest{
						ExpectedRevision: current.MutationRevision, Mode: mode, Ip: []string{"198.51.100.7/32"},
					}); err != nil {
						t.Fatal(err)
					}
				}
			}
			ctx, cancel := context.WithTimeout(t.Context(), 12*time.Second)
			visitor, err := pgx.ConnectConfig(ctx, config)
			cancel()
			if err != nil {
				t.Fatal(err)
			}
			defer visitor.Close(context.Background())
			var value int
			if err := visitor.QueryRow(t.Context(), "SELECT 42").Scan(&value); err != nil || value != 42 {
				t.Fatalf("established PostgreSQL session: %d, %v", value, err)
			}
			revoke()
			// use the socket directly to observe publisher closure while pgx is
			// idle. querying repeatedly could hide an idle-session watcher bug.
			conn := visitor.PgConn().Conn()
			_ = conn.SetReadDeadline(time.Now().Add(36 * time.Second))
			if n, err := conn.Read(make([]byte, 1)); n != 0 || err == nil {
				t.Fatalf("revoked database session still open: %d, %v", n, err)
			} else if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
				t.Fatalf("live authorization did not close the idle PostgreSQL session: %v", err)
			}
		})
	}
}

func liveDatabaseVisitorCertificate(t *testing.T, seed []byte, urlID, identity string) tls.Certificate {
	t.Helper()
	issuer, err := visitorcert.New(seed)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	certificate, err := issuer.Issue(csr, urlID, identity, now.Add(time.Hour), now)
	if err != nil {
		t.Fatal(err)
	}
	private, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	material, err := tls.X509KeyPair(certificate, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private}))
	if err != nil {
		t.Fatal(err)
	}
	return material
}

package publisher

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	mysql "github.com/go-sql-driver/mysql"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/tnldotdev/tnl/internal/inspection"
	"github.com/tnldotdev/tnl/internal/localproxy"
	"github.com/tnldotdev/tnl/internal/testutil"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func databaseTLSMaterial(t *testing.T, certificate tls.Certificate) (string, string, string) {
	t.Helper()
	key, err := x509.MarshalPKCS8PrivateKey(certificate.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(key)
	var id [8]byte
	if _, err := rand.Read(id[:]); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(id[:]), string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Certificate[0]})), string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}))
}

// the existing task-owned disposable PostgreSQL accepts COPY TO PROGRAM as its
// fixture administrator. install a private key with mode 0600 and reload TLS;
// the container and all files are removed by the normal integration target.
func configurePostgresTLS(t *testing.T, address string, certificate tls.Certificate) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	admin, err := pgx.Connect(ctx, testutil.PostgresURL(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		for _, setting := range []string{"ssl", "ssl_cert_file", "ssl_key_file"} {
			_, _ = admin.Exec(ctx, "ALTER SYSTEM RESET "+setting)
		}
		_, _ = admin.Exec(ctx, "SELECT pg_reload_conf()")
		_ = admin.Close(ctx)
	})
	id, cert, key := databaseTLSMaterial(t, certificate)
	certPath, keyPath := "/tmp/tnl-"+id+".crt", "/tmp/tnl-"+id+".key"
	for path, data := range map[string]string{certPath: cert, keyPath: key} {
		query := fmt.Sprintf("COPY (SELECT unnest(string_to_array(convert_from(decode('%s', 'base64'), 'UTF8'), E'\\n'))) TO PROGRAM 'umask 077; cat > %s'", base64.StdEncoding.EncodeToString([]byte(data)), path)
		if _, err := admin.Exec(ctx, query); err != nil {
			t.Fatalf("install disposable PostgreSQL TLS fixture: %v", err)
		}
	}
	for _, query := range []string{"ALTER SYSTEM SET ssl_cert_file = '" + certPath + "'", "ALTER SYSTEM SET ssl_key_file = '" + keyPath + "'", "ALTER SYSTEM SET ssl = 'on'", "SELECT pg_reload_conf()"} {
		if _, err := admin.Exec(ctx, query); err != nil {
			t.Fatalf("configure disposable PostgreSQL TLS: %v", err)
		}
	}
	for {
		ready := func() bool {
			c, err := (&net.Dialer{Timeout: time.Second}).DialContext(ctx, "tcp", address)
			if err != nil {
				return false
			}
			defer c.Close()
			_ = c.SetDeadline(time.Now().Add(time.Second))
			if _, err := c.Write(postgresSSLRequest[:]); err != nil {
				return false
			}
			var answer [1]byte
			if _, err := io.ReadFull(c, answer[:]); err != nil || answer[0] != 'S' {
				return false
			}
			return tls.Client(c, &tls.Config{ServerName: "route.example", RootCAs: rootsForCertificate(t, certificate)}).HandshakeContext(ctx) == nil
		}()
		if ready {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatal("disposable PostgreSQL did not enable verified TLS")
		case <-time.After(20 * time.Millisecond):
		}
	}
}

func exercisePostgresTargetTLS(t *testing.T, address string) {
	privateCertificate := publicURLTestCertificate(t, "route.example")
	configurePostgresTLS(t, address, privateCertificate)
	for _, test := range []struct {
		name, channelBinding string
		matching, success    bool
	}{
		{"matching certificate PLUS", "require", true, true}, {"different certificate PLUS", "require", false, false}, {"different certificate ordinary SCRAM", "disable", false, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			publicCertificate := privateCertificate
			if !test.matching {
				publicCertificate = publicURLTestCertificate(t, "route.example")
			}
			observations := make(chan inspection.Summary, 8)
			route, err := NewPublicURLServer(PublicURLServerConfig{Hostname: "route.example", ServiceProtocol: controlv1.Postgres, PublicPort: 5432, Target: address,
				TargetTLS: true, TargetTLSName: "route.example", TargetOptions: localproxy.TargetOptions{RootCAs: rootsForCertificate(t, privateCertificate)}, Certificate: publicCertificate,
				ObserveSummary: func(s inspection.Summary) { observations <- s }})
			if err != nil {
				t.Fatal(err)
			}
			defer route.Close()
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			connection, err := pgx.ConnectConfig(ctx, postgresClientTestConfig(t, route, rootsForCertificate(t, publicCertificate), test.channelBinding))
			if !test.success {
				if connection != nil {
					_ = connection.Close(ctx)
				}
				var problem *pgconn.PgError
				if !errors.As(err, &problem) || problem.Code != "28000" {
					t.Fatalf("incompatible PLUS did not fail at publisher authorization: %v", err)
				}
				select {
				case s := <-observations:
					t.Fatalf("rejected authentication created summary: %+v", s)
				default:
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer connection.Close(ctx)
			var value int
			if err := connection.QueryRow(ctx, "SELECT $1::int", 42).Scan(&value); err != nil || value != 42 {
				t.Fatalf("TLS query=%d, %v", value, err)
			}
			if s := awaitPublisherTest(t, observations); s.Result != inspection.ResultOK || s.Rows != 1 {
				t.Fatalf("TLS summary=%+v", s)
			}
			var secured bool
			if err := connection.QueryRow(ctx, "SELECT ssl FROM pg_stat_ssl WHERE pid = pg_backend_pid()").Scan(&secured); err != nil || !secured {
				t.Fatalf("private PostgreSQL TLS=%t, %v", secured, err)
			}
		})
	}
}

func configureMySQLTLS(t *testing.T, address string, certificate tls.Certificate) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	admin, err := sql.Open("mysql", "root:testpass@tcp("+address+")/mysql?tls=false&timeout=5s&readTimeout=5s&writeTimeout=5s")
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	var directory sql.NullString
	if err := admin.QueryRowContext(ctx, "SELECT @@global.secure_file_priv").Scan(&directory); err != nil {
		t.Fatal(err)
	}
	if !directory.Valid || directory.String == "" {
		t.Fatal("disposable MySQL TLS fixture requires its private file directory")
	}
	id, cert, key := databaseTLSMaterial(t, certificate)
	certPath, keyPath := strings.TrimRight(directory.String, "/")+"/tnl-"+id+".crt", strings.TrimRight(directory.String, "/")+"/tnl-"+id+".key"
	for path, data := range map[string]string{certPath: cert, keyPath: key} {
		if _, err := admin.ExecContext(ctx, "SELECT FROM_BASE64(?) INTO DUMPFILE '"+strings.ReplaceAll(path, "'", "''")+"'", base64.StdEncoding.EncodeToString([]byte(data))); err != nil {
			t.Fatalf("install disposable MySQL TLS fixture: %v", err)
		}
	}
	for setting, path := range map[string]string{"ssl_cert": certPath, "ssl_key": keyPath, "ssl_ca": certPath} {
		if _, err := admin.ExecContext(ctx, "SET GLOBAL "+setting+" = ?", path); err != nil {
			t.Fatalf("configure disposable MySQL TLS: %v", err)
		}
	}
	if _, err := admin.ExecContext(ctx, "ALTER INSTANCE RELOAD TLS"); err != nil {
		t.Fatalf("enable disposable MySQL TLS: %v", err)
	}
	// clear caching_sha2_password's cache so verified TLS also exercises the
	// complete password exchange, rather than only the fast-authentication path.
	if _, err := admin.ExecContext(ctx, "ALTER USER 'tnl_client'@'%' IDENTIFIED BY 'testpass'"); err != nil {
		t.Fatal(err)
	}
}

func exerciseMySQLTargetTLS(t *testing.T, address string) {
	privateCertificate := publicURLTestCertificate(t, "db.internal")
	configureMySQLTLS(t, address, privateCertificate)
	certificate := publicURLTestCertificate(t, "route.example")
	observations := make(chan inspection.Summary, 8)
	route, err := NewPublicURLServer(PublicURLServerConfig{Hostname: "route.example", ServiceProtocol: controlv1.Mysql, PublicPort: 3306, Target: address,
		TargetTLS: true, TargetTLSName: "db.internal", TargetOptions: localproxy.TargetOptions{RootCAs: rootsForCertificate(t, privateCertificate)}, Certificate: certificate,
		ObserveSummary: func(s inspection.Summary) { observations <- s }})
	if err != nil {
		t.Fatal(err)
	}
	defer route.Close()
	const name = "tnl-mysql-verified-target-tls"
	if err := mysql.RegisterTLSConfig(name, &tls.Config{ServerName: "route.example", RootCAs: rootsForCertificate(t, certificate)}); err != nil {
		t.Fatal(err)
	}
	defer mysql.DeregisterTLSConfig(name)
	mysql.RegisterDialContext(name, func(context.Context, string) (net.Conn, error) { return dialDatabaseVisitor(t, route, 3306) })
	defer mysql.DeregisterDialContext(name)
	db, err := sql.Open("mysql", "tnl_client:testpass@"+name+"(route.example:3306)/mysql?tls="+name+"&timeout=5s&readTimeout=5s&writeTimeout=5s")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	var value int
	if err := db.QueryRowContext(ctx, "SELECT 42").Scan(&value); err != nil || value != 42 {
		t.Fatalf("verified MySQL target TLS query=%d, %v", value, err)
	}
	if s := awaitPublisherTest(t, observations); s.Result != inspection.ResultOK || s.Rows != 1 {
		t.Fatalf("verified target summary=%+v", s)
	}
	var status, cipher string
	if err := db.QueryRowContext(ctx, "SHOW SESSION STATUS LIKE 'Ssl_cipher'").Scan(&status, &cipher); err != nil || cipher == "" {
		t.Fatalf("private MySQL TLS cipher=%q, %v", cipher, err)
	}
}

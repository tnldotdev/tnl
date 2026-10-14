package stagingcheck

import (
	"bufio"
	"context"
	"crypto/tls"
	"database/sql"
	"flag"
	"io"
	"net"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	mysql "github.com/go-sql-driver/mysql"
	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/testutil"
	"golang.org/x/crypto/ssh"
)

var (
	tcpProtocol = flag.String("tnl-tcp-protocol", "", "postgres, mysql, redis, or ssh")
	mysqlTarget = flag.String("tnl-test-mysql-address", "", "disposable MySQL target")
	redisTarget = flag.String("tnl-test-redis-address", "", "disposable Redis target")
	sshTarget   = flag.String("tnl-test-ssh-address", "", "disposable SSH target")
	sshHostKey  = flag.String("tnl-test-ssh-host-key", "", "disposable SSH host key")
)

func TestDeployedFullTCP(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierDeployed)
	config := deployedSettings(t)
	ctx, cancel := context.WithTimeout(t.Context(), 7*time.Minute)
	defer cancel()
	verifyBinary(t, ctx, config)
	verifyTeam(t, ctx, config)
	var target string
	switch *tcpProtocol {
	case "postgres":
		parsed, err := url.Parse(testutil.PostgresURL(t))
		if err != nil {
			t.Fatal(err)
		}
		target = parsed.Host
	case "mysql":
		target = *mysqlTarget
	case "redis":
		target = *redisTarget
	case "ssh":
		target = *sshTarget
	default:
		t.Fatalf("full TCP checks require -tnl-tcp-protocol=postgres|mysql|redis|ssh, got %q", *tcpProtocol)
	}
	if target == "" {
		t.Fatal("full TCP check requires a disposable local target")
	}
	label := runLabel(t)
	t.Logf("tcp check label=%s team=%s protocol=%s", label, config.team, *tcpProtocol)
	c := cliCheck{settings: config, cwd: t.TempDir(), state: filepath.Join(t.TempDir(), "client-state")}
	observed := map[string]string{}
	t.Cleanup(func() { cleanupCLI(t, config, label, false, observed) })
	if _, err := c.run(ctx, "auth", "login", "--server="+config.server, "--state-dir="+c.state, "--login-token"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.run(ctx, "team", "use", config.team, "--server="+config.server, "--state-dir="+c.state); err != nil {
		t.Fatal(err)
	}
	process, err := c.publish(ctx, target, "--ephemeral", "--protocol="+*tcpProtocol, "--name="+label)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := process.stop(); err != nil {
			t.Errorf("stop TCP publisher: %v", err)
		}
	})
	ready, err := process.waitReady(ctx)
	if err != nil {
		t.Fatal(err)
	}
	host, port, err := net.SplitHostPort(ready.URL)
	if err != nil || host == "" || port == "" {
		t.Fatalf("invalid TCP public address %q: %v", ready.URL, err)
	}
	status, err := c.run(ctx, "status", "--all", "--output=json", "--state-dir="+c.state)
	if err != nil {
		t.Fatal(err)
	}
	id, err := statusPublicURLID([]byte(status), ready.TunnelID, config.server)
	if err != nil {
		t.Fatal(err)
	}
	observed[id] = ready.URL
	visitCtx, visitCancel := context.WithTimeout(ctx, 30*time.Second)
	defer visitCancel()
	switch *tcpProtocol {
	case "postgres":
		checkPostgres(t, visitCtx, ready.URL)
	case "mysql":
		checkMySQL(t, visitCtx, ready.URL, host)
	case "redis":
		checkRedis(t, visitCtx, ready.URL, host)
	case "ssh":
		checkSSH(t, ready.URL)
	}
}

func checkPostgres(t *testing.T, ctx context.Context, address string) {
	t.Helper()
	publicURL := &url.URL{Scheme: "postgres", User: url.UserPassword("postgres", "postgres"), Host: address, Path: "/postgres"}
	query := publicURL.Query()
	query.Set("sslmode", "verify-full")
	query.Set("channel_binding", "disable")
	publicURL.RawQuery = query.Encode()
	connection, err := pgx.Connect(ctx, publicURL.String())
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close(context.Background())
	var value int
	if err := connection.QueryRow(ctx, "SELECT 1").Scan(&value); err != nil || value != 1 {
		t.Fatalf("public PostgreSQL query = %d: %v", value, err)
	}
}

func checkMySQL(t *testing.T, ctx context.Context, address, hostname string) {
	t.Helper()
	const tlsName = "tnl-deployed-check"
	if err := mysql.RegisterTLSConfig(tlsName, &tls.Config{ServerName: hostname, MinVersion: tls.VersionTLS12}); err != nil {
		t.Fatal(err)
	}
	defer mysql.DeregisterTLSConfig(tlsName)
	dsn := (&mysql.Config{User: "tnl_client", Passwd: "testpass", Net: "tcp", Addr: address, DBName: "mysql", TLSConfig: tlsName}).FormatDSN()
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var value int
	if err := db.QueryRowContext(ctx, "SELECT 1").Scan(&value); err != nil || value != 1 {
		t.Fatalf("public MySQL query = %d: %v", value, err)
	}
}

func checkRedis(t *testing.T, ctx context.Context, address, hostname string) {
	t.Helper()
	connection, err := (&tls.Dialer{NetDialer: &net.Dialer{Timeout: 10 * time.Second}, Config: &tls.Config{ServerName: hostname, MinVersion: tls.VersionTLS12}}).DialContext(ctx, "tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(10 * time.Second))
	reader := bufio.NewReader(connection)
	for _, step := range []struct{ command, want string }{
		{"*2\r\n$4\r\nAUTH\r\n$8\r\ntestpass\r\n", "+OK\r\n"},
		{"*1\r\n$4\r\nPING\r\n", "+PONG\r\n"},
	} {
		if _, err := io.WriteString(connection, step.command); err != nil {
			t.Fatal(err)
		}
		line, err := reader.ReadString('\n')
		if err != nil || line != step.want {
			t.Fatalf("public Redis response = %q, want %q: %v", line, step.want, err)
		}
	}
}

func checkSSH(t *testing.T, address string) {
	t.Helper()
	key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(*sshHostKey))
	if err != nil {
		t.Fatalf("parse disposable SSH host key: %v", err)
	}
	connection, err := net.DialTimeout("tcp", address, 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_ = connection.SetDeadline(time.Now().Add(20 * time.Second))
	clientConnection, channels, requests, err := ssh.NewClientConn(connection, address, &ssh.ClientConfig{
		User: "tnl_test", Auth: []ssh.AuthMethod{ssh.Password("testpass")},
		HostKeyAlgorithms: []string{ssh.KeyAlgoED25519}, HostKeyCallback: ssh.FixedHostKey(key),
	})
	if err != nil {
		_ = connection.Close()
		t.Fatal(err)
	}
	client := ssh.NewClient(clientConnection, channels, requests)
	defer client.Close()
	session, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	output, err := session.CombinedOutput("printf ssh-ok")
	if err != nil {
		t.Fatalf("public SSH command failed: %v", err)
	}
	if strings.TrimSpace(string(output)) != "ssh-ok" {
		t.Fatalf("public SSH command = %q, want ssh-ok", output)
	}
}

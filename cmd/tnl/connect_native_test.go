package main

import (
	"bytes"
	"io"
	"strings"
	"testing"

	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/connector"
)

func TestConnectNamesAndRemovedChoices(t *testing.T) {
	for _, name := range []string{"orders", "inventory", "profile", "setup", "shell"} {
		var flags cli
		parser := commandForTest(&flags, io.Discard)
		parsed, err := parser([]string{"connect", name, "--output=json"})
		if err != nil || commandID(parsed) != "connect start <name>" || flags.Connect.Start.Name != name {
			t.Fatal("service name became a command", name, err)
		}
	}
	for _, args := range [][]string{
		{"connect", "profile", "orders"}, {"connect", "setup", "orders"}, {"connect", "orders", "--local"},
		{"connect", "orders", "--client-certificate"}, {"connect", "orders", "--mtls"},
		{"connect", "stop", "--stdio"}, {"connect", "start", "--stdio"},
	} {
		var flags cli
		parser := commandForTest(&flags, io.Discard)
		if _, err := parser(args); err == nil {
			t.Fatal("obsolete choice or ambiguous command accepted", args)
		}
	}
}

func TestNativeHTTPOutputQualifiesURLAndLocalListener(t *testing.T) {
	for _, listen := range []string{"127.0.0.1:25443", "127.0.0.1:15432", "[::1]:15432"} {
		profile := connector.Profile{Protocol: config.ProtocolHTTP, ServiceID: "svc_0123456789ABCDEFGHIJKL", Hostname: "orders.example.test", Port: 15432, URL: "https://orders.example.test/",
			Command: []string{"curl", "--connect-to", "orders.example.test:443:" + listen, "https://orders.example.test/"}, Instructions: []string{"a browser uses the public endpoint when enabled; connector access needs a client-specific dial override"}}
		var output bytes.Buffer
		if err := writeNativeConnection(&output, profile, statusOutputHuman, listen, ""); err != nil {
			t.Fatal(err)
		}
		if !strings.HasPrefix(output.String(), "curl --connect-to "+shellWord("orders.example.test:443:"+listen)+" "+profile.URL+"\n") ||
			!strings.Contains(output.String(), "Listening on "+listen+"\n") || !strings.Contains(output.String(), "a browser uses the public endpoint") {
			t.Fatal("HTTP output did not qualify its URL and local listener", output.String())
		}
	}
}

func TestNativeProfileWithoutCommandKeepsClientGuidance(t *testing.T) {
	profile := connector.Profile{Protocol: config.ProtocolMySQL, Instructions: []string{"use the SDK mysql2 connection factory"}}
	var output bytes.Buffer
	if err := writeNativeConnection(&output, profile, statusOutputHuman, "127.0.0.1:13306", ""); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(output.String(), "client command") || !strings.Contains(output.String(), profile.Instructions[0]) {
		t.Fatal("unsupported CLI command was presented as usable", output.String())
	}
}

func TestInstalledConnectorKeepsLongCommandAndRunsInBackground(t *testing.T) {
	uri := "postgresql://orders.production.example.test:15432/?channel_binding=disable&gssencmode=disable&hostaddr=127.0.0.1&sslmode=verify-full&sslrootcert=system"
	profile := connector.Profile{Protocol: config.ProtocolPostgres, Command: []string{"psql", uri}, TLS: "PostgreSQL SSLRequest; verify-full; system roots"}
	var out bytes.Buffer
	if err := writeConnectorReady(&out, profile, statusOutputHuman, "127.0.0.1:15432", "", true); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(out.String(), "psql '"+uri+"'\n") || !strings.Contains(out.String(), profile.TLS) ||
		!strings.Contains(out.String(), "runs in the background") || strings.Contains(out.String(), "Keep this terminal open") {
		t.Fatal("installed profile lost its client command, TLS settings, or lifetime", out.String())
	}
}

func TestDetachedConnectionPrintsCopyableCommands(t *testing.T) {
	var out bytes.Buffer
	dir := "/path with a space/client state"
	profile := connector.Profile{DetachedID: "detached-123", Command: []string{"psql", "host=db.example sslrootcert=/path with spaces/team's cert.pem"}}
	if err := writeNativeConnection(&out, profile, statusOutputHuman, "", dir); err != nil {
		t.Fatal(err)
	}
	for _, line := range []string{
		`psql 'host=db.example sslrootcert=/path with spaces/team'\''s cert.pem'`,
		`tnl detached stop detached-123 --state-dir='/path with a space/client state'`,
	} {
		if !strings.Contains("\n"+out.String(), "\n"+line+"\n") {
			t.Fatalf("missing command %q:\n%s", line, &out)
		}
	}
}

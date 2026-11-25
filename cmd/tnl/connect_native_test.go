package main

import (
	"bytes"
	"io"
	"strings"
	"testing"

	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/connector"
	"github.com/tnldotdev/tnl/internal/connector/kubeconfig"
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
		profile := connector.Profile{Protocol: config.ProtocolHTTP, Public: true, Hostname: "orders.example.test", URL: "https://orders.example.test/",
			Command: []string{"curl", "--noproxy", "orders.example.test", "--connect-to", "orders.example.test:443:" + listen, "https://orders.example.test/"}}
		var output bytes.Buffer
		if err := writeNativeConnection(&output, profile, statusOutputHuman, listen, ""); err != nil {
			t.Fatal(err)
		}
		if !strings.HasPrefix(output.String(), "curl --noproxy orders.example.test --connect-to "+shellWord("orders.example.test:443:"+listen)+" "+profile.URL+"\nListening on "+listen+". Ctrl+C to stop.\n") ||
			!strings.Contains(output.String(), "dial override") || !strings.Contains(output.String(), "browser uses the public endpoint") {
			t.Fatal("HTTP output did not qualify its URL and local listener", output.String())
		}
	}
}

func TestNativeMySQLGivesSeparateDialAndTrustSettings(t *testing.T) {
	profile := connector.Profile{Protocol: config.ProtocolMySQL, Hostname: "orders.example", ServerCAFile: "/path with spaces/roots.pem"}
	var output bytes.Buffer
	if err := writeNativeConnection(&output, profile, statusOutputHuman, "127.0.0.1:13306", ""); err != nil {
		t.Fatal(err)
	}
	lines := strings.Join(strings.Fields(output.String()), " ")
	for _, want := range []string{"Listening on 127.0.0.1:13306. Ctrl+C to stop.", "Dial the listener with the SDK mysql2 connection factory", "Verify TLS hostname orders.example", "Server CA /path with spaces/roots.pem"} {
		if !strings.Contains(lines, want) {
			t.Fatalf("missing %q in:\n%s", want, &output)
		}
	}
}

func TestInstalledConnectorKeepsLongCommandAndRunsInBackground(t *testing.T) {
	uri := "postgresql://orders.production.example.test:15432/?channel_binding=disable&gssencmode=disable&hostaddr=127.0.0.1&sslmode=verify-full&sslrootcert=system"
	profile := connector.Profile{Protocol: config.ProtocolPostgres, Command: []string{"psql", uri}, TLS: "PostgreSQL SSLRequest; verify-full; system roots"}
	var out bytes.Buffer
	if err := writeConnectorReady(&out, profile, statusOutputHuman, "127.0.0.1:15432", "", true); err != nil {
		t.Fatal(err)
	}
	if out.String() != "psql '"+uri+"'\nListening on 127.0.0.1:15432. Installed; running in the background.\n" {
		t.Fatal("installed profile lost its client command, TLS settings, or lifetime", out.String())
	}
}

func TestDetachedConnectionPrintsCopyableCommands(t *testing.T) {
	var out bytes.Buffer
	dir := "/path with a space/client state"
	profile := connector.Profile{DetachedID: "detached-123", Command: []string{"psql", "host=db.example sslrootcert=/path with spaces/team's cert.pem"}}
	if err := writeNativeConnection(&out, profile, statusOutputHuman, "127.0.0.1:15432", dir); err != nil {
		t.Fatal(err)
	}
	for _, line := range []string{
		`psql 'host=db.example sslrootcert=/path with spaces/team'\''s cert.pem'`,
		`Listening on 127.0.0.1:15432. Running detached.`,
		`tnl detached stop detached-123 --state-dir='/path with a space/client state'`,
	} {
		if !strings.Contains("\n"+out.String(), "\n"+line+"\n") {
			t.Fatalf("missing command %q:\n%s", line, &out)
		}
	}
}

func TestNativeKubernetesCommandSelectsPreparedContext(t *testing.T) {
	kube := kubeconfig.Result{File: "/path with spaces/config", Context: "tnl:shop/cluster-123", Namespace: "development", Qualified: true}
	profile := connector.Profile{Protocol: config.ProtocolKubernetes, Kubeconfig: &kube, Command: []string{"kubectl", "--kubeconfig", kube.File, "--context", kube.Context, "get", "namespaces"}}
	var output bytes.Buffer
	if err := writeNativeConnection(&output, profile, statusOutputHuman, "127.0.0.1:16443", ""); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(output.String(), "kubectl --kubeconfig '/path with spaces/config' --context tnl:shop/cluster-123 get namespaces\nListening on 127.0.0.1:16443. Ctrl+C to stop.\n") ||
		!strings.Contains(output.String(), "Namespace: development") || !strings.Contains(output.String(), "name is in use") {
		t.Fatal(output.String())
	}
}

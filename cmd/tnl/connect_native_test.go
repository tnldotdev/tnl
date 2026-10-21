package main

import (
	"bytes"
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/alecthomas/kong"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func TestNativeProfileSeparatesLocalDialAndVerifiedIdentity(t *testing.T) {
	for _, public := range []bool{false, true} {
		for _, protocol := range []controlv1.PrivateServiceProtocol{controlv1.PrivateHttp, controlv1.Postgres, controlv1.Mysql, controlv1.Tcp, "kubernetes"} {
			service := controlv1.PrivateService{Id: "psvc_0123456789ABCDEFGHIJKL", Protocol: protocol, Enabled: true, ManagedTls: &controlv1.ManagedServiceTLS{Hostname: "orders.production.example.test", Port: 25443, Public: public}}
			approved := *service.ManagedTls
			profile, err := serviceConnectionProfile(service, "127.0.0.1:15432")
			if err != nil || !profile.ConnectorRequired || profile.Authentication != connectionConnector || profile.Host != "127.0.0.1" || profile.Port != 15432 || profile.Hostname != approved.Hostname || *service.ManagedTls != approved || profile.Public != public {
				t.Fatal("profile changed approved metadata or lost the local endpoint", err)
			}
			switch protocol {
			case controlv1.Postgres:
				connection, err := url.Parse(profile.Command[1])
				if err != nil {
					t.Fatal(err)
				}
				query := connection.Query()
				if connection.Host != approved.Hostname+":15432" || query.Get("hostaddr") != "127.0.0.1" || query.Get("sslmode") != "verify-full" || query.Get("sslrootcert") != "system" || query.Get("channel_binding") != "disable" || query.Get("gssencmode") != "disable" || query.Has("sslcert") || query.Has("sslkey") {
					t.Fatal("psql lost independent dial address or verified hostname", profile.Command)
				}
			case controlv1.PrivateHttp:
				if profile.URL != "https://"+approved.Hostname+":25443/" || strings.Join(profile.Command, " ") != "curl --connect-to "+approved.Hostname+":25443:127.0.0.1:15432 "+profile.URL {
					t.Fatal("curl would dial public DNS or verify loopback", profile.Command)
				}
			case controlv1.Mysql:
				command := strings.Join(profile.Command, " ")
				if !strings.Contains(command, "--host="+approved.Hostname) || !strings.Contains(command, "--port=15432") || !strings.Contains(command, "--ssl-mode=VERIFY_IDENTITY") || !strings.Contains(strings.Join(profile.Instructions, " "), "127.0.0.1 "+approved.Hostname) {
					t.Fatal("mysql identity checking has no exact loopback mapping", profile)
				}
			}
			var output bytes.Buffer
			if err := writeNativeConnection(&output, profile, statusOutputHuman, "127.0.0.1:15432"); err != nil {
				t.Fatal(err)
			}
			for _, line := range strings.Split(output.String(), "\n") {
				if len(line) > 72 {
					t.Fatal("output exceeds shared renderer width")
				}
			}
			encoded, _ := json.Marshal(profile)
			if bytes.Contains(encoded, []byte("client_certificate")) || bytes.Contains(encoded, []byte("key_file")) {
				t.Fatal("connector profile exposed application credentials")
			}
		}
	}
}

func TestConnectNamesAndRemovedChoices(t *testing.T) {
	for _, name := range []string{"orders", "inventory", "profile", "setup", "shell"} {
		var flags cli
		parser, err := kong.New(&flags)
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := parser.Parse([]string{"connect", name, "--output=json"})
		if err != nil || parsed.Command() != "connect start <name>" || flags.Connect.Start.Name != name {
			t.Fatal("service name became a command", name, err)
		}
	}
	for _, args := range [][]string{
		{"connect", "profile", "orders"}, {"connect", "setup", "orders"}, {"connect", "orders", "--local"},
		{"connect", "orders", "--client-certificate"}, {"connect", "orders", "--mtls"},
		{"connect", "stop", "--stdio"}, {"connect", "start", "--stdio"},
	} {
		var flags cli
		parser, err := kong.New(&flags)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := parser.Parse(args); err == nil {
			t.Fatal("obsolete choice or ambiguous command accepted", args)
		}
	}
}

func TestConnectModeMatrix(t *testing.T) {
	for _, public := range []bool{false, true} {
		for _, protocol := range []controlv1.PrivateServiceProtocol{controlv1.PrivateHttp, controlv1.Postgres, controlv1.Mysql, controlv1.Tcp, "kubernetes"} {
			service := controlv1.PrivateService{Id: "psvc_0123456789ABCDEFGHIJKL", Enabled: true, Protocol: protocol, ManagedTls: &controlv1.ManagedServiceTLS{Hostname: "service.example.test", Port: 25443, Public: public}}
			for _, flags := range []connectStartCommand{{}, {Install: true}, {Detach: true}, {Foreground: true}, {Listen: "127.0.0.1:15432"}, {Detach: true, Listen: "127.0.0.1:15432", Output: statusOutputJSON}, {Stdio: true}, {Output: statusOutputJSON}, {Protocol: "tcp"}} {
				valid := (!flags.Stdio || protocol == controlv1.Tcp) && (flags.Protocol == "" || flags.Protocol == string(protocol))
				if err := validateConnectServiceMode(flags, service); (err == nil) != valid {
					t.Fatalf("public=%v protocol=%s flags=%+v: %v", public, protocol, flags, err)
				}
			}
		}
	}
}

func TestNativeMySQLRequiresExplicitServerRoots(t *testing.T) {
	roots, err := nativeMySQLRoots()
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := os.ReadFile(roots)
	if err != nil {
		t.Fatal(err)
	}
	selected := filepath.Join(t.TempDir(), "server roots.pem")
	if err := os.WriteFile(selected, bundle, 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SSL_CERT_FILE", selected)
	service := controlv1.PrivateService{Id: "psvc_0123456789ABCDEFGHIJKL", Enabled: true, Protocol: controlv1.Mysql, ManagedTls: &controlv1.ManagedServiceTLS{Hostname: "database.example.test", Port: 25443, Public: true}}
	profile, err := serviceConnectionProfile(service, "127.0.0.1:15432")
	if err != nil || profile.ServerCAFile != selected || !strings.Contains(strings.Join(profile.Command, " "), "--ssl-ca="+selected) {
		t.Fatal("mysql omitted explicit roots", err)
	}
	if err := os.WriteFile(selected, []byte("not a PEM bundle"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := validateConnectServiceMode(connectStartCommand{}, service); err == nil {
		t.Fatal("invalid roots escaped preflight")
	}
}

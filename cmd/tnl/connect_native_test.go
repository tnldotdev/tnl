package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/alecthomas/kong"
	"github.com/tnldotdev/tnl/internal/clientstate"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func TestNativeProfileUsesVerifiedTLSAndSafeCredentialPaths(t *testing.T) {
	service := controlv1.PrivateService{Id: "psvc_0123456789ABCDEFGHIJKL", Protocol: controlv1.Postgres, Enabled: true, ManagedTls: &controlv1.ManagedServiceTLS{Hostname: "orders.production.storefront.example.test", Port: 25443, Public: true}}
	material := &clientstate.ServiceClientMaterial{CertificateFile: "/private/state/a b'c/client-cert.pem", KeyFile: "/private/state/a b'c/client-key.pem", ExpiresAt: time.Now().Add(time.Hour), Certificate: tls.Certificate{PrivateKey: "must-not-serialize-private-key"}}
	profile, err := serviceConnectionProfile(service, material)
	if err != nil || profile.ConnectorRequired || profile.Authentication != connectionMTLS {
		t.Fatal("public native profile required a connector or lost mTLS", err)
	}
	connection, err := url.Parse(profile.Command[1])
	if err != nil {
		t.Fatal(err)
	}
	query := connection.Query()
	if connection.Host != "orders.production.storefront.example.test:25443" || query.Get("sslmode") != "verify-full" || query.Get("sslrootcert") != "system" || query.Get("channel_binding") != "disable" || query.Get("sslcert") != material.CertificateFile || query.Get("sslkey") != material.KeyFile {
		t.Fatal("native TLS settings or path encoding changed", profile.Command)
	}
	encoded, err := json.Marshal(profile)
	if err != nil || strings.Contains(string(encoded), "must-not-serialize-private-key") || strings.Contains(string(encoded), "private_key") {
		t.Fatal("profile serialized private key material", err)
	}
	if _, err = serviceConnectionProfile(service, nil); err == nil {
		t.Fatal("public database profile silently omitted its client credential")
	}
	service.ManagedTls.Public = false
	private, err := serviceConnectionProfile(service, nil)
	if err != nil || !private.ConnectorRequired || private.ClientCertificate != nil || private.Authentication != connectionConnector {
		t.Fatal("private native client needed a certificate", err)
	}
	service.Protocol = controlv1.PrivateHttp
	private, err = serviceConnectionProfile(service, nil)
	if err != nil || len(private.Command) != 2 || private.Command[0] != "curl" || private.Command[1] != "https://orders.production.storefront.example.test:25443/" {
		t.Fatal("private curl did not use native verified HTTPS", private.Command, err)
	}
	service.ManagedTls.Hostname = "bad\r\nhost"
	if _, err = serviceConnectionProfile(service, nil); err == nil {
		t.Fatal("profile printed an unvalidated server endpoint")
	}
}

func TestConnectNamesAndRemovedChoices(t *testing.T) {
	for _, name := range []string{"orders", "profile", "setup", "shell"} {
		var flags cli
		parser, err := kong.New(&flags)
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := parser.Parse([]string{"connect", name, "--output=json"})
		if err != nil || parsed.Command() != "connect start <name>" || flags.Connect.Start.Name != name {
			t.Fatal("service name was interpreted as a subcommand", name, err)
		}
	}
	for _, args := range [][]string{
		{"connect", "profile", "orders"}, {"connect", "setup", "orders"},
		{"connect", "orders", "--client-certificate"}, {"connect", "orders", "--mtls"},
		{"connect", "stop", "--stdio"}, {"connect", "start", "--stdio"},
	} {
		var flags cli
		parser, err := kong.New(&flags)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := parser.Parse(args); err == nil {
			t.Fatal("removed choice or ambiguous subcommand accepted", args)
		}
	}
}

func TestConnectModeMatrix(t *testing.T) {
	for _, public := range []bool{false, true} {
		for _, protocol := range []controlv1.PrivateServiceProtocol{controlv1.PrivateHttp, controlv1.Postgres, controlv1.Mysql, controlv1.Tcp} {
			service := controlv1.PrivateService{Id: "psvc_0123456789ABCDEFGHIJKL", Enabled: true, Protocol: protocol, ManagedTls: &controlv1.ManagedServiceTLS{Hostname: "service.example.test", Port: 25443, Public: public}}
			for _, flags := range []connectStartCommand{{}, {Install: true}, {Detach: true}, {Listen: "127.0.0.1:25443"}, {Stdio: true}, {Output: statusOutputJSON}, {Protocol: "tcp"}} {
				finite := public && protocol != controlv1.Tcp
				valid := !(finite && (flags.Install || flags.Detach || flags.Listen != "")) && (!flags.Stdio || protocol == controlv1.Tcp) && (flags.Output != statusOutputJSON || finite) && (flags.Protocol == "" || flags.Protocol == string(protocol))
				if err := validateConnectServiceMode(flags, service); (err == nil) != valid {
					t.Fatalf("public=%v protocol=%s flags=%+v: %v", public, protocol, flags, err)
				}
			}
		}
	}
}

func TestNativeMySQLRequiresExplicitServerRootsAndRenderedOutputIsBounded(t *testing.T) {
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
	service := controlv1.PrivateService{Id: "psvc_0123456789ABCDEFGHIJKL", Enabled: true, Protocol: controlv1.Mysql, ManagedTls: &controlv1.ManagedServiceTLS{Hostname: "database.production.example.test", Port: 25443, Public: true}}
	material := &clientstate.ServiceClientMaterial{CertificateFile: "/private/state/client-cert.pem", KeyFile: "/private/state/client-key.pem", ExpiresAt: time.Now().Add(time.Hour)}
	profile, err := serviceConnectionProfile(service, material)
	if err != nil || profile.ServerCAFile != selected || !strings.Contains(strings.Join(profile.Command, " "), "--ssl-ca="+selected) {
		t.Fatal("mysql omitted explicit server roots", err)
	}
	var output bytes.Buffer
	if err := writeNativeConnection(&output, profile, statusOutputHuman, ""); err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(output.String(), "\n") {
		if len(line) > 72 {
			t.Fatal("native output exceeds renderer width", len(line))
		}
	}
	if err := os.WriteFile(selected, []byte("not a PEM bundle"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := validateConnectServiceMode(connectStartCommand{}, service); err == nil {
		t.Fatal("missing native server roots escaped preflight")
	}
}

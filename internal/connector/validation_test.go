package connector

import (
	"bytes"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestConnectorHTTPInstructionsKeepCanonicalAuthorityWithoutHostEdits(t *testing.T) {
	service := controlv1.Service{Id: "svc_0123456789ABCDEFGHIJKL", Protocol: controlv1.ServiceProtocolHTTP, Enabled: true, Endpoint: &controlv1.ServiceEndpoint{Hostname: "orders.example.test", Port: 443, Public: true}}
	for _, listen := range []string{"127.0.0.1:25443", "127.0.0.1:15432", "[::1]:15432"} {
		profile, err := serviceConnectionProfile(service, listen)
		if err != nil {
			t.Fatal(err)
		}
		instructions := strings.Join(profile.Instructions, " ")
		if !strings.Contains(instructions, "client-specific dial override") || profile.URL != "https://orders.example.test/" {
			t.Fatal("connector instructions changed the HTTPS authority", instructions)
		}
		if strings.Contains(instructions, "/etc/hosts") || strings.Contains(instructions, profile.Host+" "+profile.Hostname) {
			t.Fatal("connector instructions require OS hostname edits", instructions)
		}
	}
}

func TestConnectorHTTPCurlDialsOverrideWithVerifiedAuthority(t *testing.T) {
	curl, err := exec.LookPath("curl")
	if err != nil {
		t.Skip("curl is required to exercise the printed native command")
	}
	var requests atomic.Int64
	const authority = "example.com"
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != authority || r.TLS.ServerName != "example.com" {
			t.Error("curl lost the local HTTP authority or TLS identity")
			w.WriteHeader(http.StatusMisdirectedRequest)
			return
		}
		requests.Add(1)
		_, _ = io.WriteString(w, "local connector reached")
	}))
	defer target.Close()
	caFile := filepath.Join(t.TempDir(), "roots.pem")
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: target.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	// even a configured HTTPS proxy must not divert this local connector command.
	t.Setenv("https_proxy", "http://127.0.0.1:1")
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	service := controlv1.Service{Id: "svc_0123456789ABCDEFGHIJKL", Protocol: controlv1.ServiceProtocolHTTP, Enabled: true, Endpoint: &controlv1.ServiceEndpoint{Hostname: "example.com", Port: 443, Public: true}}
	invoke := func() ([]byte, error) {
		t.Helper()
		profile, err := serviceConnectionProfile(service, target.Listener.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		args := append([]string{"--cacert", caFile, "--silent", "--show-error", "--fail", "--max-time", "5"}, profile.Command[1:]...)
		return exec.CommandContext(t.Context(), curl, args...).CombinedOutput()
	}
	if output, err := invoke(); err != nil || string(output) != "local connector reached" || requests.Load() != 1 {
		t.Fatalf("printed curl command missed the local listener: %v %s", err, output)
	}
	service.Endpoint.Hostname = "wrong.example.test"
	if _, err := invoke(); err == nil || requests.Load() != 1 {
		t.Fatal("printed curl command bypassed managed hostname verification")
	}
}

func TestConnectorProfileSeparatesLocalDialAndVerifiedIdentity(t *testing.T) {
	for _, public := range []bool{false, true} {
		for _, protocol := range []controlv1.ServiceProtocol{controlv1.ServiceProtocolHTTP, controlv1.Postgres, controlv1.Mysql, controlv1.Tcp, "kubernetes"} {
			service := controlv1.Service{Id: "svc_0123456789ABCDEFGHIJKL", Protocol: protocol, Enabled: true, Endpoint: &controlv1.ServiceEndpoint{Hostname: "orders.production.example.test", Port: 25443, Public: public}}
			if protocol == controlv1.ServiceProtocolHTTP {
				service.Endpoint.Port = 443
			}
			approved := *service.Endpoint
			profile, err := serviceConnectionProfile(service, "127.0.0.1:15432")
			if err != nil || !profile.ConnectorRequired || profile.Authentication != connectionConnector || profile.Host != "127.0.0.1" || profile.Port != 15432 || profile.Hostname != approved.Hostname || *service.Endpoint != approved || profile.Public != public {
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
			case controlv1.ServiceProtocolHTTP:
				if profile.URL != "https://"+approved.Hostname+"/" || strings.Join(profile.Command, " ") != "curl --noproxy "+approved.Hostname+" --connect-to "+approved.Hostname+":443:127.0.0.1:15432 "+profile.URL {
					t.Fatal("curl would dial public DNS or verify loopback", profile.Command)
				}
			case controlv1.Mysql:
				instructions := strings.Join(profile.Instructions, " ")
				if len(profile.Command) != 0 || !strings.Contains(instructions, "dials 127.0.0.1:15432") || !strings.Contains(instructions, "TLS server as "+approved.Hostname) || !strings.Contains(instructions, "SDK mysql2") {
					t.Fatal("mysql guidance lost separate dial and verified hostname", profile)
				}
				if strings.Contains(instructions, "/etc/hosts") || strings.Contains(instructions, "127.0.0.1 "+approved.Hostname) || strings.Contains(instructions, "VERIFY_CA") {
					t.Fatal("mysql guidance requires host edits or weaker verification", instructions)
				}
			}
			encoded, _ := json.Marshal(profile)
			if bytes.Contains(encoded, []byte("client_certificate")) || bytes.Contains(encoded, []byte("key_file")) {
				t.Fatal("connector profile exposed application credentials")
			}
		}
	}
}

func TestConnectModeMatrix(t *testing.T) {
	for _, public := range []bool{false, true} {
		for _, protocol := range []controlv1.ServiceProtocol{controlv1.ServiceProtocolHTTP, controlv1.Postgres, controlv1.Mysql, controlv1.Tcp, "kubernetes"} {
			service := controlv1.Service{Id: "svc_0123456789ABCDEFGHIJKL", Enabled: true, Protocol: protocol, Endpoint: &controlv1.ServiceEndpoint{Hostname: "service.example.test", Port: 25443, Public: public}}
			if protocol == controlv1.ServiceProtocolHTTP {
				service.Endpoint.Port = 443
			}
			for _, flags := range []StartOptions{{}, {Install: true}, {Detach: true}, {Foreground: true}, {Listen: "127.0.0.1:15432"}, {Detach: true, Listen: "127.0.0.1:15432", Output: "json"}, {Stdio: true}, {Output: "json"}, {Protocol: "tcp"}} {
				valid := (!flags.Stdio || protocol == controlv1.Tcp) && (flags.Protocol == "" || flags.Protocol == string(protocol))
				if err := ValidateServiceMode(flags, service); (err == nil) != valid {
					t.Fatalf("public=%v protocol=%s flags=%+v: %v", public, protocol, flags, err)
				}
			}
		}
	}
}

func TestConnectorPrivateIdentityNeedsNoPublicReservation(t *testing.T) {
	for _, protocol := range []controlv1.ServiceProtocol{"http", "tcp", "postgres", "mysql", "kubernetes"} {
		service := controlv1.Service{Id: "svc_0123456789ABCDEFGHIJKL", Enabled: true, Protocol: protocol,
			Endpoint: &controlv1.ServiceEndpoint{Hostname: "private.example.test"}}
		port := 0
		if protocol == controlv1.ServiceProtocolHTTP {
			port = 443
			service.Endpoint.Port = port
		}
		profile, err := serviceConnectionProfile(service, "127.0.0.1:24117")
		if err != nil || profile.Port != 24117 || profile.ServicePort != port || profile.Public || strings.Contains(profile.URL, ":0") {
			t.Fatal("private identity acquired a public port or lost its local listener", profile, err)
		}
		if protocol == "http" && (profile.URL != "https://private.example.test/" || !strings.Contains(strings.Join(profile.Command, " "), ":443:127.0.0.1:24117")) {
			t.Fatal("private HTTP confused authority with the saved local port", profile.URL)
		}
		service.Endpoint.Public = true
		if err := ValidateService(service); protocol == "http" && err != nil || protocol != "http" && err == nil {
			t.Fatal("public service accepted an unallocated port")
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
	service := controlv1.Service{Id: "svc_0123456789ABCDEFGHIJKL", Enabled: true, Protocol: controlv1.Mysql, Endpoint: &controlv1.ServiceEndpoint{Hostname: "database.example.test", Port: 25443, Public: true}}
	profile, err := serviceConnectionProfile(service, "127.0.0.1:15432")
	if err != nil || profile.ServerCAFile != selected {
		t.Fatal("mysql omitted explicit roots", err)
	}
	if err := os.WriteFile(selected, []byte("not a PEM bundle"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := ValidateServiceMode(StartOptions{}, service); err == nil {
		t.Fatal("invalid roots escaped preflight")
	}
}

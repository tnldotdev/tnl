package connector

import (
	"bytes"
	"encoding/json"
	"encoding/pem"
	"io"
	"net"
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

func TestConnectorHTTPBrowserInstructionsSeparateLocalAndPublicPorts(t *testing.T) {
	service := controlv1.Service{Id: "svc_0123456789ABCDEFGHIJKL", Protocol: controlv1.ServiceProtocolHTTP, Enabled: true, Endpoint: &controlv1.ServiceEndpoint{Hostname: "orders.example.test", Port: 25443, Public: true}}
	for _, listen := range []string{"127.0.0.1:25443", "127.0.0.1:15432", "[::1]:15432"} {
		profile, err := serviceConnectionProfile(service, listen)
		if err != nil {
			t.Fatal(err)
		}
		instructions := strings.Join(profile.Instructions, " ")
		if !strings.Contains(instructions, "must resolve to the local listener") || !strings.Contains(instructions, "exact managed hostname") {
			t.Fatal("browser instructions rely on public DNS", instructions)
		}
		if strings.Contains(instructions, "--listen=") || !strings.Contains(instructions, profile.Host+" "+profile.Hostname) || !strings.Contains(instructions, profile.URL) {
			t.Fatal("browser origin omitted its exact loopback mapping", instructions)
		}
	}
}

func TestConnectorHTTPCurlDialsOverrideWithVerifiedAuthority(t *testing.T) {
	curl, err := exec.LookPath("curl")
	if err != nil {
		t.Skip("curl is required to exercise the printed native command")
	}
	var requests atomic.Int64
	var authority string
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
	_, port, _ := net.SplitHostPort(target.Listener.Addr().String())
	authority = net.JoinHostPort("example.com", port)
	caFile := filepath.Join(t.TempDir(), "roots.pem")
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: target.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	// even a configured HTTPS proxy must not divert this local connector command.
	t.Setenv("https_proxy", "http://127.0.0.1:1")
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	service := controlv1.Service{Id: "svc_0123456789ABCDEFGHIJKL", Protocol: controlv1.ServiceProtocolHTTP, Enabled: true, Endpoint: &controlv1.ServiceEndpoint{Hostname: "example.com", Port: 25443, Public: true}}
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
				if profile.URL != "https://"+approved.Hostname+":15432/" || strings.Join(profile.Command, " ") != "curl --noproxy "+approved.Hostname+" --connect-to "+approved.Hostname+":15432:127.0.0.1:15432 "+profile.URL {
					t.Fatal("curl would dial public DNS or verify loopback", profile.Command)
				}
			case controlv1.Mysql:
				command := strings.Join(profile.Command, " ")
				if !strings.Contains(command, "--host="+approved.Hostname) || !strings.Contains(command, "--port=15432") || !strings.Contains(command, "--ssl-mode=VERIFY_IDENTITY") || !strings.Contains(strings.Join(profile.Instructions, " "), "127.0.0.1 "+approved.Hostname) {
					t.Fatal("mysql identity checking has no exact loopback mapping", profile)
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
		profile, err := serviceConnectionProfile(service, "127.0.0.1:24117")
		if err != nil || profile.Port != 24117 || profile.ServicePort != 0 || profile.Public || strings.Contains(profile.URL, ":0") {
			t.Fatal("private identity acquired a public port or lost its local listener", profile, err)
		}
		if protocol == "http" && profile.URL != "https://private.example.test:24117/" {
			t.Fatal("private HTTP URL does not use the saved local port", profile.URL)
		}
		service.Endpoint.Public = true
		if ValidateService(service) == nil {
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
	if err != nil || profile.ServerCAFile != selected || !strings.Contains(strings.Join(profile.Command, " "), "--ssl-ca="+selected) {
		t.Fatal("mysql omitted explicit roots", err)
	}
	if err := os.WriteFile(selected, []byte("not a PEM bundle"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := ValidateServiceMode(StartOptions{}, service); err == nil {
		t.Fatal("invalid roots escaped preflight")
	}
}

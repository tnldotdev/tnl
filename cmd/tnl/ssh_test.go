package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os/user"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/alecthomas/kong"
	"github.com/tnldotdev/tnl/internal/clientauth"
	"github.com/tnldotdev/tnl/internal/clioutput"
	"github.com/tnldotdev/tnl/internal/controlclient"
	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/sshclient"
	"github.com/tnldotdev/tnl/internal/visitorcert"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
	"golang.org/x/crypto/ssh"
)

func TestSSHCommandModel(t *testing.T) {
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"ssh", "chase@workstation.example.test"}, "ssh <user@host> <command>"},
		{[]string{"ssh", "-L", "15432:localhost:5432", "-D", "1080", "chase@workstation.example.test"}, "ssh <user@host> <command>"},
		{[]string{"ssh", "chase@workstation.example.test", "--", "git status"}, "ssh <user@host> <command>"},
		{[]string{"ssh", "enable", "--name", "workstation", "--user", "chase", "--user", "deploy"}, "ssh enable"},
		{[]string{"ssh", "connect", "--public-url-id", "url_0123456789abcdefghijkl"}, "ssh connect"},
		{[]string{"ssh", "copy", "local.txt", "chase@workstation.example.test:remote.txt"}, "ssh copy <source> <destination>"},
		{[]string{"ssh", "sftp", "chase@workstation.example.test"}, "ssh sftp <user@host>"},
		{[]string{"ssh", "install"}, "ssh install"},
		{[]string{"service", "status", "workstation"}, "service status <job>"},
	} {
		t.Run(strings.Join(tc.args, " "), func(t *testing.T) {
			var flags cli
			parser, err := kong.New(&flags)
			if err != nil {
				t.Fatal(err)
			}
			parsed, err := parser.Parse(tc.args)
			if err != nil || canonicalParsedCommand(parsed.Command()) != tc.want {
				t.Fatalf("parsed command: %v, %v", parsed, err)
			}
			if flags.SSH.Run.Destination != "" && strings.Contains(strings.Join(tc.args, " "), "git status") && !reflect.DeepEqual(flags.SSH.Run.Command, []string{"git status"}) {
				t.Fatalf("remote command changed: %#v", flags.SSH.Run.Command)
			}
			if tc.want == "ssh enable" && !reflect.DeepEqual(flags.SSH.Enable.Users, []string{"chase", "deploy"}) {
				t.Fatalf("account allowlist: %#v", flags.SSH.Enable.Users)
			}
		})
	}
	for _, arg := range []string{"-R", "-A", "-X", "-o", "--access-token"} {
		for _, args := range [][]string{{"ssh", arg, "secret", "chase@workstation.example.test"}, {"ssh", "chase@workstation.example.test", arg, "secret"}} {
			var flags cli
			parser, err := kong.New(&flags)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := parser.Parse(args); err == nil {
				t.Fatalf("unapproved SSH flag %s was accepted", arg)
			}
		}
	}
}

func TestSSHPreflightDoesNotReadLoginOrWriteStdout(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	for _, tc := range []struct {
		args []string
		want error
	}{
		{[]string{"ssh", "-L", "0.0.0.0:8080:localhost:80", "chase@host.example.test"}, sshclient.ErrInvalidForward},
		{[]string{"ssh", "chase@host.example.test"}, sshclient.ErrSSHUnavailable},
	} {
		var stdout, stderr bytes.Buffer
		err := run(t.Context(), tc.args, &stdout, &stderr)
		if !errors.Is(err, tc.want) || stdout.Len() != 0 || stderr.Len() != 0 {
			t.Fatalf("preflight: %v, stdout=%q stderr=%q", err, &stdout, &stderr)
		}
	}
}

func TestSSHDestinationAndManagedInventory(t *testing.T) {
	for _, destination := range []string{"root@host.example", "host.example", "-oProxyCommand=x@host.example", "chase@host.example:22", "chase@https://host.example", "chase@host.example/path", "chase@127.0.0.1", "chase@host.example@other.example"} {
		if _, _, err := parseSSHDestination(destination); err == nil {
			t.Fatalf("invalid destination accepted: %q", destination)
		}
	}
	if account, host, err := parseSSHDestination("chase@workstation.example.test"); err != nil || account != "chase" || host != "workstation.example.test" {
		t.Fatalf("valid destination: %q %q %v", account, host, err)
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(controlv1.AvailablePublicURLPage{PublicUrls: []controlv1.AvailablePublicURL{}})
	}))
	defer server.Close()
	control, err := controlclient.New(server.URL, server.Client(), credentials.AccessToken("session"))
	if err != nil {
		t.Fatal(err)
	}
	session := &teamSession{authenticated: &clientauth.Client{Control: control}}
	if _, err := resolveVisitorPublicURL(t.Context(), session, "unknown.example.test"); !errors.Is(err, controlclient.ErrNotFound) {
		t.Fatalf("unknown host: %v", err)
	}
	port, pin := int32(15432), "not-a-key"
	item := controlv1.AvailablePublicURL{Id: "url_0123456789abcdefghijkl", CanonicalHostname: "host.example.test", ServiceProtocol: "ssh", PublicPort: &port}
	if err := selectSSHVisitorURL(item); err == nil {
		t.Fatal("unmanaged SSH URL accepted without a host key")
	}
	item.SshHostKey = &pin
	item.ServiceProtocol = "postgres"
	if err := selectSSHVisitorURL(item); err == nil {
		t.Fatal("database URL accepted as SSH")
	}
}

func TestSSHExitStatusAndSafeDiagnostics(t *testing.T) {
	for _, code := range []int{1, 23, 255} {
		err := clioutput.WrapCommand("tnl ssh", failure.Wrap("visit SSH host", failure.TransportUnavailable, &sshclient.ExitError{Code: code, Err: errors.New("remote command failed")}))
		if got, render := terminalResult(err); got != code || render != nil {
			t.Fatalf("exit result: %d, %v", got, render)
		}
	}
	var output bytes.Buffer
	writeCommandError(&output, errors.Join(sshclient.ErrSSHUnavailable, errors.New("sensitive-cause-secret")))
	if !strings.Contains(output.String(), "OpenSSH") || !strings.Contains(output.String(), "install") || strings.Contains(output.String(), "sensitive-cause-secret") {
		t.Fatalf("missing-ssh diagnostic: %s", &output)
	}
}

type sshCertificateIssuer struct {
	issuer *visitorcert.Issuer
	urlID  string
}

func (i sshCertificateIssuer) IssueVisitorCertificate(_ context.Context, urlID string, csr []byte) (controlv1.VisitorCertificate, error) {
	if i.urlID != "" {
		urlID = i.urlID
	}
	expires := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
	cert, err := i.issuer.Issue(csr, urlID, "ident_0123456789abcdefghijkl", expires, time.Now())
	return controlv1.VisitorCertificate{PublicUrlId: urlID, CertificatePem: string(cert), IssuerPem: string(i.issuer.CertificatePEM()), ExpiresAt: expires}, err
}

func TestSSHVisitorCertificateIsFreshAndURLBound(t *testing.T) {
	issuer, err := visitorcert.New(make([]byte, ed25519.SeedSize))
	if err != nil {
		t.Fatal(err)
	}
	const urlID = "url_0123456789abcdefghijkl"
	first, issued, err := createVisitorCertificate(t.Context(), sshCertificateIssuer{issuer: issuer}, urlID)
	if err != nil {
		t.Fatal(err)
	}
	second, _, err := createVisitorCertificate(t.Context(), sshCertificateIssuer{issuer: issuer}, urlID)
	if err != nil {
		t.Fatal(err)
	}
	if first.PrivateKey.(*ecdsa.PrivateKey).Equal(second.PrivateKey) || first.Leaf.URIs[0].Path != "/"+urlID+"/ident_0123456789abcdefghijkl" {
		t.Fatal("visitor identity key reused or certificate has the wrong URL")
	}
	if _, _, err := createVisitorCertificate(t.Context(), sshCertificateIssuer{issuer: issuer, urlID: "url_abcdefghijkl0123456789"}, urlID); !errors.Is(err, visitorcert.ErrInvalidCertificate) {
		t.Fatalf("different URL response accepted: %v", err)
	}
	wrongKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := validateVisitorCertificate(issued, wrongKey, urlID, time.Now()); !errors.Is(err, visitorcert.ErrInvalidCertificate) {
		t.Fatalf("different local key accepted: %v", err)
	}
	if _, err := validateVisitorCertificate(issued, first.PrivateKey.(*ecdsa.PrivateKey), urlID, issued.ExpiresAt.Add(time.Second)); !errors.Is(err, visitorcert.ErrInvalidCertificate) {
		t.Fatalf("expired certificate accepted: %v", err)
	}
}

func TestSSHEnableChecksExistingNonrootAccounts(t *testing.T) {
	lookup := func(name string) (*user.User, error) {
		if name == "missing" {
			return nil, errors.New("private-account-directory-error")
		}
		uid := "501"
		if name == "root-alias" {
			uid = "0"
		}
		return &user.User{Username: name, Uid: uid}, nil
	}
	for _, accounts := range [][]string{nil, {"root"}, {"root-alias"}, {"missing"}, {"chase", "chase"}, {"-injected"}} {
		if err := validateSSHEnable(sshEnableCommand{Name: "workstation", Users: accounts}, lookup); err == nil {
			t.Fatalf("invalid account list accepted: %v", accounts)
		}
	}
	if err := validateSSHEnable(sshEnableCommand{Name: "workstation", Users: []string{"chase", "deploy"}}, lookup); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"0xcadams-laptop", strings.Repeat("a", 33), "nested.host"} {
		if err := validateSSHEnable(sshEnableCommand{Name: name, Users: []string{"chase"}}, func(string) (*user.User, error) {
			t.Fatal("invalid job name reached account lookup")
			return nil, nil
		}); err == nil {
			t.Fatalf("invalid enrollment/job name accepted: %q", name)
		}
	}
}

type sshSetupFake struct {
	request controlv1.CreatePublicURLRequest
	events  []string
}

func (f *sshSetupFake) CreatePublicURL(_ context.Context, r controlv1.CreatePublicURLRequest, key string) (controlv1.PublicURL, error) {
	f.request = r
	f.events = append(f.events, "create")
	return controlv1.PublicURL{Id: "url_0123456789abcdefghijkl", TeamId: r.TeamId, CanonicalHostname: r.CanonicalHostname, ServiceProtocol: *r.ServiceProtocol, AccessMode: *r.AccessMode, SshHostKey: r.SshHostKey}, nil
}

func (f *sshSetupFake) CreatePublisherEnrollment(_ context.Context, r controlv1.CreatePublisherEnrollmentRequest) (controlv1.PublisherEnrollment, error) {
	f.events = append(f.events, "enroll")
	return controlv1.PublisherEnrollment{Id: "pen_0123456789abcdefghijkl", EnrollmentKey: "pen_0123456789abcdefghijkl.one-use", TeamId: r.TeamId, Kind: "saved_url", PublicUrlId: r.PublicUrlId, ExpiresAt: time.Now().Add(time.Minute)}, nil
}

func TestSSHEnablePreparesTargetlessScopedPrivateHandoff(t *testing.T) {
	api := &sshSetupFake{}
	payload, err := prepareSSHHost(t.Context(), api, controlv1.CreatePublicURLRequest{TeamId: "team", CanonicalHostname: "workstation.example.test"}, "workstation", []string{"chase", "deploy"}, "https://control.example.test", func(_ context.Context, urlID, account string) error {
		api.events = append(api.events, "grant:"+account)
		if urlID != "url_0123456789abcdefghijkl" {
			t.Fatal("self grant used another URL")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if api.request.Target != "" || *api.request.ServiceProtocol != controlv1.Ssh || *api.request.AccessMode != controlv1.Restricted || !reflect.DeepEqual(api.events, []string{"create", "grant:chase", "grant:deploy", "enroll"}) {
		t.Fatalf("managed SSH setup boundary: %+v, %v", api.request, api.events)
	}
	block, _ := pem.Decode(payload.HostPrivateKey)
	if block == nil {
		t.Fatal("host install payload has no private key")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil || strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey()))) != *api.request.SshHostKey {
		t.Fatalf("installed host key does not match control pin: %v", err)
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"access_token", "refresh_token", "state_dir", "target"} {
		if bytes.Contains(encoded, []byte(forbidden)) {
			t.Fatalf("private install handoff includes %s", forbidden)
		}
	}
	grantErr := errors.New("self grant rejected")
	api = &sshSetupFake{}
	if _, err := prepareSSHHost(t.Context(), api, controlv1.CreatePublicURLRequest{TeamId: "team", CanonicalHostname: "workstation.example.test"}, "workstation", []string{"chase"}, "https://control.example.test", func(context.Context, string, string) error { return grantErr }); !errors.Is(err, grantErr) || len(api.events) != 1 {
		t.Fatalf("enrollment continued after grant rejection: %v, %v", err, api.events)
	}
}

func TestSSHEnableRejectsInvalidSetupBeforeLogin(t *testing.T) {
	err := runSSHEnable(t.Context(), sshEnableCommand{Name: "invalid.name", Users: []string{"root"}}, io.Discard, io.Discard)
	if reason, ok := failure.ReasonOf(err); !ok || reason != failure.InvalidSetupInput {
		t.Fatalf("invalid setup reached login: %v", err)
	}
}

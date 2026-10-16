package main

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"os/user"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/alecthomas/kong"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/managedssh"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
	"golang.org/x/crypto/ssh"
)

func TestServiceSSHCommandModel(t *testing.T) {
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"service", "ssh", "enable", "--name", "workstation", "--user", "chase", "--user", "deploy"}, "service ssh enable"},
		{[]string{"service", "ssh", "install"}, "service ssh install"},
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
			if tc.want == "service ssh enable" && !reflect.DeepEqual(flags.Service.SSH.Enable.Users, []string{"chase", "deploy"}) {
				t.Fatalf("account allowlist: %#v", flags.Service.SSH.Enable.Users)
			}
		})
	}
	for _, args := range [][]string{
		{"ssh", "chase@workstation.example.test"}, {"ssh", "run", "chase@workstation.example.test"},
		{"ssh", "connect", "--public-url-id", "url_0123456789abcdefghijkl"},
		{"ssh", "copy", "local.txt", "chase@workstation.example.test:remote.txt"},
		{"ssh", "sftp", "chase@workstation.example.test"}, {"ssh", "enable"}, {"ssh", "install"},
		{"service", "ssh", "connect"}, {"service", "ssh", "install", "--public-port", "2222"},
	} {
		var flags cli
		parser, err := kong.New(&flags)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := parser.Parse(args); err == nil {
			t.Fatalf("removed visitor command or private installer flag accepted: %q", args)
		}
	}
}

func TestServiceSSHHelpExposesOnlyHostSetup(t *testing.T) {
	var flags cli
	var output bytes.Buffer
	parser, err := kong.New(&flags, kong.Name("tnl"), kong.Writers(&output, io.Discard), kong.Exit(func(int) {}))
	if err != nil {
		t.Fatal(err)
	}
	// the real help path exits before command validation; the test keeps running.
	if _, err := parser.Parse([]string{"service", "ssh", "--help"}); err != nil && output.Len() == 0 {
		t.Fatal(err)
	}
	text := strings.Join(strings.Fields(output.String()), " ")
	if !strings.Contains(text, "service ssh enable") || strings.Contains(text, "service ssh install") || strings.Contains(text, "connect") || strings.Contains(text, "sftp") || strings.Contains(text, "--protocol") {
		t.Fatalf("service SSH help: %s", text)
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
	mutate  func(*controlv1.PublicURL)
}

func (f *sshSetupFake) CreatePublicURL(_ context.Context, r controlv1.CreatePublicURLRequest, _ string) (controlv1.PublicURL, error) {
	f.request = r
	f.events = append(f.events, "create")
	port := 2222
	saved := controlv1.PublicURL{Id: "url_0123456789abcdefghijkl", TeamId: r.TeamId, CanonicalHostname: r.CanonicalHostname, PublicPort: &port, ServiceProtocol: *r.ServiceProtocol, AccessMode: *r.AccessMode, SshHostKey: r.SshHostKey}
	if f.mutate != nil {
		f.mutate(&saved)
	}
	return saved, nil
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
	if payload.PublicPort != 2222 || api.request.Target != "" || *api.request.ServiceProtocol != controlv1.Ssh || *api.request.AccessMode != controlv1.Restricted || !reflect.DeepEqual(api.events, []string{"create", "grant:chase", "grant:deploy", "enroll"}) {
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
}

func TestSSHEnableRejectsInvalidSavedPortAndPin(t *testing.T) {
	for name, mutate := range map[string]func(*controlv1.PublicURL){
		"missing port":  func(saved *controlv1.PublicURL) { saved.PublicPort = nil },
		"low port":      func(saved *controlv1.PublicURL) { *saved.PublicPort = 1023 },
		"high port":     func(saved *controlv1.PublicURL) { *saved.PublicPort = 65536 },
		"different pin": func(saved *controlv1.PublicURL) { pin := "different"; saved.SshHostKey = &pin },
	} {
		t.Run(name, func(t *testing.T) {
			api := &sshSetupFake{mutate: mutate}
			_, err := prepareSSHHost(t.Context(), api, controlv1.CreatePublicURLRequest{TeamId: "team", CanonicalHostname: "workstation.example.test"}, "workstation", []string{"deploy"}, "https://control.example.test", func(context.Context, string, string) error {
				t.Fatal("invalid saved host reached self grant")
				return nil
			})
			if reason, ok := failure.ReasonOf(err); !ok || reason != failure.ServerResponseInvalid || !reflect.DeepEqual(api.events, []string{"create"}) {
				t.Fatalf("invalid saved host accepted: %v", err)
			}
		})
	}
}

func TestSSHHostInstalledOutputUsesPublicConnectionMetadata(t *testing.T) {
	payload := sshInstallFixture(t)
	var output bytes.Buffer
	if err := writeSSHHostInstalled(&output, payload); err != nil {
		t.Fatal(err)
	}
	signer, err := managedssh.ParseHostKey(payload.HostPrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{"tnl service ssh enable", payload.Hostname, "2222", ssh.FingerprintSHA256(signer.PublicKey()), "ssh deploy@workstation.example.test -p 2222", "visitor access awaits server integration"} {
		if !strings.Contains(output.String(), expected) {
			t.Fatalf("installed host field missing: %s", expected)
		}
	}
	for _, secret := range []string{string(payload.HostPrivateKey), payload.EnrollmentKey, "tnl ssh "} {
		if strings.Contains(output.String(), secret) {
			t.Fatal("private setup or removed visitor path escaped the renderer")
		}
	}
}

func TestSSHEnableRejectsInvalidSetupBeforeLogin(t *testing.T) {
	err := runSSHEnable(t.Context(), sshEnableCommand{Name: "invalid.name", Users: []string{"root"}}, io.Discard, io.Discard)
	if reason, ok := failure.ReasonOf(err); !ok || reason != failure.InvalidSetupInput {
		t.Fatalf("invalid setup reached login: %v", err)
	}
}

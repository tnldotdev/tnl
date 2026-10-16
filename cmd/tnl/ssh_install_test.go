package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/user"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/clientauth"
	"github.com/tnldotdev/tnl/internal/controlclient"
	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/managedssh"
	nativeauth "github.com/tnldotdev/tnl/internal/publisheridentity/native"
	"github.com/tnldotdev/tnl/internal/publisherjob"
	"github.com/tnldotdev/tnl/pkg/api/authorityv1"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
	"golang.org/x/crypto/ssh"
)

func sshInstallFixture(t *testing.T) sshHostInstallPayload {
	t.Helper()
	key, _, err := managedssh.GenerateHostKey()
	if err != nil {
		t.Fatal(err)
	}
	return sshHostInstallPayload{Version: 1, Name: "workstation", Server: "https://control.example.test", PublicURLID: "url_0123456789abcdefghijkl", TeamID: "tm_0123456789abcdefghijkl", Hostname: "workstation.example.test", PublicPort: 2222, Users: []string{"deploy"}, EnrollmentKey: "pen_0123456789abcdefghijkl.one-use", HostPrivateKey: key}
}

func TestSSHInstallInputIsBoundedAndStrict(t *testing.T) {
	payload := sshInstallFixture(t)
	valid, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := decodeSSHHostInstallPayload(bytes.NewReader(valid)); err != nil || !reflect.DeepEqual(got, payload) {
		t.Fatalf("valid install input: %v", err)
	}
	for name, input := range map[string][]byte{
		"oversize":         bytes.Repeat([]byte{' '}, maxSSHHostInstallPayload+1),
		"trailing object":  append(append([]byte(nil), valid...), []byte(" {}")...),
		"trailing scalar":  append(append([]byte(nil), valid...), []byte(" true")...),
		"arbitrary binary": append(append([]byte(nil), valid[:len(valid)-1]...), []byte(`,"binary":"/private/operator-secret"}`)...),
		"arbitrary state":  append(append([]byte(nil), valid[:len(valid)-1]...), []byte(`,"system_state_dir":"/private/operator-secret"}`)...),
		"operator token":   append(append([]byte(nil), valid[:len(valid)-1]...), []byte(`,"access_token":"operator-secret"}`)...),
	} {
		t.Run(name, func(t *testing.T) {
			_, err := decodeSSHHostInstallPayload(bytes.NewReader(input))
			if reason, ok := failure.ReasonOf(err); !ok || reason != failure.InvalidSetupInput {
				t.Fatalf("unsafe install input accepted: %v", err)
			}
			var output bytes.Buffer
			writeCommandError(&output, err)
			if strings.Contains(output.String(), "operator-secret") || bytes.Contains(output.Bytes(), payload.HostPrivateKey) {
				t.Fatal("installer diagnostic disclosed private input")
			}
		})
	}
	for _, mutate := range []func(*sshHostInstallPayload){
		func(p *sshHostInstallPayload) { p.Version++ },
		func(p *sshHostInstallPayload) { p.Name = "../job" },
		func(p *sshHostInstallPayload) { p.Server = "https://token@control.example.test" },
		func(p *sshHostInstallPayload) { p.PublicURLID += "%h" },
		func(p *sshHostInstallPayload) { p.PublicPort = 0 },
		func(p *sshHostInstallPayload) { p.PublicPort = 1023 },
		func(p *sshHostInstallPayload) { p.PublicPort = 65536 },
		func(p *sshHostInstallPayload) { p.Users = []string{"root"} },
		func(p *sshHostInstallPayload) { p.Users = []string{"deploy", "deploy"} },
		func(p *sshHostInstallPayload) { p.HostPrivateKey = []byte("private-key-secret") },
	} {
		changed := payload
		mutate(&changed)
		if err := validateSSHHostInstallPayload(changed); err == nil {
			t.Fatal("invalid install settings accepted")
		}
	}
}

func TestSSHInstallerUsesPrivateStdinAndFixedArguments(t *testing.T) {
	payload := sshInstallFixture(t)
	for _, root := range []bool{false, true} {
		calls := 0
		err := invokeSSHHostInstall(t.Context(), payload, "/absolute/tnl's binary", root, io.Discard, func(_ context.Context, program string, args []string, input io.Reader, _ io.Writer) error {
			calls++
			wantProgram, wantArgs := "/usr/bin/sudo", []string{"-n", "--", "/absolute/tnl's binary", "service", "ssh", "install"}
			if root {
				wantProgram, wantArgs = "/absolute/tnl's binary", []string{"service", "ssh", "install"}
			}
			if program != wantProgram || !reflect.DeepEqual(args, wantArgs) {
				t.Fatalf("installer command: %s %q", program, args)
			}
			got, err := decodeSSHHostInstallPayload(input)
			if err != nil || !reflect.DeepEqual(got, payload) {
				t.Fatalf("private stdin changed: %v", err)
			}
			return nil
		})
		if err != nil || calls != 1 {
			t.Fatalf("installer handoff: %v; calls %d", err, calls)
		}
	}
}

func TestSSHInstallerCommandDoesNotInheritOperatorEnvironment(t *testing.T) {
	t.Setenv("TNL_ACCESS_TOKEN", "operator-secret")
	t.Setenv("TNL_STATE_DIR", "/operator-state")
	t.Setenv("TNL_PUBLISHER_FILE", "/operator-file")
	path := filepath.Join(t.TempDir(), "installer")
	if err := os.WriteFile(path, []byte("#!/bin/sh\nif [ -n \"${TNL_ACCESS_TOKEN+x}${TNL_STATE_DIR+x}${TNL_PUBLISHER_FILE+x}\" ]; then exit 7; fi\n/bin/cat >/dev/null\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := executeSSHInstaller(t.Context(), path, nil, strings.NewReader("private stdin"), io.Discard); err != nil {
		t.Fatal(err)
	}
}

func TestSSHHostJobEnrolledOnlyIntoItsExactRootProfile(t *testing.T) {
	var account string
	candidates := []string{"nobody", "daemon"}
	if current, err := user.Current(); err == nil {
		candidates = append([]string{current.Username}, candidates...)
	}
	for _, candidate := range candidates {
		if validSSHAccount(candidate) && managedssh.ValidateUsers([]string{candidate}) == nil {
			account = candidate
			break
		}
	}
	if account == "" {
		t.Skip("no existing nonroot local account is available")
	}
	for _, mismatch := range []string{"", "host key", "url", "team", "hostname", "missing port", "low port", "high port", "different port", "target", "anonymous", "namespace"} {
		t.Run(mismatch, func(t *testing.T) {
			registry, authority, control, _ := backgroundFixture(t)
			payload := sshInstallFixture(t)
			payload.Users = []string{account}
			payload.PublicURLID = *authority.identity.PublicUrlId
			authority.identity.TeamId = payload.TeamID
			signer, err := managedssh.ParseHostKey(payload.HostPrivateKey)
			if err != nil {
				t.Fatal(err)
			}
			pin := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey())))
			port := payload.PublicPort
			control.publicURL = controlv1.PublicURL{Id: payload.PublicURLID, TeamId: payload.TeamID, CanonicalHostname: payload.Hostname, PublicPort: &port, LifecycleState: controlv1.Enabled, Purpose: controlv1.App, ServiceProtocol: controlv1.Ssh, AccessMode: controlv1.Restricted, SshHostKey: &pin}
			switch mismatch {
			case "host key":
				_, other, err := managedssh.GenerateHostKey()
				if err != nil {
					t.Fatal(err)
				}
				control.publicURL.SshHostKey = &other
			case "url":
				control.publicURL.Id = "url_abcdefghijkl0123456789"
			case "team":
				authority.identity.TeamId = "tm_abcdefghijkl0123456789"
			case "hostname":
				control.publicURL.CanonicalHostname = "other.example.test"
			case "missing port":
				control.publicURL.PublicPort = nil
			case "low port":
				port = 1023
			case "high port":
				port = 65536
			case "different port":
				port++
			case "target":
				control.publicURL.Target = "localhost:22"
			case "anonymous":
				control.publicURL.AccessMode = controlv1.Anonymous
			case "namespace":
				domain, namespace := "dom_0123456789abcdefghijkl", "member.example.test"
				authority.identity.Kind, authority.identity.PublicUrlId, authority.identity.DomainId, authority.identity.Namespace = "namespace", nil, &domain, &namespace
			}
			err = installSSHHostJob(t.Context(), registry, payload, func(job publisherjob.Job) (nativeauth.NativeControl, nativeauth.EnrollmentAuthority, error) {
				if job.Target != "" || job.Protocol != controlv1.Ssh || job.Server != payload.Server {
					t.Fatal("installer attempted raw SSH forwarding or selected another server")
				}
				return control, authority, nil
			})
			jobs, listErr := registry.List(t.Context())
			if listErr != nil {
				t.Fatal(listErr)
			}
			if mismatch != "" {
				if err == nil || len(jobs) != 0 {
					t.Fatalf("mismatched scope installed: %v, %d jobs", err, len(jobs))
				}
				return
			}
			if err != nil || len(jobs) != 1 || !bytes.Equal(jobs[0].SSHHostKey, payload.HostPrivateKey) || !reflect.DeepEqual(jobs[0].SSHUsers, payload.Users) {
				t.Fatalf("targetless SSH job installation failed: %v, %d jobs", err, len(jobs))
			}
			payload.EnrollmentExpiresAt = time.Now().Add(-time.Hour)
			if err := installSSHHostJob(t.Context(), registry, payload, func(publisherjob.Job) (nativeauth.NativeControl, nativeauth.EnrollmentAuthority, error) {
				t.Fatal("an installed retry attempted another enrollment")
				return nil, nil, nil
			}); err != nil {
				t.Fatal(err)
			}
			retried, err := registry.List(t.Context())
			if err != nil || len(retried) != 1 || retried[0].Revision != jobs[0].Revision || authority.redemptions != 1 {
				t.Fatalf("installed retry changed identity or revision: %v", err)
			}
			changed := payload
			changed.Users = append([]string(nil), payload.Users...)
			changed.Users = append(changed.Users, "another-account")
			if err := installSSHHostJob(t.Context(), registry, changed, nil); err == nil {
				t.Fatal("retry silently widened the installed allowlist")
			}
			profile, err := registry.Profile(t.Context(), payload.Server)
			if err != nil {
				t.Fatal(err)
			}
			if _, found, err := profile.PublisherSigningIdentity(t.Context(), "job:"+payload.Name); err != nil || !found {
				t.Fatalf("job identity was not saved in root profile: %v", err)
			}
			if _, found, err := profile.ControlSession(t.Context()); err != nil || found {
				t.Fatalf("root state acquired an operator session: %v", err)
			}
			var output bytes.Buffer
			if err := renderSystemJobs(&output, "tnl service status", jobs, payload.Name); err != nil || bytes.Contains(output.Bytes(), payload.HostPrivateKey) || !strings.Contains(output.String(), account) || !strings.Contains(output.String(), ssh.FingerprintSHA256(signer.PublicKey())) {
				t.Fatalf("unsafe or missing SSH job status: %v", err)
			}
		})
	}
}

func TestSSHRootEnrollmentRefreshRequiresNoPreviousAttempt(t *testing.T) {
	registry, authority, control, _ := backgroundFixture(t)
	payload := sshInstallFixture(t)
	payload.PublicURLID = *authority.identity.PublicUrlId
	authority.identity.TeamId = payload.TeamID
	payload.EnrollmentExpiresAt = time.Now().Add(-time.Minute)
	clients := func(publisherjob.Job) (nativeauth.NativeControl, nativeauth.EnrollmentAuthority, error) {
		return control, authority, nil
	}
	if err := installSSHHostJob(t.Context(), registry, payload, clients); !errors.Is(err, errSSHEnrollmentRefresh) || authority.redemptions != 0 {
		t.Fatalf("unused expired enrollment was redeemed: %v", err)
	}
	profile, err := registry.Profile(t.Context(), payload.Server)
	if err != nil {
		t.Fatal(err)
	}
	state, err := profile.LockSSHHostSetup(t.Context(), payload.TeamID, payload.Hostname)
	if err != nil {
		t.Fatal(err)
	}
	if _, found, err := state.Read(t.Context()); err != nil || found {
		t.Fatalf("refresh probe wrote a redemption marker: %v", err)
	}
	// simulate a durable prior attempt whose native pending row was pruned.
	if err := state.Save(t.Context(), []byte(`{"PublicURLID":"different-prior-attempt"}`)); err != nil {
		t.Fatal(err)
	}
	state.Close()
	if err := installSSHHostJob(t.Context(), registry, payload, clients); err == nil || errors.Is(err, errSSHEnrollmentRefresh) || authority.redemptions != 0 {
		t.Fatalf("uncertain root attempt allowed a fresh enrollment: %v", err)
	}
}

func TestSSHInstallerResponseIsBoundedAndSecretFree(t *testing.T) {
	if err := readSSHInstallResponse([]byte(`{"state":"installed"}`)); err != nil {
		t.Fatal(err)
	}
	if err := readSSHInstallResponse([]byte(`{"state":"enrollment_required"}`)); !errors.Is(err, errSSHEnrollmentRefresh) {
		t.Fatal(err)
	}
	for _, input := range []string{`{"state":"installed","key":"secret"}`, `{"state":"installed"} {}`, `{"state":"other"}`} {
		if err := readSSHInstallResponse([]byte(input)); err == nil {
			t.Fatal("invalid installer acknowledgment accepted")
		}
	}
	var buffer sshInstallResponseBuffer
	if _, err := buffer.Write(make([]byte, 2049)); err == nil {
		t.Fatal("unbounded installer response accepted")
	}
}

func TestSSHHostSelfGrantUsesAuthenticatedIdentityAndAccount(t *testing.T) {
	const identity = "ident_0123456789abcdefghijkl"
	const urlID = "url_0123456789abcdefghijkl"
	posts := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		posts++
		var request controlv1.CreateIdentityVisitorGrantRequest
		if r.Method != http.MethodPost || r.URL.Path != "/v1/public-urls/"+urlID+"/visitor-identity-grants" || r.Header.Get("Authorization") != "Bearer operator" || r.Header.Get("Idempotency-Key") == "" {
			t.Errorf("unexpected self-grant request: %s %s", r.Method, r.URL.Path)
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Error(err)
		}
		if request.IdentityId != identity || request.SshUser == nil || *request.SshUser != "deploy" {
			t.Error("self grant did not bind the authenticated identity and account")
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(controlv1.VisitorGrant{Id: "grant", PublicUrlId: urlID, Kind: "identity", IdentityId: &request.IdentityId, SshUser: request.SshUser})
	}))
	defer server.Close()
	control, err := controlclient.New(server.URL, server.Client(), credentials.AccessToken("operator"))
	if err != nil {
		t.Fatal(err)
	}
	session := &teamSession{authenticated: &clientauth.Client{Control: control}, identity: authorityv1.IdentityContext{Identity: authorityv1.Identity{Id: identity}}}
	if err := grantSSHHostSelfAccess(t.Context(), session, urlID, "deploy"); err != nil || posts != 1 {
		t.Fatalf("self grant: %v; posts %d", err, posts)
	}
}

func TestSSHChildDispatchAcceptsOnlyThePrivateEntryPoint(t *testing.T) {
	if !isSSHChildCommand([]string{"runtime", "ssh-child"}) {
		t.Fatal("private child entry point missing")
	}
	for _, args := range [][]string{{"runtime", "ssh-child", "id"}, {"runtime", "ssh-child", "--user", "root"}, {"ssh-child"}} {
		if isSSHChildCommand(args) {
			t.Fatal("untrusted child arguments accepted")
		}
	}
}

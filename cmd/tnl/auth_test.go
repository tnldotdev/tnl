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
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/client/auth"
	clientauthority "github.com/tnldotdev/tnl/internal/client/authority"
	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/failure/diagnostic"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestAuthCommandParsing(t *testing.T) {
	for _, test := range []struct {
		args    []string
		command string
	}{
		{[]string{"auth", "status", "--output=json"}, "auth status"},
		{[]string{"auth", "status", "--check"}, "auth status"},
		{[]string{"auth", "login", "--open"}, "auth login"},
		{[]string{"auth", "login", "--open", "--copy-code"}, "auth login"},
		{[]string{"auth", "login", "--output=json"}, "auth login"},
		{[]string{"auth", "login", "start", "--output=json"}, "auth login start"},
		{[]string{"auth", "login", "wait", "auth_01234567890123456789012345678901", "--timeout=2s"}, "auth login wait <operation-id>"},
		{[]string{"auth", "login", "inspect", "auth_01234567890123456789012345678901"}, "auth login inspect <operation-id>"},
		{[]string{"auth", "login", "cancel", "auth_01234567890123456789012345678901"}, "auth login cancel <operation-id>"},
		{[]string{"auth", "logout", "--output=json"}, "auth logout"},
	} {
		t.Run(strings.Join(test.args, " "), func(t *testing.T) {
			var flags cli
			parser := commandForTest(&flags, io.Discard)
			parsed, err := parser(test.args)
			if err != nil {
				t.Fatal(err)
			}
			if got := commandID(parsed); got != test.command {
				t.Fatalf("command = %q", got)
			}
		})
	}
	for _, unsupported := range []string{"login", "logout", "auth login --pkce", "auth login --token", "auth login --no-open", "auth login --login-token", "auth login start --copy-code"} {
		var flags cli
		parser := commandForTest(&flags, io.Discard)
		if _, err := parser(strings.Split(unsupported, " ")); err == nil {
			t.Fatalf("unexpectedly accepted %s", unsupported)
		}
	}
}

func TestLoginResumeSelectsOriginalServerAndState(t *testing.T) {
	clientstate.UseMemoryKeychainForTesting()
	t.Setenv("TNL_SERVER", "")
	db, err := clientstate.Open(t.Context(), filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	const alternate = "https://control.example.test"
	op := clientstate.AuthOperation{
		ID: "auth_01234567890123456789012345678901", Server: defaultServerURL, Method: "device_code",
		Phase: clientstate.AuthPending, ExpiresAt: time.Now().Add(time.Minute), ApprovalURL: defaultServerURL + "/v1/auth/device/approve",
	}
	flags := loginCommand{StateDir: "/some user/state"}
	want := "tnl auth login wait " + op.ID
	if got := (loginCommand{}).resumeCommand(t.Context(), db, op); got != want {
		t.Fatalf("hosted login added unnecessary flags: %s", got)
	}
	check := func(serverArg string) {
		t.Helper()
		if got := flags.resumeCommand(t.Context(), db, op); got != want+serverArg+" --state-dir='/some user/state'" {
			t.Fatalf("resume command = %q", got)
		}
	}
	check("")
	flags.projectServer = new(alternate)
	check(" --server=" + defaultServerURL)
	flags.projectServer = nil
	if err := db.SaveServer(t.Context(), alternate); err != nil {
		t.Fatal(err)
	}
	check(" --server=" + defaultServerURL)
	if pin := suggestedServer(t.Context(), defaultServerURL, nil, "", db.Root(), nil); pin != defaultServerURL {
		t.Fatalf("a follow-up without an open database ignored the saved server: %q", pin)
	}
	t.Setenv("TNL_SERVER", defaultServerURL)
	check("")
	op.Server = alternate
	check(" --server=" + alternate)
	op.ExpiresAt = time.Now().Add(-time.Minute)
	if got := flags.resumeCommand(t.Context(), db, op); got != "" {
		t.Fatalf("offered to resume expired challenge: %s", got)
	}
	op.ExpiresAt = time.Now().Add(time.Minute)
	op.Phase = clientstate.AuthCancelled
	if got := flags.resumeCommand(t.Context(), db, op); got != "" {
		t.Fatalf("offered to resume cancelled login: %s", got)
	}
}

func TestLoginHostedApprovalAndSuccess(t *testing.T) {
	const code = "ABCDEF-123456"
	const url = defaultServerURL + "/v1/auth/device/approve?code=" + code
	op := clientstate.AuthOperation{ApprovalURL: url, UserCode: code, Phase: clientstate.AuthPending, ExpiresAt: time.Now().Add(time.Minute)}
	for _, test := range []struct {
		opening bool
		want    string
	}{
		{false, "Open this URL to sign in:\n" + url + "\nMatch code: " + code + "\nWaiting for approval...\n"},
		{true, "Match code: " + code + "\nIf your browser doesn't open, visit:\n" + url + "\nWaiting for approval...\n"},
	} {
		var diag bytes.Buffer
		if err := writeWaitingLogin(&diag, op, statusOutputHuman, test.opening, ""); err != nil || diag.String() != test.want {
			t.Fatalf("opening=%t: %q, %v", test.opening, &diag, err)
		}
	}
	var out bytes.Buffer
	if err := writeSignedIn(&out, defaultServerURL); err != nil || out.String() != "Signed in.\n" {
		t.Fatalf("successful login = %q; %v", &out, err)
	}
}

type loginPromptWriter func([]byte) (int, error)

func (w loginPromptWriter) Write(p []byte) (int, error) { return w(p) }

func loginChallengeServer(t *testing.T, challenge authorityv1.DeviceLoginChallenge, poll http.HandlerFunc) *httptest.Server {
	t.Helper()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/discovery":
			_ = json.NewEncoder(w).Encode(controlv1.ControlDiscovery{Authentication: controlv1.AuthenticationFacts{Methods: []controlv1.AuthenticationFactsMethods{controlv1.Oidc}, Oidc: &controlv1.OIDCAuthenticationFacts{Issuer: "https://issuer.example", LoginFlow: controlv1.DeviceCode}}})
		case "/v1/auth/device":
			response := challenge
			response.ApprovalUrl = "https://" + r.Host + "/v1/auth/device/approve?code=" + challenge.UserCode
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(response)
		case "/v1/auth/device/poll":
			if poll != nil {
				poll(w, r)
				return
			}
			fallthrough
		default:
			t.Errorf("unexpected login request: %s", r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)
	before := http.DefaultTransport
	http.DefaultTransport = server.Client().Transport
	t.Cleanup(func() { http.DefaultTransport = before })
	return server
}

func TestLoginApprovalResumeAndStreams(t *testing.T) {
	clientstate.UseMemoryKeychainForTesting()
	const code = "ABCDEF-123456"
	secret := strings.Repeat("p", 43)
	expires := time.Now().UTC().Add(10 * time.Minute)
	server := loginChallengeServer(t, authorityv1.DeviceLoginChallenge{PollingCredential: secret, UserCode: code, ExpiresAt: expires, IntervalSeconds: 30}, nil)
	flags := loginCommand{StateDir: filepath.Join(t.TempDir(), "client state"), ServerURL: server.URL, Timeout: time.Millisecond}
	var out, diag bytes.Buffer
	if err := runAuthLoginStart(t.Context(), flags, &out, &diag); err != nil {
		t.Fatal(err)
	}
	approval := "Open this URL to sign in:\n" + server.URL + "/v1/auth/device/approve?code=" + code + "\nMatch code: " + code + "\n"
	resume := strings.Split(strings.TrimSpace(out.String()), "\n")
	fields := strings.Fields(resume[len(resume)-1])
	if len(fields) < 5 || !strings.HasPrefix(fields[4], "auth_") {
		t.Fatalf("missing operation ID in start: %s", &out)
	}
	id := fields[4]
	cmd := "tnl auth login wait " + id + " --server=" + server.URL + " --state-dir=" + shellWord(flags.StateDir)
	start := approval + "Finish login before " + expires.Format("15:04 MST") + ":\n" + cmd + "\n"
	if out.String() != start || diag.Len() != 0 {
		t.Fatalf("start = %q; diagnostics = %q", &out, &diag)
	}
	out.Reset()
	if err := runAuthLoginOperation(t.Context(), flags, id, "inspect", &out, &diag); err != nil || out.String() != start || diag.Len() != 0 {
		t.Fatalf("inspect = %q; diagnostics = %q; %v", &out, &diag, err)
	}
	out.Reset()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	waiting := approval + "Waiting for approval...\n"
	err := runLogin(ctx, flags, loginDesktopActions{}, &out, loginPromptWriter(func(p []byte) (int, error) {
		if diag.Len() == 0 {
			if string(p) != waiting {
				t.Fatalf("active login prompt = %q", p)
			}
			cancel()
		}
		return diag.Write(p)
	}))
	if !errors.Is(err, context.Canceled) || diag.String() != waiting+"Resume login:\n"+cmd+"\n" || out.Len() != 0 {
		t.Fatalf("interrupted login = %q; diagnostics = %q; %v", &out, &diag, err)
	}
	diag.Reset()
	err = runAuthLoginOperation(t.Context(), flags, id, "wait", &out, &diag)
	if reason, _ := failure.ReasonOf(err); reason != failure.AuthWaitTimeout || diag.String() != waiting || out.Len() != 0 {
		t.Fatalf("timed-out wait = %q; diagnostics = %q; %v", &out, &diag, err)
	}
	writeCommandError(&diag, err)
	if strings.Count(diag.String(), "tnl auth login wait ") != 1 || !strings.Contains(diag.String(), "Resume login:\n"+cmd+"\n") || strings.Contains(diag.String(), "<operation-id>") {
		t.Fatalf("timeout should show one usable resume command: %s", &diag)
	}
	diag.Reset()
	flags.Output = statusOutputJSON
	err = runLogin(t.Context(), flags, loginDesktopActions{}, &out, &diag)
	var event struct {
		SchemaVersion int `json:"schema_version"`
		clientstate.AuthOperation
	}
	if reason, _ := failure.ReasonOf(err); reason != failure.AuthWaitTimeout || out.Len() != 0 || json.Unmarshal(diag.Bytes(), &event) != nil ||
		event.SchemaVersion != 1 || event.ID != id || event.UserCode != code || strings.Contains(diag.String(), secret) {
		t.Fatalf("machine login = %q; diagnostics = %q; %v", &out, &diag, err)
	}
}

func TestAuthLoginExplicitDesktopActions(t *testing.T) {
	browser, clipboard := "open", "pbcopy"
	if runtime.GOOS == "linux" {
		browser, clipboard = "xdg-open", "wl-copy"
		t.Setenv("WAYLAND_DISPLAY", "test-wayland")
		t.Setenv("DISPLAY", "")
	} else if runtime.GOOS != "darwin" {
		t.Skip("native desktop helpers are not supported")
	}
	clientstate.UseMemoryKeychainForTesting()
	const code, helperOutput = "ABCDEF-123456", "private helper output"
	secret := strings.Repeat("p", 43)
	server := loginChallengeServer(t, authorityv1.DeviceLoginChallenge{
		PollingCredential: secret, UserCode: code, ExpiresAt: time.Now().Add(time.Minute), IntervalSeconds: 30,
	}, nil)
	url := server.URL + "/v1/auth/device/approve?code=" + code
	dir := t.TempDir()
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("AI_AGENT", "test-agent")
	t.Setenv("TNL_OUTPUT", "")
	for name, action := range map[string]string{
		browser:   `printf '%s' "$1" > "$TEST_OPENED_URL"`,
		clipboard: `/bin/cat > "$TEST_COPIED_CODE"`,
	} {
		script := "#!/bin/sh\n" + action + "\nprintf '%s' '" + helperOutput + "'\nprintf '%s' '" + helperOutput + "' >&2\n" + `exit "$TEST_DESKTOP_EXIT"` + "\n"
		if err := os.WriteFile(filepath.Join(dir, name), []byte(script), 0700); err != nil {
			t.Fatal(err)
		}
	}
	for _, tt := range []struct {
		name                   string
		open, copy             bool
		fails, machine, broken bool
	}{
		{name: "no agent default"},
		{name: "open only", open: true},
		{name: "copy only", copy: true, fails: true},
		{name: "both", open: true, copy: true},
		{name: "machine", open: true, copy: true, machine: true, fails: true},
		{name: "broken approval output", open: true, copy: true, broken: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			root, opened, copied := filepath.Join(dir, "client state"), filepath.Join(dir, "opened"), filepath.Join(dir, "copied")
			t.Setenv("TEST_OPENED_URL", opened)
			t.Setenv("TEST_COPIED_CODE", copied)
			exit := "0"
			if tt.fails {
				exit = "1"
			}
			t.Setenv("TEST_DESKTOP_EXIT", exit)
			args := []string{"--no-config", "auth", "login", "--server=" + server.URL, "--state-dir=" + root, "--timeout=1ms"}
			if tt.open {
				args = append(args, "--open")
			}
			if tt.copy {
				args = append(args, "--copy-code")
			}
			if tt.machine {
				args = append(args, "--output=json")
			}
			checkFile := func(path, want string) {
				t.Helper()
				got, err := os.ReadFile(path)
				if want == "" && !errors.Is(err, os.ErrNotExist) || want != "" && (err != nil || string(got) != want) {
					t.Fatalf("%s: got %q, %v; want %q", path, got, err, want)
				}
			}
			var out, diag bytes.Buffer
			var resume string
			wrote := false
			err := run(t.Context(), args, &out, loginPromptWriter(func(p []byte) (int, error) {
				if !wrote {
					wrote = true
					checkFile(opened, "")
					checkFile(copied, "")
					// a separate reader can resume the operation before any helper runs.
					db, err := clientstate.Open(t.Context(), root)
					if err != nil {
						t.Fatal(err)
					}
					defer db.Close()
					store, err := db.Server(t.Context(), server.URL)
					if err != nil {
						t.Fatal(err)
					}
					op, found, err := store.ActiveAuthOperation(t.Context())
					if err != nil || !found || op.Phase != clientstate.AuthPending || op.UserCode != code || op.ApprovalURL != url {
						t.Fatal("approval not durable before rendering")
					}
					resume = "tnl --no-config auth login wait " + op.ID + " --server=" + server.URL + " --state-dir=" + shellWord(root)
					if tt.machine {
						var event map[string]json.RawMessage
						if err := json.Unmarshal(p, &event); err != nil || string(event["schema_version"]) != "1" ||
							string(event["operation_id"]) != `"`+op.ID+`"` || string(event["user_code"]) != `"`+code+`"` ||
							string(event["approval_url"]) != `"`+url+`"` || bytes.Contains(p, []byte(resume)) {
							t.Fatalf("machine approval changed: %s", p)
						}
					} else if !bytes.Contains(p, []byte("\n"+url+"\n")) || !bytes.Contains(p, []byte("Match code: "+code+"\n")) ||
						(tt.open || tt.copy) && !bytes.Contains(p, []byte("Resume login:\n"+resume+"\n")) {
						t.Fatalf("human approval not visible and resumable: %s", p)
					}
					if tt.broken {
						return 0, io.ErrClosedPipe
					}
				}
				return diag.Write(p)
			}))
			wantReason := failure.AuthWaitTimeout
			if tt.broken {
				wantReason = failure.OutputUnavailable
			}
			if reason, _ := failure.ReasonOf(err); reason != wantReason || out.Len() != 0 || !wrote {
				t.Fatalf("login: %v; stdout %q", err, &out)
			}
			if tt.open && !tt.broken {
				deadline := time.NewTimer(time.Second)
				defer deadline.Stop()
				poll := time.NewTicker(time.Millisecond)
				defer poll.Stop()
				for {
					if b, _ := os.ReadFile(opened); string(b) == url {
						break
					}
					select {
					case <-deadline.C:
						t.Fatal("browser helper did not receive the approval URL")
					case <-poll.C:
					}
				}
			} else {
				checkFile(opened, "")
			}
			if tt.copy && !tt.broken {
				checkFile(copied, code)
			} else {
				checkFile(copied, "")
			}
			if tt.machine {
				if !json.Valid(diag.Bytes()) {
					t.Fatalf("expected one machine approval: %q", &diag)
				}
			} else if !tt.broken {
				writeCommandError(&diag, err)
				if strings.Count(diag.String(), resume) != 1 || strings.Contains(diag.String(), "<operation-id>") {
					t.Fatalf("expected one usable resume command: %q", &diag)
				}
				if strings.Contains(diag.String(), "Could not copy") != (tt.copy && tt.fails) ||
					strings.Contains(diag.String(), "Could not open a browser") {
					t.Fatalf("desktop warning mismatch: %q", &diag)
				}
			}
			if strings.Contains(diag.String(), secret) || strings.Contains(diag.String(), helperOutput) {
				t.Fatal("login emitted the polling credential or helper output")
			}
		})
	}
}

func TestAuthLoginStartWaitJSON(t *testing.T) {
	clientstate.UseMemoryKeychainForTesting()
	const code = "ABCDEF-123456"
	pollCredential := strings.Repeat("p", 43)
	access, _, _, err := credentials.NewAccessToken()
	if err != nil {
		t.Fatal(err)
	}
	refresh, _, _, err := credentials.NewRefreshToken()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	session := authorityv1.ControlSessionResponse{
		SessionId: "cs_0123456789abcdefghijkl", AccessToken: access.String(), RefreshToken: refresh.String(),
		AccessExpiresAt: now.Add(time.Hour), RefreshExpiresAt: now.Add(24 * time.Hour),
	}
	server := loginChallengeServer(t, authorityv1.DeviceLoginChallenge{
		PollingCredential: pollCredential, UserCode: code, ExpiresAt: now.Add(time.Minute), IntervalSeconds: 1,
	}, func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(authorityv1.DeviceLoginResult{Status: authorityv1.DeviceLoginResultStatusApproved, Session: &session})
	})
	selection := []string{"--server=" + server.URL, "--state-dir=" + filepath.Join(t.TempDir(), "state"), "--output=json"}
	call := func(args ...string) clientstate.AuthOperation {
		t.Helper()
		var stdout, stderr bytes.Buffer
		if err := run(t.Context(), append(args, selection...), &stdout, &stderr); err != nil {
			t.Fatal(err)
		}
		if stderr.Len() != 0 {
			t.Fatal("start or wait wrote to stderr")
		}
		for _, private := range []string{pollCredential, access.String(), refresh.String()} {
			if strings.Contains(stdout.String(), private) {
				t.Fatal("start or wait exposed a private credential")
			}
		}
		var result struct {
			SchemaVersion int `json:"schema_version"`
			clientstate.AuthOperation
		}
		if err := json.Unmarshal(stdout.Bytes(), &result); err != nil || result.SchemaVersion != 1 {
			t.Fatalf("invalid login result: %v", err)
		}
		return result.AuthOperation
	}
	started := call("--no-config", "auth", "login", "start")
	if started.ID == "" || started.Phase != clientstate.AuthPending || started.UserCode != code ||
		started.ApprovalURL != server.URL+"/v1/auth/device/approve?code="+code {
		t.Fatal("start did not return the approval details and operation ID")
	}
	completed := call("--no-config", "auth", "login", "wait", started.ID)
	if completed.ID != started.ID || completed.Phase != clientstate.AuthCompleted {
		t.Fatal("wait did not complete the same operation")
	}
}

func TestLoginResumeAfterUnavailablePoll(t *testing.T) {
	clientstate.UseMemoryKeychainForTesting()
	secret := strings.Repeat("p", 43)
	server := loginChallengeServer(t, authorityv1.DeviceLoginChallenge{
		PollingCredential: secret, UserCode: "ABCDEF-123456", ExpiresAt: time.Now().Add(5 * time.Minute), IntervalSeconds: 1,
	}, func(w http.ResponseWriter, _ *http.Request) { http.Error(w, secret, http.StatusServiceUnavailable) })
	root := filepath.Join(t.TempDir(), "client state")
	args := []string{"--no-config", "auth", "login", "--state-dir", root, "--server", server.URL}
	var out, diag bytes.Buffer
	err := run(t.Context(), args, &out, &diag)
	if !errors.Is(err, clientauthority.ErrUnavailable) {
		t.Fatalf("poll failure = %v", err)
	}
	exit, render := terminalResult(err)
	if exit != 1 || render == nil {
		t.Fatalf("terminal result = %d, %v", exit, render)
	}
	writeCommandError(&diag, render)

	var saved bytes.Buffer
	err = runAuthLoginStart(t.Context(), loginCommand{StateDir: root, ServerURL: server.URL, Output: statusOutputJSON}, &saved, io.Discard)
	var op clientstate.AuthOperation
	if err != nil || json.Unmarshal(saved.Bytes(), &op) != nil || op.Phase != clientstate.AuthExchanging || op.ID == "" {
		t.Fatalf("did not recover the polling operation: %v", err)
	}
	cmd := "tnl --no-config auth login wait " + op.ID + " --server=" + server.URL + " --state-dir=" + shellWord(root)
	text := diag.String()
	if out.Len() != 0 || strings.Count(text, "auth login wait") != 1 || !strings.HasSuffix(text, "Resume login:\n"+cmd+"\n") ||
		strings.Count(text, string(diagnostic.ServerUnavailable)) != 1 || strings.Contains(text, secret) {
		t.Fatal("expected the original diagnostic and one scoped resume command on stderr")
	}

	diag.Reset()
	err = run(t.Context(), append(args, "--output=json"), &out, &diag)
	if !errors.Is(err, clientauthority.ErrUnavailable) {
		t.Fatalf("machine poll failure = %v", err)
	}
	writeCommandError(&diag, err)
	dec := json.NewDecoder(&diag)
	var prompt clientstate.AuthOperation
	var result commandDiagnostic
	if strings.Contains(diag.String(), secret) || out.Len() != 0 || dec.Decode(&prompt) != nil || prompt.ID != op.ID ||
		dec.Decode(&result) != nil || result.Code != string(diagnostic.ServerUnavailable) || !result.Retryable || dec.Decode(&struct{}{}) != io.EOF {
		t.Fatal("expected just the operation and its existing JSON diagnostic")
	}
}

func TestAuthStatusJSONDistinguishesSavedAndChecked(t *testing.T) {
	clientstate.UseMemoryKeychainForTesting()
	access, _, _, err := credentials.NewAccessToken()
	if err != nil {
		t.Fatal(err)
	}
	refresh, _, _, err := credentials.NewRefreshToken()
	if err != nil {
		t.Fatal(err)
	}
	var requests, identityRequests atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/discovery":
			_ = json.NewEncoder(w).Encode(controlv1.ControlDiscovery{Authentication: controlv1.AuthenticationFacts{Methods: []controlv1.AuthenticationFactsMethods{controlv1.Oidc}, Oidc: &controlv1.OIDCAuthenticationFacts{Issuer: "https://issuer.example", LoginFlow: controlv1.DeviceCode}}})
		case "/v1/identity":
			identityRequests.Add(1)
			if r.Header.Get("Authorization") != "Bearer "+access.String() {
				t.Error("identity check did not use the saved credential")
			}
			_ = json.NewEncoder(w).Encode(authorityv1.IdentityContext{Identity: authorityv1.Identity{Id: "identity_1", DisplayName: "Test"}, PersonalTeamId: "team_1"})
		default:
			t.Errorf("unexpected status request: %s", r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)
	before := http.DefaultTransport
	http.DefaultTransport = server.Client().Transport
	t.Cleanup(func() { http.DefaultTransport = before })
	root := filepath.Join(t.TempDir(), "state")
	db, err := clientstate.Open(t.Context(), root)
	if err != nil {
		t.Fatal(err)
	}
	store, err := db.Server(t.Context(), server.URL)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if err := store.SaveControlSession(t.Context(), clientstate.ControlSession{SessionID: "cs_0123456789abcdefghijkl", AccessToken: access.String(), RefreshToken: refresh.String(), AccessExpiresAt: now.Add(time.Hour), RefreshExpiresAt: now.Add(24 * time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"available", "authenticated"} {
		var stdout, stderr bytes.Buffer
		check := want == "authenticated"
		args := []string{"--no-config", "auth", "status", "--server=" + server.URL, "--state-dir=" + root, "--output=json"}
		if check {
			args = append(args, "--check")
		}
		if err := run(t.Context(), args, &stdout, &stderr); err != nil {
			t.Fatal(err)
		}
		if stderr.Len() != 0 || strings.Contains(stdout.String(), access.String()) || strings.Contains(stdout.String(), refresh.String()) {
			t.Fatal("status emitted credential or diagnostic")
		}
		var status auth.StatusResult
		if err := json.Unmarshal(stdout.Bytes(), &status); err != nil {
			t.Fatal(err)
		}
		if status.Source != "saved_session" || status.Status != want || status.Checked != check || status.AccessExpiresAt == nil {
			t.Fatalf("status = %#v", status)
		}
		if !check && requests.Load() != 0 || check && identityRequests.Load() != 1 {
			t.Fatalf("check=%t: total requests=%d, identity requests=%d", check, requests.Load(), identityRequests.Load())
		}
	}
}

func TestAuthLogoutCancelsPendingOperationsOffline(t *testing.T) {
	clientstate.UseMemoryKeychainForTesting()
	root := filepath.Join(t.TempDir(), "state")
	db, err := clientstate.Open(t.Context(), root)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	store, err := db.Server(t.Context(), "https://offline.example")
	if err != nil {
		t.Fatal(err)
	}
	id, err := clientstate.NewAuthOperationID()
	if err != nil {
		t.Fatal(err)
	}
	if err := store.CreateAuthOperation(t.Context(), clientstate.AuthOperation{ID: id, Phase: clientstate.AuthPending, Method: "device_code", ExpiresAt: time.Now().Add(time.Minute)}); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if err := runLogout(t.Context(), logoutCommand{ServerURL: "https://offline.example", StateDir: root, Output: statusOutputJSON}, &output); err != nil {
		t.Fatal(err)
	}
	op, err := store.AuthOperation(t.Context(), id)
	if err != nil || op.Phase != clientstate.AuthCancelled || len(op.Private) != 0 {
		t.Fatalf("logout operation = %s, %v", op.Phase, err)
	}
	if !strings.Contains(output.String(), `"status":"logged_out"`) {
		t.Fatalf("logout = %q", output.String())
	}
}

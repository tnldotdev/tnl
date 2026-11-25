package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
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
	for _, old := range []string{"login", "logout", "auth login --pkce", "auth login --token", "auth login --no-open", "auth login --login-token"} {
		var flags cli
		parser := commandForTest(&flags, io.Discard)
		if _, err := parser(strings.Split(old, " ")); err == nil {
			t.Fatalf("obsolete %s accepted", old)
		}
	}
}

func TestAuthLoginWorksWithoutTerminalInput(t *testing.T) {
	config := authLoginConfig(loginCommand{Open: true}, "https://control.example", nil, strings.NewReader(""), io.Discard)
	if config.OpenURL != nil || config.AuthenticationPrompt == nil {
		t.Fatalf("browser selection = %#v", config)
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
		if err := writeWaitingLogin(&diag, op, statusOutputHuman, test.opening); err != nil || diag.String() != test.want {
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
	if err := runAuthLoginStart(t.Context(), flags, nil, &out, &diag); err != nil {
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
	err := runLogin(ctx, flags, nil, &out, loginPromptWriter(func(p []byte) (int, error) {
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
	err = runLogin(t.Context(), flags, nil, &out, &diag)
	var event struct {
		SchemaVersion int `json:"schema_version"`
		clientstate.AuthOperation
	}
	if reason, _ := failure.ReasonOf(err); reason != failure.AuthWaitTimeout || out.Len() != 0 || json.Unmarshal(diag.Bytes(), &event) != nil ||
		event.SchemaVersion != 1 || event.ID != id || event.UserCode != code || strings.Contains(diag.String(), secret) {
		t.Fatalf("machine login = %q; diagnostics = %q; %v", &out, &diag, err)
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
	err = runAuthLoginStart(t.Context(), loginCommand{StateDir: root, ServerURL: server.URL, Output: statusOutputJSON}, nil, &saved, io.Discard)
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

func TestAuthStatusLocalJSONDoesNotExposeSavedCredentials(t *testing.T) {
	clientstate.UseMemoryKeychainForTesting()
	root := filepath.Join(t.TempDir(), "state")
	db, err := clientstate.Open(t.Context(), root)
	if err != nil {
		t.Fatal(err)
	}
	store, err := db.Server(t.Context(), "https://offline.example")
	if err != nil {
		t.Fatal(err)
	}
	access, _, _, err := credentials.NewAccessToken()
	if err != nil {
		t.Fatal(err)
	}
	refresh, _, _, err := credentials.NewRefreshToken()
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
	var stdout, stderr bytes.Buffer
	if err := run(t.Context(), []string{"--no-config", "auth", "status", "--server=https://offline.example", "--state-dir=" + root, "--output=json"}, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	if stderr.Len() != 0 || strings.Contains(stdout.String(), access.String()) || strings.Contains(stdout.String(), refresh.String()) {
		t.Fatal("status emitted credential or diagnostic")
	}
	var status auth.StatusResult
	if err := json.Unmarshal(stdout.Bytes(), &status); err != nil {
		t.Fatal(err)
	}
	if status.Source != "saved_session" || status.Status != "available" || status.Checked || status.AccessExpiresAt == nil {
		t.Fatalf("status = %#v", status)
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

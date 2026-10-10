package main

import (
	"bytes"
	"encoding/json"
	"io"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/alecthomas/kong"
	"github.com/tnldotdev/tnl/internal/clientauth"
	"github.com/tnldotdev/tnl/internal/clientstate"
	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/zalando/go-keyring"
)

func TestAuthCommandParsing(t *testing.T) {
	for _, test := range []struct {
		args    []string
		command string
	}{
		{[]string{"auth", "status", "--output=json"}, "auth status"},
		{[]string{"auth", "status", "--check"}, "auth status"},
		{[]string{"auth", "login", "--open"}, "auth login"},
		{[]string{"auth", "login", "--login-token", "--output=json"}, "auth login"},
		{[]string{"auth", "login", "start", "--output=json"}, "auth login start"},
		{[]string{"auth", "login", "wait", "auth_01234567890123456789012345678901", "--timeout=2s"}, "auth login wait <operation-id>"},
		{[]string{"auth", "login", "inspect", "auth_01234567890123456789012345678901"}, "auth login inspect <operation-id>"},
		{[]string{"auth", "login", "cancel", "auth_01234567890123456789012345678901"}, "auth login cancel <operation-id>"},
		{[]string{"auth", "logout", "--output=json"}, "auth logout"},
	} {
		t.Run(strings.Join(test.args, " "), func(t *testing.T) {
			var flags cli
			parser, err := kong.New(&flags)
			if err != nil {
				t.Fatal(err)
			}
			parsed, err := parser.Parse(test.args)
			if err != nil {
				t.Fatal(err)
			}
			if got := canonicalParsedCommand(parsed.Command()); got != test.command {
				t.Fatalf("command = %q", got)
			}
		})
	}
	for _, old := range []string{"login", "logout", "auth login --pkce", "auth login --token", "auth login --no-open"} {
		var flags cli
		parser, err := kong.New(&flags)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := parser.Parse(strings.Split(old, " ")); err == nil {
			t.Fatalf("obsolete %s accepted", old)
		}
	}
}

func TestAuthLoginTokenFromEnvironment(t *testing.T) {
	token, err := credentials.NewLoginToken()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("TNL_LOGIN_TOKEN", token.String())
	config, err := authLoginConfig(loginCommand{}, "https://control.example", nil, strings.NewReader(""), io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if !config.ForceLoginToken || config.OpenURL != nil || config.LoginToken == nil {
		t.Fatalf("login token or browser selection = %#v", config)
	}
	actual, err := config.LoginToken()
	if err != nil || actual != token {
		t.Fatalf("login token did not match the supplied value: %v", err)
	}
}

func TestAuthStatusLocalJSONDoesNotExposeSavedCredentials(t *testing.T) {
	keyring.MockInit()
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
	var status clientauth.StatusResult
	if err := json.Unmarshal(stdout.Bytes(), &status); err != nil {
		t.Fatal(err)
	}
	if status.Source != "saved_session" || status.Status != "available" || status.Checked || status.AccessExpiresAt == nil {
		t.Fatalf("status = %#v", status)
	}
}

func TestAuthLogoutFencesPendingOperationsOffline(t *testing.T) {
	keyring.MockInit()
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
	if err := store.CreateAuthOperation(t.Context(), clientstate.AuthOperation{ID: id, Phase: clientstate.AuthPending, Method: "device_code", Private: []byte("private challenge"), ExpiresAt: time.Now().Add(time.Minute)}); err != nil {
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

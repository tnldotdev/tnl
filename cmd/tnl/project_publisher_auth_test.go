package main

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/clientruntime"
	"github.com/tnldotdev/tnl/internal/clientstate"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/internal/privateprotocol"
	"github.com/tnldotdev/tnl/internal/projectconfig"
	"github.com/tnldotdev/tnl/pkg/api/authorityv1"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
	"github.com/zalando/go-keyring"
)

func TestProjectPublisherLoginKeepsAnIndependentContainerSession(t *testing.T) {
	keyring.MockInit()
	token, err := credentials.NewLoginToken()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("TNL_LOGIN_TOKEN", token.String())
	access, _, _, err := credentials.NewAccessToken()
	if err != nil {
		t.Fatal(err)
	}
	refresh, _, _, err := credentials.NewRefreshToken()
	if err != nil {
		t.Fatal(err)
	}
	var redeemed bool
	control := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/discovery":
			privateprotocol.Write(w, http.StatusOK, controlv1.ControlDiscovery{
				Authentication: controlv1.AuthenticationFacts{Methods: []controlv1.AuthenticationFactsMethods{controlv1.LoginToken}},
			})
		case "/v1/auth/token":
			redeemed = true
			privateprotocol.Write(w, http.StatusOK, authorityv1.ControlSessionResponse{
				SessionId: "cs_0123456789abcdefghijkl", AccessToken: access.String(), RefreshToken: refresh.String(),
				AccessExpiresAt: time.Now().Add(time.Hour), RefreshExpiresAt: time.Now().Add(24 * time.Hour),
			})
		case "/v1/auth/logout":
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer control.Close()
	projectRoot, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	stateRoot := t.TempDir()
	if err := os.Chmod(stateRoot, 0700); err != nil {
		t.Fatal(err)
	}
	state, err := clientstate.Open(t.Context(), stateRoot)
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	owner, err := publisherCredential()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(projectRoot, "owner-token"), []byte(owner), 0600); err != nil {
		t.Fatal(err)
	}
	selected := "owner-token"
	project := projectConfiguration{Project: projectconfig.Project{Root: projectRoot,
		Config: config.TNL{Server: &control.URL}, RelativeServiceDirectories: map[string]string{}}}
	runtime := &appRuntime{project: project, state: state, authHTTP: control.Client()}
	runtime.manager, err = clientruntime.New(t.Context(), projectRoot, stateRoot, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.manager.Close()
	key, err := runtimeKey(projectRoot, stateRoot)
	if err != nil {
		t.Fatal(err)
	}
	server, _, err := startRuntimeTCPWithOptions(key, runtime.handler(), "127.0.0.1:0", owner, "")
	if err != nil {
		t.Fatal(err)
	}
	defer stopRuntimeTCP(context.Background(), server, key)
	endpoint, err := readRuntimeTCPEndpoint(key)
	if err != nil {
		t.Fatal(err)
	}
	project.Config.Publisher = &config.ProjectPublisher{Type: "url", URL: &endpoint.URL, OwnerCredentialFile: &selected}
	var stdout, stderr bytes.Buffer
	if err := runPublisherLogin(t.Context(), project, loginCommand{ServerURL: control.URL, Timeout: time.Minute}, strings.NewReader(""), &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	if !redeemed || strings.Contains(stdout.String()+stderr.String(), token.String()) || strings.Contains(stdout.String(), refresh.String()) {
		t.Fatalf("publisher login failed or exposed a token: redeemed=%t", redeemed)
	}
	store, err := state.Server(t.Context(), control.URL)
	if err != nil {
		t.Fatal(err)
	}
	if session, found, err := store.ControlSession(t.Context()); err != nil || !found || session.RefreshToken != refresh.String() {
		t.Fatalf("publisher did not retain its own control session: found=%t, error=%v", found, err)
	}
	hostStateRoot := t.TempDir()
	if err := os.Chmod(hostStateRoot, 0700); err != nil {
		t.Fatal(err)
	}
	hostState, err := clientstate.Open(t.Context(), hostStateRoot)
	if err != nil {
		t.Fatal(err)
	}
	defer hostState.Close()
	hostStore, err := hostState.Server(t.Context(), control.URL)
	if err != nil {
		t.Fatal(err)
	}
	if _, found, err := hostStore.ControlSession(t.Context()); err != nil || found {
		t.Fatalf("publisher login copied its control session into host state: found=%t, error=%v", found, err)
	}
	var status bytes.Buffer
	if err := runPublisherAuthStatus(t.Context(), project, authStatusCommand{}, &status); err != nil || !strings.Contains(status.String(), "available") {
		t.Fatalf("host publisher session status = %q, %v", status.String(), err)
	}
	if err := runPublisherLogout(t.Context(), project, logoutCommand{}, io.Discard); err != nil {
		t.Fatal(err)
	}
	if session, found, err := store.ControlSession(t.Context()); err != nil || found {
		t.Fatalf("publisher session survived logout: found=%t, error=%v, id=%q", found, err, session.SessionID)
	}
}

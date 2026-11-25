package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/tnldotdev/tnl/internal/security/credentials"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestTeamSelectionConfirmations(t *testing.T) {
	access, _, _, err := credentials.NewAccessToken()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("TNL_ACCESS_TOKEN", access.String())
	memberships := []authorityv1.Membership{
		{TeamId: statusTestTeamOne, TeamDisplayName: "studio", Role: "owner"},
		{TeamId: statusTestTeamTwo, TeamDisplayName: "payments", Role: "member"},
	}
	const newID = "tm_1111111111111111111111"
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.Method + " " + r.URL.Path {
		case "GET /v1/discovery":
			_ = json.NewEncoder(w).Encode(controlv1.ControlDiscovery{ManagedDomain: "example.test", ManagedUrlMode: "generated", Authentication: controlv1.AuthenticationFacts{Methods: []controlv1.AuthenticationFactsMethods{"oidc"}, Oidc: &controlv1.OIDCAuthenticationFacts{Issuer: "https://issuer.example.test", LoginFlow: "device_code"}}})
		case "GET /v1/identity":
			_ = json.NewEncoder(w).Encode(authorityv1.IdentityContext{PersonalTeamId: statusTestTeamOne, Memberships: memberships})
		case "POST /v1/teams":
			_ = json.NewEncoder(w).Encode(authorityv1.Team{Id: newID, DisplayName: "ops"})
		case "POST /v1/invitations/accept":
			_ = json.NewEncoder(w).Encode(authorityv1.Membership{TeamId: newID, TeamDisplayName: "ops", Role: "member"})
		default:
			t.Errorf("unexpected team request: %s %s", r.Method, r.URL)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	original := http.DefaultTransport
	http.DefaultTransport = server.Client().Transport
	defer func() { http.DefaultTransport = original }()
	for _, test := range []struct{ command, arg, project, want string }{
		{"use", "studio", "", "Selected studio.\n"},
		{"use", statusTestTeamOne, "studio", "Selected studio.\n"},
		{"use", "studio", statusTestTeamTwo, "Saved studio as your default team. This project still uses payments.\n"},
		{"create", "ops", "", "Created team ops.\n"},
		{"create", "ops", "payments", "Created team ops.\nSaved ops as your default team. This project still uses payments.\n"},
		{"join", "invitation", "", "Joined ops as member.\n"},
		{"join", "invitation", "payments", "Joined ops as member.\nSaved ops as your default team. This project still uses payments.\n"},
	} {
		t.Run(test.command+"/"+test.project, func(t *testing.T) {
			args := []string{"--no-config"}
			if test.project != "" {
				path := filepath.Join(t.TempDir(), "tnl.yml")
				if err := os.WriteFile(path, []byte("version: 1\ntnl:\n  team: "+test.project+"\n"), 0o600); err != nil {
					t.Fatal(err)
				}
				args = []string{"--config", path}
			}
			var out bytes.Buffer
			args = append(args, "team", test.command, test.arg, "--server", server.URL, "--state-dir", filepath.Join(t.TempDir(), "state"))
			if err := run(t.Context(), args, &out, io.Discard); err != nil || out.String() != test.want {
				t.Fatalf("team %s: %q, %v; want %q", test.command, &out, err, test.want)
			}
		})
	}
}

package main

import (
	"path/filepath"
	"testing"

	"github.com/tnldotdev/tnl/internal/client/auth"
	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	clientteam "github.com/tnldotdev/tnl/internal/client/team"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
)

func TestFollowupScopePinsHostedOnlyWhenNeeded(t *testing.T) {
	t.Setenv("TNL_SERVER", "")
	t.Setenv("TNL_ACCESS_TOKEN", "")
	const other = "https://control.example.test"
	for _, tc := range []struct {
		name, saved, project, env, wantServer string
	}{
		{name: "redundant explicit hosted"},
		{name: "hosted from project", project: defaultServerURL},
		{name: "project would select another server", project: other, wantServer: defaultServerURL},
		{name: "saved state would select another server", saved: other, wantServer: defaultServerURL},
		{name: "environment selects hosted over the saved server", env: defaultServerURL, saved: other},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("TNL_SERVER", tc.env)
			root := filepath.Join(t.TempDir(), "client state")
			db, err := clientstate.OpenWithOptions(t.Context(), root, clientstate.OpenOptions{Protection: clientstate.ProtectionFile})
			if err != nil {
				t.Fatal(err)
			}
			session := clientteam.NewSession(db, nil, &auth.Client{ServerEndpoint: defaultServerURL}, authorityv1.IdentityContext{}, clientteam.Options{})
			defer session.Close()
			if tc.saved != "" {
				if err := db.SaveServer(t.Context(), tc.saved); err != nil {
					t.Fatal(err)
				}
			}
			flags := scopedTeamFlags{remoteFlags: remoteFlags{ServerURL: defaultServerURL, StateDir: root, configArgs: "--config=tnl.json "}, teamSelectionFlags: teamSelectionFlags{Team: "studio"}}
			if tc.project != "" {
				flags.projectServer = &tc.project
			}
			got := flags.followupScope(t.Context(), session, "tm_studio").command("domain status", "studio.example")
			want := "tnl --config=tnl.json domain status studio.example"
			if tc.wantServer != "" {
				want += " --server=" + tc.wantServer
			}
			want += " --team=studio --state-dir=" + shellWord(root)
			if got != want {
				t.Errorf("follow-up:\n%s\nwant:\n%s", got, want)
			}
		})
	}
}

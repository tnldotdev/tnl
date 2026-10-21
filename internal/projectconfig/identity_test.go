package projectconfig

import "testing"

func TestRemoteIdentityIgnoresTransportAndCredentials(t *testing.T) {
	for _, remote := range []string{"git@github.com:tnldotdev/tnl.git", "ssh://git@github.com/tnldotdev/tnl.git", "https://user:secret@GitHub.com/tnldotdev/tnl/"} {
		got, err := NormalizeGitRemote(remote)
		if err != nil || got != "github.com/tnldotdev/tnl" {
			t.Fatalf("remote = %q: %v", got, err)
		}
	}
	for _, remote := range []string{"/Users/user/repo", "../repo", "file:///tmp/repo", "https://github.com/org/repo?token=secret", "https://github.com/org/../repo"} {
		if _, err := NormalizeGitRemote(remote); err == nil {
			t.Fatalf("accepted nonportable remote %q", remote)
		}
	}
}

package naming

import (
	"strings"
	"testing"
)

func TestRemoteIdentityIgnoresTransportAndCredentials(t *testing.T) {
	for _, remote := range []string{"git@github.com:tnldotdev/tnl.git", "ssh://git@github.com/tnldotdev/tnl.git", "https://user:secret@GitHub.com/tnldotdev/tnl/"} {
		got, err := NormalizeGitRemote(remote)
		if err != nil || got != "github.com/tnldotdev/tnl" {
			t.Fatalf("remote = %q: %v", got, err)
		}
		public, err := SanitizeGitRemote(remote)
		if err != nil || strings.Contains(public, "@") {
			t.Fatal("source facts retained Git credentials", err)
		}
		if normalized, err := NormalizeGitRemote(public); err != nil || normalized != got {
			t.Fatal("removing Git credentials changed source identity", err)
		}
	}
	for _, remote := range []string{"/Users/user/repo", "../repo", "file:///tmp/repo", "https://github.com/org/repo?token=secret", "https://github.com/org/../repo"} {
		if _, err := NormalizeGitRemote(remote); err == nil {
			t.Fatalf("accepted nonportable remote %q", remote)
		}
	}
}

func TestGitProjectSourceIdentity(t *testing.T) {
	for _, origin := range []string{"https://example.test/example.git", "git@example.test:example.git"} {
		identity, err := (GitProjectSource{GitOrigin: origin, ConfigurationPath: "tnl.yml"}).Identity()
		if err != nil || identity.Fingerprint != "a4c232311b1a5083342e81207d920e296029c9181e4a45f9f3492a13216aa45c" || identity.Key != "project-a4c232311b1a5083342e81207d920e296029c9181e4a45f9" || identity.Label != "example" {
			t.Fatal("existing source identity changed", identity, err)
		}
	}
	for _, path := range []string{"", ".", "/Users/person/tnl.yml", "../tnl.yml", "apps/../tnl.yml", `apps\tnl.yml`} {
		if _, err := (GitProjectSource{GitOrigin: "https://example.test/example.git", ConfigurationPath: path}).Identity(); err == nil {
			t.Fatal("accepted a non-repository-relative configuration path", path)
		}
	}
}

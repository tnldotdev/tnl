package managedssh

import (
	"os/user"
	"testing"
)

func TestRootAliasRejectedByUID(t *testing.T) {
	for _, uid := range []string{"0", "4294967296", "4294967295", "-1"} {
		_, err := lookupAccountUsing("administrator-alias", func(name string) (*user.User, error) {
			return &user.User{Username: name, Uid: uid, Gid: "0", HomeDir: "/root"}, nil
		})
		if err == nil {
			t.Fatalf("accepted a root, overflowing, or sentinel uid: %s", uid)
		}
	}
}

func TestServerProductionRootAndUserChecks(t *testing.T) {
	config := protocolConfig(t)
	if _, err := newServer(config, 501, func([]string) error { return nil }); err != ErrConfiguration {
		t.Fatalf("non-root server = %v", err)
	}
	config.Users = []string{"root"}
	if _, err := New(config); err != ErrConfiguration {
		t.Fatalf("root OS user = %v", err)
	}
}

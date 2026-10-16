package managedssh

import (
	"os/user"
	"testing"
)

func TestValidateUsers(t *testing.T) {
	for _, names := range [][]string{nil, {"root"}, {"0"}, {"12345"}, {""}, {"bad/name"}, {"no-such-tnl-test-account-94028"}} {
		if ValidateUsers(names) == nil {
			t.Errorf("accepted invalid user list %q", names)
		}
	}
	u, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	if u.Uid == "0" {
		t.Skip("current account is root")
	}
	if err := ValidateUsers([]string{u.Username}); err != nil {
		t.Fatal(err)
	}
	if ValidateUsers([]string{u.Username, u.Username}) == nil {
		t.Fatal("accepted duplicate")
	}
}

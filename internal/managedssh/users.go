package managedssh

import (
	"errors"
	"os/user"
	"strconv"
	"strings"
)

type account struct {
	name, home, shell string
	uid, gid          int
	groups            []int
}

// ValidateUsers checks the explicitly allowed, existing non-root accounts.
func ValidateUsers(users []string) error {
	if len(users) == 0 {
		return errors.New("at least one ssh user is required")
	}
	seen := make(map[string]bool, len(users))
	for _, name := range users {
		if seen[name] {
			return errors.New("duplicate ssh user")
		}
		seen[name] = true
		if _, err := lookupAccount(name); err != nil {
			return err
		}
	}
	return nil
}

func lookupAccount(name string) (account, error) {
	return lookupAccountUsing(name, user.Lookup)
}

func lookupAccountUsing(name string, lookup func(string) (*user.User, error)) (account, error) {
	var a account
	if name == "" || len(name) > 256 || strings.ContainsAny(name, "\x00\r\n/: \t") {
		return a, errors.New("invalid ssh user name")
	}
	if strings.IndexFunc(name, func(r rune) bool { return r < '0' || r > '9' }) == -1 {
		return a, errors.New("ssh users must be named accounts")
	}
	u, err := lookup(name)
	if err != nil || u.Username != name {
		return a, errors.New("ssh user does not exist")
	}
	a.uid, err = strconv.Atoi(u.Uid)
	if err != nil || a.uid <= 0 || uint64(a.uid) >= 1<<32-1 {
		return a, errors.New("ssh user must not be root")
	}
	a.gid, err = strconv.Atoi(u.Gid)
	if err != nil || a.gid < 0 || uint64(a.gid) >= 1<<32-1 {
		return a, errors.New("invalid ssh user group")
	}
	ids, err := u.GroupIds()
	if err != nil {
		return a, errors.New("cannot resolve ssh user groups")
	}
	for _, id := range ids {
		gid, err := strconv.Atoi(id)
		if err != nil || gid < 0 || uint64(gid) >= 1<<32-1 {
			return a, errors.New("invalid ssh user group")
		}
		a.groups = append(a.groups, gid)
	}
	if !strings.HasPrefix(u.HomeDir, "/") || strings.ContainsRune(u.HomeDir, 0) {
		return a, errors.New("invalid ssh user home")
	}
	a.name, a.home, a.shell = name, u.HomeDir, accountShell(name)
	return a, nil
}

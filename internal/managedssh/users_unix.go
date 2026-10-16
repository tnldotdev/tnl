//go:build linux || darwin

package managedssh

import (
	"os"
	"strings"
	"syscall"
)

func accountShell(name string) string {
	data, err := os.ReadFile("/etc/passwd")
	if err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			fields := strings.Split(line, ":")
			if len(fields) == 7 && fields[0] == name && strings.HasPrefix(fields[6], "/") && !strings.ContainsRune(fields[6], 0) {
				return fields[6]
			}
		}
	}
	return platformShell(name)
}

func dropAccount(a account, sameUID bool) error {
	if sameUID && os.Getuid() == a.uid && os.Geteuid() == a.uid {
		return nil
	}
	if os.Getuid() != 0 || os.Geteuid() != 0 {
		return errRootRequired
	}
	// syscall's setters update all go runtime threads, not just the caller.
	if err := syscall.Setgroups(a.groups); err != nil {
		return err
	}
	if err := syscall.Setgid(a.gid); err != nil {
		return err
	}
	if err := syscall.Setuid(a.uid); err != nil {
		return err
	}
	if os.Getuid() != a.uid || os.Geteuid() != a.uid || os.Getgid() != a.gid || os.Getegid() != a.gid {
		return errPrivilegeDrop
	}
	return nil
}

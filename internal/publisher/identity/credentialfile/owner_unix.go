//go:build darwin || linux || freebsd || netbsd || openbsd

package credentialfile

import (
	"os"
	"syscall"
)

func safeFile(info os.FileInfo) bool {
	if !info.Mode().IsRegular() || info.Mode().Perm()&0027 != 0 {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return false
	}
	mode := info.Mode().Perm()
	if mode&0040 == 0 {
		return mode&0600 != 0 && (int(stat.Uid) == os.Geteuid() || int(stat.Uid) == 0)
	}
	// root-owned, read-only secret mounts may grant one configured group access.
	if stat.Uid != 0 || mode&0600 == 0 {
		return false
	}
	if int(stat.Gid) == os.Getegid() {
		return true
	}
	groups, err := os.Getgroups()
	if err != nil {
		return false
	}
	for _, group := range groups {
		if group == int(stat.Gid) {
			return true
		}
	}
	return false
}

//go:build !darwin && !linux && !freebsd && !netbsd && !openbsd

package credentialfile

import "os"

func safeFile(info os.FileInfo) bool {
	return false
}

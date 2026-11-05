//go:build unix

package runtimetrace

import (
	"errors"
	"os"
	"syscall"
)

// inherited exec pipes are blocking. set nonblocking before NewFile so Go's
// poller can interrupt a blocked read/write when cancellation closes the file.
// adoption happens inside the already-execed child; close-on-exec prevents its
// descendants from retaining the private pipes without affecting ExtraFiles.
func OpenPipeFD(fd int, name string) (*os.File, error) {
	if fd < 3 {
		return nil, errors.New("native trace pipe unavailable")
	}
	syscall.CloseOnExec(fd)
	if syscall.SetNonblock(fd, true) != nil {
		return nil, errors.New("native trace pipe unavailable")
	}
	f := os.NewFile(uintptr(fd), name)
	if f == nil {
		return nil, errors.New("native trace pipe unavailable")
	}
	info, err := f.Stat()
	if err != nil || info.Mode()&os.ModeNamedPipe == 0 {
		_ = f.Close()
		return nil, errors.New("native trace descriptor is not a pipe")
	}
	return f, nil
}

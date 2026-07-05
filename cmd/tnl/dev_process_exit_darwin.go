//go:build darwin

package main

import (
	"errors"
	"fmt"
	"syscall"

	"golang.org/x/sys/unix"
)

func watchDevProcessExit(pid int) (<-chan error, error) {
	queue, err := unix.Kqueue()
	if err != nil {
		return nil, err
	}
	unix.CloseOnExec(queue)
	change := unix.Kevent_t{
		Ident:  uint64(pid),
		Filter: unix.EVFILT_PROC,
		Flags:  unix.EV_ADD | unix.EV_ENABLE | unix.EV_ONESHOT,
		Fflags: unix.NOTE_EXIT,
	}
	if _, err := unix.Kevent(queue, []unix.Kevent_t{change}, nil, nil); err != nil {
		closeErr := unix.Close(queue)
		if errors.Is(err, unix.ESRCH) && closeErr == nil {
			exited := make(chan error, 1)
			exited <- nil
			return exited, nil
		}
		return nil, errors.Join(err, closeErr)
	}
	exited := make(chan error, 1)
	go func() {
		defer unix.Close(queue)
		events := make([]unix.Kevent_t, 1)
		for {
			n, err := unix.Kevent(queue, nil, events, nil)
			if errors.Is(err, unix.EINTR) {
				continue
			}
			if err == nil && n != 1 {
				err = fmt.Errorf("kqueue returned %d process events", n)
			} else if err == nil && events[0].Flags&unix.EV_ERROR != 0 {
				err = syscall.Errno(events[0].Data)
			}
			exited <- err
			return
		}
	}()
	return exited, nil
}

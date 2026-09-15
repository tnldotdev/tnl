//go:build linux

package main

import (
	"errors"

	"golang.org/x/sys/unix"
)

func watchDevProcessExit(pid int) (<-chan error, error) {
	exited := make(chan error, 1)
	go func() {
		for {
			err := unix.Waitid(unix.P_PID, pid, nil, unix.WEXITED|unix.WNOWAIT, nil)
			if errors.Is(err, unix.EINTR) {
				continue
			}
			exited <- err
			return
		}
	}()
	return exited, nil
}

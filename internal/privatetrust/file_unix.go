//go:build unix

package privatetrust

import (
	"os"

	"golang.org/x/sys/unix"
)

func openProjectFile(root *os.Root, name string) (*os.File, error) {
	// confinement comes from os.Root. nonblocking open also bounds a race where
	// a regular file is replaced with a FIFO after its initial stat.
	return root.OpenFile(name, os.O_RDONLY|unix.O_NONBLOCK, 0)
}

//go:build !unix

package privatetrust

import "os"

func openProjectFile(root *os.Root, name string) (*os.File, error) {
	return root.Open(name)
}

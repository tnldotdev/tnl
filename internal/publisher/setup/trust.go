package setup

import (
	"io"
	"os"

	"github.com/tnldotdev/tnl/internal/publisher/target"
)

// ReadTrust bounds a selected installation trust file before changing state.
func ReadTrust(path string) ([]byte, error) {
	if path == "" {
		return nil, nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	value, err := io.ReadAll(io.LimitReader(f, (128<<10)+1))
	if err != nil {
		return nil, err
	}
	if len(value) > 128<<10 {
		return nil, target.ErrScope
	}
	return value, nil
}

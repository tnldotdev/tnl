package state

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/0xcadams/tnl/internal/credentials"
)

const bootstrapTokenName = "bootstrap-token"

// EnsureBootstrapToken loads or creates the state directory's bootstrap token.
func EnsureBootstrapToken(
	dir string,
	legacy credentials.BootstrapToken,
) (credentials.BootstrapToken, bool, error) {
	dir, err := prepareDirectory(dir)
	if err != nil {
		return "", false, err
	}
	if token, err := readBootstrapToken(dir); err == nil {
		if legacy != "" && token != legacy {
			return "", false, errors.New("state: configured bootstrap token differs from persisted token")
		}
		return token, false, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", false, err
	}

	token := legacy
	generated := false
	if token == "" {
		token, err = credentials.NewBootstrapToken()
		if err != nil {
			return "", false, err
		}
		generated = true
	} else if _, err := credentials.ParseBootstrapToken(token); err != nil {
		return "", false, errors.New("state: legacy bootstrap token is invalid")
	}
	if err := writeBootstrapToken(dir, token, false); err != nil {
		if errors.Is(err, os.ErrExist) {
			stored, readErr := readBootstrapToken(dir)
			return stored, false, readErr
		}
		return "", false, err
	}
	return token, generated, nil
}

// ReadBootstrapToken reads the persisted bootstrap token.
func ReadBootstrapToken(dir string) (credentials.BootstrapToken, error) {
	dir, err := filepath.Abs(dir)
	if err != nil {
		return "", fmt.Errorf("state: resolve directory: %w", err)
	}
	return readBootstrapToken(dir)
}

// RotateBootstrapToken replaces the persisted token while holding the state lock.
func RotateBootstrapToken(dir string) (credentials.BootstrapToken, error) {
	lock, err := LockDirectory(dir)
	if err != nil {
		return "", err
	}
	defer lock.Close()
	token, err := credentials.NewBootstrapToken()
	if err != nil {
		return "", err
	}
	if err := writeBootstrapToken(dir, token, true); err != nil {
		return "", err
	}
	return token, nil
}

func readBootstrapToken(dir string) (credentials.BootstrapToken, error) {
	path := filepath.Join(dir, bootstrapTokenName)
	info, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		return "", errors.New("state: bootstrap token must be a regular file with mode 0600")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("state: read bootstrap token: %w", err)
	}
	if len(data) > 256 {
		return "", errors.New("state: bootstrap token file is too large")
	}
	token := credentials.BootstrapToken(strings.TrimSpace(string(data)))
	if _, err := credentials.ParseBootstrapToken(token); err != nil {
		return "", errors.New("state: persisted bootstrap token is invalid")
	}
	return token, nil
}

func writeBootstrapToken(dir string, token credentials.BootstrapToken, replace bool) error {
	if _, err := credentials.ParseBootstrapToken(token); err != nil {
		return errors.New("state: invalid bootstrap token")
	}
	path := filepath.Join(dir, bootstrapTokenName)
	if !replace {
		file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return err
		}
		if err := writeAndSync(file, token); err != nil {
			file.Close()
			_ = os.Remove(path)
			return err
		}
		if err := file.Close(); err != nil {
			return fmt.Errorf("state: close bootstrap token: %w", err)
		}
		return syncDirectory(dir)
	}

	file, err := os.CreateTemp(dir, ".bootstrap-token-*")
	if err != nil {
		return fmt.Errorf("state: create bootstrap token: %w", err)
	}
	temporary := file.Name()
	defer os.Remove(temporary)
	if err := file.Chmod(0o600); err != nil {
		file.Close()
		return fmt.Errorf("state: secure bootstrap token: %w", err)
	}
	if err := writeAndSync(file, token); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("state: close bootstrap token: %w", err)
	}
	if err := os.Rename(temporary, path); err != nil {
		return fmt.Errorf("state: replace bootstrap token: %w", err)
	}
	return syncDirectory(dir)
}

func writeAndSync(file *os.File, token credentials.BootstrapToken) error {
	if _, err := file.WriteString(token.String() + "\n"); err != nil {
		return fmt.Errorf("state: write bootstrap token: %w", err)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("state: sync bootstrap token: %w", err)
	}
	return nil
}

func syncDirectory(dir string) error {
	file, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("state: open directory for sync: %w", err)
	}
	defer file.Close()
	if err := file.Sync(); err != nil {
		return fmt.Errorf("state: sync directory: %w", err)
	}
	return nil
}

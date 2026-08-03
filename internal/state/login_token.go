package state

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/0xcadams/tnl/internal/credentials"
)

const loginTokenName = "login-token"

// EnsureLoginToken loads or creates the state directory's login token.
func EnsureLoginToken(dir string) (credentials.LoginToken, bool, error) {
	dir, err := prepareDirectory(dir)
	if err != nil {
		return "", false, err
	}
	if token, err := readLoginToken(dir); err == nil {
		return token, false, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", false, err
	}

	token, err := credentials.NewLoginToken()
	if err != nil {
		return "", false, err
	}
	if err := writeLoginToken(dir, token, false); err != nil {
		if errors.Is(err, os.ErrExist) {
			stored, readErr := readLoginToken(dir)
			return stored, false, readErr
		}
		return "", false, err
	}
	return token, true, nil
}

// ReadLoginToken reads the persisted login token.
func ReadLoginToken(dir string) (credentials.LoginToken, error) {
	dir, err := filepath.Abs(dir)
	if err != nil {
		return "", fmt.Errorf("state: resolve directory: %w", err)
	}
	return readLoginToken(dir)
}

// RotateLoginToken replaces the persisted token while holding the state lock.
func RotateLoginToken(dir string) (credentials.LoginToken, error) {
	lock, err := LockDirectory(dir)
	if err != nil {
		return "", err
	}
	defer lock.Close()
	token, err := credentials.NewLoginToken()
	if err != nil {
		return "", err
	}
	if err := writeLoginToken(dir, token, true); err != nil {
		return "", err
	}
	return token, nil
}

func readLoginToken(dir string) (credentials.LoginToken, error) {
	path := filepath.Join(dir, loginTokenName)
	info, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		return "", errors.New("state: login token must be a regular file with mode 0600")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("state: read login token: %w", err)
	}
	if len(data) > 256 {
		return "", errors.New("state: login token file is too large")
	}
	token := credentials.LoginToken(strings.TrimSpace(string(data)))
	if _, err := credentials.ParseLoginToken(token); err != nil {
		return "", errors.New("state: persisted login token is invalid")
	}
	return token, nil
}

func writeLoginToken(dir string, token credentials.LoginToken, replace bool) error {
	if _, err := credentials.ParseLoginToken(token); err != nil {
		return errors.New("state: invalid login token")
	}
	path := filepath.Join(dir, loginTokenName)
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
			return fmt.Errorf("state: close login token: %w", err)
		}
		return syncDirectory(dir)
	}

	file, err := os.CreateTemp(dir, ".login-token-*")
	if err != nil {
		return fmt.Errorf("state: create login token: %w", err)
	}
	temporary := file.Name()
	defer os.Remove(temporary)
	if err := file.Chmod(0o600); err != nil {
		file.Close()
		return fmt.Errorf("state: secure login token: %w", err)
	}
	if err := writeAndSync(file, token); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("state: close login token: %w", err)
	}
	if err := os.Rename(temporary, path); err != nil {
		return fmt.Errorf("state: replace login token: %w", err)
	}
	return syncDirectory(dir)
}

func writeAndSync(file *os.File, token credentials.LoginToken) error {
	if _, err := file.WriteString(token.String() + "\n"); err != nil {
		return fmt.Errorf("state: write login token: %w", err)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("state: sync login token: %w", err)
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

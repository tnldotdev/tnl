package clientstate

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// the key lives next to the database; the file is required to open that state.
type fileSecretProtector struct {
	account, keyPath string
}

func newFileSecretProtector(account, root string) secretProtector {
	return &fileSecretProtector{
		account: account, keyPath: filepath.Join(root, "wrapping-key-v1"),
	}
}

func (p *fileSecretProtector) Seal(ctx context.Context, secretContext string, plaintext []byte) ([]byte, error) {
	key, err := p.wrappingKey(ctx)
	if err != nil {
		return nil, err
	}
	return sealPrivateState(key, secretAdditionalData(p.account, secretContext), plaintext)
}

func (p *fileSecretProtector) Open(ctx context.Context, secretContext string, sealed []byte) ([]byte, error) {
	key, err := p.wrappingKey(ctx)
	if err != nil {
		return nil, err
	}
	return openPrivateState(key, secretAdditionalData(p.account, secretContext), sealed)
}

func (p *fileSecretProtector) wrappingKey(ctx context.Context) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	key, err := p.readKey()
	if errors.Is(err, os.ErrNotExist) {
		return nil, errors.New("clientstate: wrapping key file is missing; restore it with the client state directory")
	}
	return key, err
}

// the migration lock in Open covers both the key and database initialization.
// an existing database never gets a replacement key, including on a new write.
func prepareFileSecretProtection(ctx context.Context, root string, databaseExists bool) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	p := &fileSecretProtector{keyPath: filepath.Join(root, "wrapping-key-v1")}
	if _, err := p.readKey(); err == nil {
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if databaseExists {
		return errors.New("clientstate: wrapping key file is missing for the existing database; restore both from the same backup")
	}
	key := make([]byte, wrappingKeySize)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return fmt.Errorf("clientstate: generate wrapping key: %w", err)
	}
	file, err := os.OpenFile(p.keyPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("clientstate: create wrapping key file: %w", err)
	}
	_, writeErr := file.Write(key)
	if writeErr == nil {
		writeErr = file.Sync()
	}
	closeErr := file.Close()
	if writeErr != nil || closeErr != nil {
		return fmt.Errorf("clientstate: save wrapping key file: %w", errors.Join(writeErr, closeErr))
	}
	_, err = p.readKey()
	return err
}

func (p *fileSecretProtector) readKey() ([]byte, error) {
	pathInfo, err := os.Lstat(p.keyPath)
	if err != nil {
		return nil, err
	}
	if err := validatePrivateFile(pathInfo, false); err != nil {
		return nil, fmt.Errorf("clientstate: invalid wrapping key file: %w", err)
	}
	file, err := os.Open(p.keyPath)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("clientstate: inspect wrapping key file: %w", err)
	}
	if err := validatePrivateFile(info, false); err != nil {
		return nil, fmt.Errorf("clientstate: invalid wrapping key file: %w", err)
	}
	if info.Size() != wrappingKeySize || !os.SameFile(pathInfo, info) {
		return nil, errors.New("clientstate: invalid wrapping key file: key length or file identity changed")
	}
	key := make([]byte, wrappingKeySize)
	if _, err := io.ReadFull(file, key); err != nil {
		return nil, fmt.Errorf("clientstate: read wrapping key file: %w", err)
	}
	return key, nil
}

package clientstate

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

const wrappingKeySize = 32

var sealedValuePrefix = []byte("tnl-sealed-v1\x00")

type secretProtector interface {
	Seal(context.Context, string, []byte) ([]byte, error)
	Open(context.Context, string, []byte) ([]byte, error)
}

// encryptedProtector is shared by every platform and secret-bearing table.
// the key is loaded once during locked database initialization, never on Seal.
type encryptedProtector struct {
	key     []byte
	account string
}

func (p *encryptedProtector) Seal(ctx context.Context, secretContext string, plaintext []byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	aead, err := newAEAD(p.key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("clientstate: generate private state nonce: %w", err)
	}
	header := append(bytes.Clone(sealedValuePrefix), nonce...)
	return aead.Seal(header, nonce, plaintext, p.additionalData(secretContext)), nil
}

func (p *encryptedProtector) Open(ctx context.Context, secretContext string, sealed []byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	aead, err := newAEAD(p.key)
	if err != nil {
		return nil, err
	}
	headerSize := len(sealedValuePrefix) + aead.NonceSize()
	if len(sealed) < headerSize+aead.Overhead() || !bytes.HasPrefix(sealed, sealedValuePrefix) {
		return nil, errors.New("clientstate: invalid encrypted private state")
	}
	value, err := aead.Open(nil, sealed[len(sealedValuePrefix):headerSize], sealed[headerSize:], p.additionalData(secretContext))
	if err != nil {
		return nil, errors.New("clientstate: decrypt private state")
	}
	return value, nil
}

func (p *encryptedProtector) additionalData(secretContext string) []byte {
	value, _ := json.Marshal([]string{"tnl client state v1", p.account, secretContext})
	return value
}

func newAEAD(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("clientstate: initialize private state encryption: %w", err)
	}
	return cipher.NewGCM(block)
}

type scopedProtector struct {
	protector secretProtector
	scope     string
}

func (p scopedProtector) secretContext(value string) string {
	encoded, _ := json.Marshal([]string{p.scope, value})
	return string(encoded)
}
func (p scopedProtector) Seal(ctx context.Context, name string, value []byte) ([]byte, error) {
	return p.protector.Seal(ctx, p.secretContext(name), value)
}
func (p scopedProtector) Open(ctx context.Context, name string, value []byte) ([]byte, error) {
	return p.protector.Open(ctx, p.secretContext(name), value)
}

// WrappingKeyPath is separate from the database and its backups. file protection
// is the default outside macOS and can be explicitly selected for system state.
func WrappingKeyPath(root string) string { return filepath.Join(root, "v1.wrapping-key") }

func fileWrappingKey(root string, create bool) ([]byte, error) {
	path := WrappingKeyPath(root)
	file, err := OpenPrivateFile(path)
	if errors.Is(err, os.ErrNotExist) && create {
		key := make([]byte, wrappingKeySize)
		if _, err := io.ReadFull(rand.Reader, key); err != nil {
			return nil, err
		}
		if err := publishWrappingKey(root, key, nil); err != nil {
			return nil, fmt.Errorf("clientstate: publish wrapping key: %w", err)
		}
		return key, nil
	}
	if err != nil {
		return nil, fmt.Errorf("clientstate: read wrapping key: %w", err)
	}
	defer file.Close()
	key, err := io.ReadAll(io.LimitReader(file, wrappingKeySize+1))
	if err != nil {
		return nil, err
	}
	if len(key) != wrappingKeySize {
		return nil, errors.New("clientstate: invalid wrapping key")
	}
	return key, nil
}

type wrappingKeyPublicationStage string

const (
	wrappingKeyCreated   wrappingKeyPublicationStage = "created"
	wrappingKeyWritten   wrappingKeyPublicationStage = "written"
	wrappingKeySynced    wrappingKeyPublicationStage = "synced"
	wrappingKeyPublished wrappingKeyPublicationStage = "published"
	wrappingKeyDurable   wrappingKeyPublicationStage = "durable"
)

// publishWrappingKey makes only a complete, synced key visible at its canonical
// name. the caller holds the database initialization lock until the directory
// sync finishes, before it may publish a database using this key. checkpoint is
// an optional per-call observer for deterministic failure and process-exit tests.
func publishWrappingKey(root string, key []byte, checkpoint func(wrappingKeyPublicationStage, *os.File) error) error {
	if len(key) != wrappingKeySize {
		return errors.New("clientstate: invalid wrapping key")
	}
	file, err := os.CreateTemp(root, ".v1-wrapping-key-*")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	defer file.Close()
	observe := func(stage wrappingKeyPublicationStage) error {
		if checkpoint != nil {
			return checkpoint(stage, file)
		}
		return nil
	}
	if err := observe(wrappingKeyCreated); err != nil {
		return err
	}
	n, err := file.Write(key)
	if err != nil {
		return err
	}
	if n != len(key) {
		return io.ErrShortWrite
	}
	if err := observe(wrappingKeyWritten); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := observe(wrappingKeySynced); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	// link is atomic and fails if the canonical name already exists. never
	// replace or remove that name, even if a later cleanup or sync fails.
	if err := os.Link(file.Name(), WrappingKeyPath(root)); err != nil {
		return err
	}
	if err := observe(wrappingKeyPublished); err != nil {
		return err
	}
	if err := os.Remove(file.Name()); err != nil {
		return err
	}
	directory, err := os.Open(root)
	if err != nil {
		return err
	}
	err = directory.Sync()
	err = errors.Join(err, directory.Close())
	if err != nil {
		return err
	}
	return observe(wrappingKeyDurable)
}

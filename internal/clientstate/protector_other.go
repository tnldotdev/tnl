//go:build !darwin

package clientstate

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
)

const fileWrappingKeySize = 32

var fileSealedPrefix = []byte("tnl-sealed-v1\x00")

type fileSecretProtector struct {
	root    string
	account string
}

func newSecretProtector(account, _, root string) secretProtector {
	return fileSecretProtector{root: root, account: account}
}

func (p fileSecretProtector) Seal(ctx context.Context, name string, value []byte) ([]byte, error) {
	key, err := readFileWrappingKey(ctx, p.root)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	header := append(bytes.Clone(fileSealedPrefix), nonce...)
	return aead.Seal(header, nonce, value, []byte(p.account+"\x00"+name)), nil
}

func (p fileSecretProtector) Open(ctx context.Context, name string, sealed []byte) ([]byte, error) {
	key, err := readFileWrappingKey(ctx, p.root)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	headerSize := len(fileSealedPrefix) + aead.NonceSize()
	if len(sealed) < headerSize+aead.Overhead() || !bytes.HasPrefix(sealed, fileSealedPrefix) {
		return nil, errors.New("clientstate: invalid encrypted private state")
	}
	value, err := aead.Open(nil, sealed[len(fileSealedPrefix):headerSize], sealed[headerSize:], []byte(p.account+"\x00"+name))
	if err != nil {
		return nil, errors.New("clientstate: decrypt private state")
	}
	return value, nil
}

func readFileWrappingKey(ctx context.Context, root string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	info, err := os.Lstat(WrappingKeyPath(root))
	if err != nil {
		return nil, fmt.Errorf("clientstate: read wrapping key: %w", err)
	}
	if err := validatePrivateFile(info, false); err != nil {
		return nil, fmt.Errorf("clientstate: wrapping key: %w", err)
	}
	file, err := os.Open(WrappingKeyPath(root))
	if err != nil {
		return nil, err
	}
	defer file.Close()
	key, err := io.ReadAll(io.LimitReader(file, fileWrappingKeySize+1))
	if err != nil || len(key) != fileWrappingKeySize {
		return nil, errors.New("clientstate: invalid wrapping key")
	}
	return key, nil
}

// the caller holds the database migration lock through key publication.
func preparePlatformProtection(ctx context.Context, root string, existingDatabase bool) error {
	if _, err := readFileWrappingKey(ctx, root); err == nil {
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if existingDatabase {
		return errors.New("clientstate: v1 database is missing its wrapping key")
	}
	key := make([]byte, fileWrappingKeySize)
	if _, err := rand.Read(key); err != nil {
		return err
	}
	temp, err := os.CreateTemp(root, ".v1-wrapping-key-*")
	if err != nil {
		return err
	}
	defer os.Remove(temp.Name())
	if n, err := temp.Write(key); err != nil || n != len(key) {
		temp.Close()
		return errors.New("clientstate: write wrapping key")
	}
	if err := temp.Sync(); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	if err := os.Link(temp.Name(), WrappingKeyPath(root)); err != nil {
		return err
	}
	directory, err := os.Open(root)
	if err != nil {
		return err
	}
	err = directory.Sync()
	return errors.Join(err, directory.Close())
}

func verifyPlatformProtection(ctx context.Context, root string, db *sql.DB, existingDatabase bool) error {
	var mode string
	var stored []byte
	err := db.QueryRowContext(ctx, `SELECT protection_mode, key_check_ciphertext FROM state_protection WHERE id = 1`).Scan(&mode, &stored)
	if errors.Is(err, sql.ErrNoRows) && !existingDatabase {
		digest := sha256.Sum256([]byte(root))
		protector := fileSecretProtector{root: root, account: hex.EncodeToString(digest[:])}
		sealed, err := protector.Seal(ctx, "wrapping-key-check", []byte("tnl client state v1"))
		if err != nil {
			return err
		}
		_, err = db.ExecContext(ctx, `INSERT INTO state_protection (id, protection_mode, key_check_ciphertext) VALUES (1, 'file', ?)`, sealed)
		return err
	}
	if err != nil || mode != "file" {
		return errors.New("clientstate: invalid v1 state protection")
	}
	digest := sha256.Sum256([]byte(root))
	protector := fileSecretProtector{root: root, account: hex.EncodeToString(digest[:])}
	value, err := protector.Open(ctx, "wrapping-key-check", stored)
	if err != nil || string(value) != "tnl client state v1" {
		return errors.New("clientstate: wrapping key does not match database")
	}
	return nil
}

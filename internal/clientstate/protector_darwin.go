package clientstate

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/zalando/go-keyring"
	"golang.org/x/sys/unix"
)

const (
	keychainService = "dev.tnl.client-state"
	wrappingKeySize = 32
)

var sealedValuePrefix = []byte("tnl-sealed-v1\x00")

type keyringClient interface {
	Get(string, string) (string, error)
	Set(string, string, string) error
}

type systemKeyring struct{}

func (systemKeyring) Get(service, account string) (string, error) {
	return keyring.Get(service, account)
}

func (systemKeyring) Set(service, account, value string) error {
	return keyring.Set(service, account, value)
}

type keychainSecretProtector struct {
	account  string
	lockPath string
	keyring  keyringClient

	mu  sync.Mutex
	key []byte
}

func newSecretProtector(account, lockPath string) secretProtector {
	return &keychainSecretProtector{account: account, lockPath: lockPath, keyring: systemKeyring{}}
}

func openBlockingLock(path, kind string) (*Lock, error) {
	return openLockOperation(path, kind, unix.LOCK_EX)
}

func (p *keychainSecretProtector) Seal(context string, plaintext []byte) ([]byte, error) {
	key, err := p.wrappingKey(true)
	if err != nil {
		return nil, err
	}
	aead, err := newAEAD(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("clientstate: generate private state nonce: %w", err)
	}
	sealed := make([]byte, len(sealedValuePrefix)+len(nonce))
	copy(sealed, sealedValuePrefix)
	copy(sealed[len(sealedValuePrefix):], nonce)
	return aead.Seal(sealed, nonce, plaintext, p.additionalData(context)), nil
}

func (p *keychainSecretProtector) Open(context string, sealed []byte) ([]byte, error) {
	key, err := p.wrappingKey(false)
	if err != nil {
		return nil, err
	}
	aead, err := newAEAD(key)
	if err != nil {
		return nil, err
	}
	headerSize := len(sealedValuePrefix) + aead.NonceSize()
	if len(sealed) < headerSize+aead.Overhead() || !bytes.Equal(sealed[:len(sealedValuePrefix)], sealedValuePrefix) {
		return nil, errors.New("clientstate: invalid encrypted private state")
	}
	nonce := sealed[len(sealedValuePrefix):headerSize]
	plaintext, err := aead.Open(nil, nonce, sealed[headerSize:], p.additionalData(context))
	if err != nil {
		return nil, errors.New("clientstate: decrypt private state")
	}
	return plaintext, nil
}

func newAEAD(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("clientstate: initialize private state encryption: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("clientstate: initialize private state authentication: %w", err)
	}
	return aead, nil
}

func (p *keychainSecretProtector) wrappingKey(create bool) ([]byte, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.key) != 0 {
		return p.key, nil
	}
	value, err := p.keyring.Get(keychainService, p.account)
	if err == nil {
		p.key, err = parseWrappingKey(value)
		return p.key, err
	}
	if !errors.Is(err, keyring.ErrNotFound) {
		return nil, fmt.Errorf("clientstate: read Keychain wrapping key: %w", err)
	}
	if !create {
		return nil, errors.New("clientstate: Keychain wrapping key is missing")
	}
	lock, err := openBlockingLock(p.lockPath, "Keychain initialization")
	if err != nil {
		return nil, err
	}
	defer lock.Close()

	value, err = p.keyring.Get(keychainService, p.account)
	if err == nil {
		p.key, err = parseWrappingKey(value)
		return p.key, err
	}
	if !errors.Is(err, keyring.ErrNotFound) {
		return nil, fmt.Errorf("clientstate: reread Keychain wrapping key: %w", err)
	}
	generated := make([]byte, wrappingKeySize)
	if _, err := io.ReadFull(rand.Reader, generated); err != nil {
		return nil, fmt.Errorf("clientstate: generate Keychain wrapping key: %w", err)
	}
	if err := p.keyring.Set(keychainService, p.account, base64.RawStdEncoding.EncodeToString(generated)); err != nil {
		return nil, fmt.Errorf("clientstate: save Keychain wrapping key: %w", err)
	}
	value, err = p.keyring.Get(keychainService, p.account)
	if err != nil {
		return nil, fmt.Errorf("clientstate: verify Keychain wrapping key: %w", err)
	}
	p.key, err = parseWrappingKey(value)
	return p.key, err
}

func parseWrappingKey(value string) ([]byte, error) {
	key, err := base64.RawStdEncoding.DecodeString(value)
	if err != nil || len(key) != wrappingKeySize {
		return nil, errors.New("clientstate: invalid Keychain wrapping key")
	}
	return key, nil
}

func (p *keychainSecretProtector) additionalData(context string) []byte {
	return []byte("tnl client state v1\x00" + p.account + "\x00" + context)
}

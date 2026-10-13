package clientstate

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/zalando/go-keyring"
)

const keychainService = "dev.tnl.client-state"

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

func newSecretProtector(account, lockPath, _ string) secretProtector {
	return &keychainSecretProtector{account: account, lockPath: lockPath, keyring: systemKeyring{}}
}

func prepareSecretProtection(context.Context, string, bool) error { return nil }

func (p *keychainSecretProtector) Seal(ctx context.Context, secretContext string, plaintext []byte) ([]byte, error) {
	key, err := p.wrappingKey(ctx, true)
	if err != nil {
		return nil, err
	}
	return sealPrivateState(key, secretAdditionalData(p.account, secretContext), plaintext)
}

func (p *keychainSecretProtector) Open(ctx context.Context, secretContext string, sealed []byte) ([]byte, error) {
	key, err := p.wrappingKey(ctx, false)
	if err != nil {
		return nil, err
	}
	return openPrivateState(key, secretAdditionalData(p.account, secretContext), sealed)
}

func (p *keychainSecretProtector) wrappingKey(ctx context.Context, create bool) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if key := p.cachedWrappingKey(); len(key) != 0 {
		return key, nil
	}
	value, err := p.keyring.Get(keychainService, p.account)
	if err == nil {
		return p.rememberWrappingKey(value)
	}
	if !errors.Is(err, keyring.ErrNotFound) {
		return nil, fmt.Errorf("clientstate: read Keychain wrapping key: %w", err)
	}
	if !create {
		return nil, errors.New("clientstate: Keychain wrapping key is missing")
	}
	lock, err := openLockContext(ctx, p.lockPath, "Keychain initialization")
	if err != nil {
		return nil, err
	}
	defer lock.Close()
	if key := p.cachedWrappingKey(); len(key) != 0 {
		return key, nil
	}

	value, err = p.keyring.Get(keychainService, p.account)
	if err == nil {
		return p.rememberWrappingKey(value)
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
	return p.rememberWrappingKey(value)
}

func (p *keychainSecretProtector) cachedWrappingKey() []byte {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.key
}

func (p *keychainSecretProtector) rememberWrappingKey(value string) ([]byte, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.key) != 0 {
		return p.key, nil
	}
	key, err := parseWrappingKey(value)
	if err != nil {
		return nil, err
	}
	p.key = key
	return p.key, nil
}

func parseWrappingKey(value string) ([]byte, error) {
	key, err := base64.RawStdEncoding.DecodeString(value)
	if err != nil || len(key) != wrappingKeySize {
		return nil, errors.New("clientstate: invalid Keychain wrapping key")
	}
	return key, nil
}

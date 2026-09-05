// Package storagekey encrypts recoverable secrets stored by control.
package storagekey

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
)

const (
	keySize         = 32
	envelopeVersion = 1
)

var errInvalidCiphertext = errors.New("storagekey: invalid ciphertext")

// Keyring holds the current storage key and an optional previous key used only
// while ciphertext is being re-encrypted.
type Keyring struct {
	currentID  string
	current    cipher.AEAD
	previousID string
	previous   cipher.AEAD
}

func New(current, previous string) (*Keyring, error) {
	currentKey, err := parse(current)
	if err != nil {
		return nil, fmt.Errorf("storagekey: current key: %w", err)
	}
	currentAEAD, err := newAEAD(currentKey)
	if err != nil {
		return nil, err
	}
	keyring := &Keyring{currentID: keyID(currentKey), current: currentAEAD}
	if previous == "" {
		return keyring, nil
	}
	previousKey, err := parse(previous)
	if err != nil {
		return nil, fmt.Errorf("storagekey: previous key: %w", err)
	}
	if subtle.ConstantTimeCompare(currentKey, previousKey) == 1 {
		return nil, errors.New("storagekey: previous key must differ from current key")
	}
	keyring.previous, err = newAEAD(previousKey)
	if err != nil {
		return nil, err
	}
	keyring.previousID = keyID(previousKey)
	return keyring, nil
}

func (k *Keyring) CurrentID() string {
	if k == nil {
		return ""
	}
	return k.currentID
}

func (k *Keyring) PreviousID() string {
	if k == nil {
		return ""
	}
	return k.previousID
}

func (k *Keyring) Seal(context string, plaintext []byte) ([]byte, error) {
	if k == nil || k.current == nil || context == "" || len(plaintext) == 0 {
		return nil, errors.New("storagekey: invalid encryption input")
	}
	nonce := make([]byte, k.current.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("storagekey: generate nonce: %w", err)
	}
	envelope := make([]byte, 1, 1+len(nonce)+len(plaintext)+k.current.Overhead())
	envelope[0] = envelopeVersion
	envelope = append(envelope, nonce...)
	return k.current.Seal(envelope, nonce, plaintext, associatedData(context)), nil
}

// Open decrypts ciphertext and reports whether it used the previous key.
func (k *Keyring) Open(keyID, context string, ciphertext []byte) ([]byte, bool, error) {
	if k == nil || k.current == nil || context == "" || len(ciphertext) < 1+k.current.NonceSize()+k.current.Overhead() || ciphertext[0] != envelopeVersion {
		return nil, false, errInvalidCiphertext
	}
	nonceEnd := 1 + k.current.NonceSize()
	nonce, sealed := ciphertext[1:nonceEnd], ciphertext[nonceEnd:]
	if keyID == k.currentID {
		plaintext, err := k.current.Open(nil, nonce, sealed, associatedData(context))
		if err == nil {
			return plaintext, false, nil
		}
	}
	if keyID == k.previousID && k.previous != nil {
		plaintext, err := k.previous.Open(nil, nonce, sealed, associatedData(context))
		if err == nil {
			return plaintext, true, nil
		}
	}
	return nil, false, errInvalidCiphertext
}

func keyID(key []byte) string {
	digest := sha256.Sum256(key)
	return base64.RawURLEncoding.EncodeToString(digest[:])
}

func parse(encoded string) ([]byte, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || len(decoded) != keySize || base64.RawURLEncoding.EncodeToString(decoded) != encoded {
		return nil, errors.New("key must be canonical unpadded base64url encoding of 32 bytes")
	}
	return decoded, nil
}

func newAEAD(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("storagekey: initialize AES-256: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("storagekey: initialize GCM: %w", err)
	}
	return aead, nil
}

func associatedData(context string) []byte {
	return []byte("tnl-storage-v1\x00" + context)
}

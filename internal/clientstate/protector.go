package clientstate

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
)

const wrappingKeySize = 32

var sealedValuePrefix = []byte("tnl-sealed-v1\x00")

type secretProtector interface {
	Seal(context.Context, string, []byte) ([]byte, error)
	Open(context.Context, string, []byte) ([]byte, error)
}

func secretAdditionalData(account, secretContext string) []byte {
	return []byte("tnl client state v1\x00" + account + "\x00" + secretContext)
}

func sealPrivateState(key, additionalData, plaintext []byte) ([]byte, error) {
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
	return aead.Seal(sealed, nonce, plaintext, additionalData), nil
}

func openPrivateState(key, additionalData, sealed []byte) ([]byte, error) {
	aead, err := newAEAD(key)
	if err != nil {
		return nil, err
	}
	headerSize := len(sealedValuePrefix) + aead.NonceSize()
	if len(sealed) < headerSize+aead.Overhead() || !bytes.Equal(sealed[:len(sealedValuePrefix)], sealedValuePrefix) {
		return nil, errors.New("clientstate: invalid encrypted private state")
	}
	nonce := sealed[len(sealedValuePrefix):headerSize]
	plaintext, err := aead.Open(nil, nonce, sealed[headerSize:], additionalData)
	if err != nil {
		return nil, errors.New("clientstate: decrypt private state; check the wrapping key and state directory")
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

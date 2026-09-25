//go:build !darwin

package clientstate

import (
	"bytes"
	"context"
)

type plaintextSecretProtector struct{}

func (plaintextSecretProtector) Seal(_ context.Context, _ string, value []byte) ([]byte, error) {
	return bytes.Clone(value), nil
}

func (plaintextSecretProtector) Open(_ context.Context, _ string, value []byte) ([]byte, error) {
	return bytes.Clone(value), nil
}

func newSecretProtector(_, _ string) secretProtector {
	return plaintextSecretProtector{}
}

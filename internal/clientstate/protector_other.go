//go:build !darwin

package clientstate

import "bytes"

type plaintextSecretProtector struct{}

func (plaintextSecretProtector) Seal(_ string, value []byte) ([]byte, error) {
	return bytes.Clone(value), nil
}

func (plaintextSecretProtector) Open(_ string, value []byte) ([]byte, error) {
	return bytes.Clone(value), nil
}

func newSecretProtector(_, _ string) secretProtector {
	return plaintextSecretProtector{}
}

package main

import (
	"crypto/x509"
	"errors"
	"os"
)

func loadCertPool(path string) (*x509.CertPool, error) {
	if path == "" {
		return nil, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(data) {
		return nil, errors.New("control CA file contains no certificates")
	}
	return pool, nil
}

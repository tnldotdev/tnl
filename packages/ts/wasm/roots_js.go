//go:build js && wasm

package main

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"syscall/js"

	// wasm has no OS root store. only this binary registers the maintained
	// WebPKI fallback; shared connector libraries retain native trust policy.
	_ "golang.org/x/crypto/x509roots/fallback"
)

func serviceTrust(host js.Value) (*tls.Config, error) {
	pool, err := fixtureServiceRoots(host)
	if err != nil {
		return nil, err
	}
	if pool == nil {
		pool, err = x509.SystemCertPool()
		if err != nil || pool == nil || len(pool.Subjects()) == 0 {
			return nil, errors.New("WASM WebPKI roots unavailable")
		}
	}
	return &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool}, nil
}

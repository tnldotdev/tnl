//go:build js && wasm && !tnlwasmtest

package main

import (
	"crypto/x509"
	"syscall/js"
)

func reportFixtureFailure(error) {}

func fixtureServiceRoots(host js.Value) (*x509.CertPool, error) {
	if value := bridgeGet(host, "__tnlTestServiceRootPEM"); !value.IsUndefined() && !value.IsNull() {
		return nil, errArguments
	}
	return nil, nil
}

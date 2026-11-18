//go:build js && wasm && !tnlpublisher

package main

// the connector validates the service certificate inside the tunnel. wasm has
// no OS root store, so use the maintained WebPKI fallback. the publisher serves
// its own certificate and relies on the host for relay and control TLS.
import _ "golang.org/x/crypto/x509roots/fallback"

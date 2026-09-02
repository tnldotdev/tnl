// Package router reads a size-limited TLS ClientHello to select a route by SNI
// or ACME ALPN, then makes every consumed byte available to the selected
// upstream.
package router

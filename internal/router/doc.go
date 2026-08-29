// Package router contains bounded inspection for opaque TCP routing. It reads
// enough of a TLS ClientHello to select a route by SNI or ACME ALPN, then makes
// every consumed byte available for replay to the selected upstream.
package router

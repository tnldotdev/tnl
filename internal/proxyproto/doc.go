// Package proxyproto implements tnl's strict PROXY protocol v2 boundary. it
// accepts one TCP-over-IPv4 or TCP-over-IPv6 header and rejects other versions,
// commands, transports, extensions, and duplicate headers.
package proxyproto

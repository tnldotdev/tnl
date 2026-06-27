# `@tnldotdev/dev`

This package lets the official tnl integrations communicate with `tnl dev`. It
is installed automatically and is not intended to be added directly to an
application.

The integration supplies its framework name through the private local
development handshake. Tunnel policy, hostname, server, and command settings
are resolved by the Go client from CLI flags, environment variables, and the
project configuration file. Framework processes never receive server access
tokens.

The handshake has four stages: the CLI bootstraps the framework with a private
local socket, the integration requests a tunnel assignment, the framework calls
`registerLocalPort` with its actual loopback listening port, and the CLI marks
the route version ready and runtime routable. This lets frameworks keep their
native occupied-port behavior without exposing a route to the wrong local
process.

`publicTunnelEnvironment` exposes only the public URL, hostname, and tunnel ID;
private bootstrap credentials are never included.

Install `@tnldotdev/next` or `@tnldotdev/vite` instead.

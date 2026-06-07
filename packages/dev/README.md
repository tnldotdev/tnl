# `@tnldotdev/dev`

This package lets the official tnl integrations communicate with `tnl dev`. It
is installed automatically and is not intended to be added directly to an
application.

The integration supplies `TnlTunnelOptions` through the authenticated local
development handshake. Its fields are `controlURL`, `host`, `allowIP`, and
`allowCurrentIP`. CLI `--server`/`TNL_SERVER` and `--host`/`TNL_HOST` take
precedence over `controlURL` and `host`. The Go client retains credentials and
performs server authentication, hostname authorization, and public-IP
resolution.

The handshake has four stages: the CLI bootstraps the framework with a private
local socket, the integration requests a tunnel assignment, the framework calls
`registerLocalPort` with its actual loopback listening port, and the CLI marks
the route version ready and runtime routable. This lets frameworks keep their
native occupied-port behavior without exposing a route to the wrong local
process.

Options factories receive `TnlTunnelOptionsContext`, including a read-only copy
of the environment, the current working directory, and `TnlWorktree`. The
worktree value includes the absolute root, original directory name, DNS-safe
label, and whether Git provided the root. Public declarations include
property-level documentation for all options and context values.

`publicTunnelEnvironment` exposes only the public URL, hostname, and tunnel ID;
private bootstrap credentials are never included.

Install `@tnldotdev/next` or `@tnldotdev/vite` instead.

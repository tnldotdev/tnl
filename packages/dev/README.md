# `@tnldotdev/dev`

This package lets the official tnl integrations communicate with `tnl dev`. It
is installed automatically and is not intended to be added directly to an
application.

The integration supplies runtime `server`, `name`, `allowIP`, and
`allowCurrentIP` options through the authenticated local development handshake.
The Go client retains credentials and performs all remote authorization and IP
resolution.

The handshake has four stages: the CLI bootstraps the framework with a private
local socket, the integration requests a tunnel assignment, the framework
registers its actual listening target, and the CLI marks the public route ready.
This lets frameworks keep their native occupied-port behavior without exposing
a route to the wrong local process.

Options factories receive `TnlOptionsContext`, including a frozen environment,
the current working directory, and `TnlWorktree`. The worktree value includes
the absolute root, original directory name, DNS-safe label, and whether Git
provided the root. Public declarations include property-level documentation for
all options and context values.

`publicTunnelEnvironment` exposes only the public URL, hostname, and tunnel ID;
private bootstrap credentials are never included.

Install `@tnldotdev/next` or `@tnldotdev/vite` instead.

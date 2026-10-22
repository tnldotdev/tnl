# split server template

`compose.yaml`, `.env.example`, and `Caddyfile` form one split deployment unit.
copy the example environment to `.env` beside the Compose file. keep its private
control certificates under the selected directory's `certs/`, or supply explicit
paths in the environment file.

Control receives the pooled database URL, storage key, DNS, ACME, and authority
settings. the migration process receives only the direct database URL. ingress
and relay processes use the private control endpoint and cluster authentication.
the template preserves separate public bind addresses and the private control
network.

See [self-hosting](https://tnl.dev/docs/self-hosting) for configuration and
deployment procedures. the contributor stack lives in `development/local`.

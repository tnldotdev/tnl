# standalone server template

`compose.yaml`, `.env.example`, and `Caddyfile` form one standalone deployment
unit. copy the example environment to `.env` beside the Compose file and keep
certificate and environment paths relative to that directory.

The migration process receives the direct database URL; the serving process uses
the pooled URL. standalone combines control, ingress, and two logical relay
services. the control proxy has its own bind address.

See [self-hosting](https://tnl.dev/docs/self-hosting) for configuration and
deployment procedures. the contributor stack lives in `development/local`.

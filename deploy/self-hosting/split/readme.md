# split server

This Compose file runs control, two ingress processes, and two relay services
against your PostgreSQL database on one host. Separate containers do not provide
independent host failure boundaries. Bring an existing HTTPS edge for control.

Copy `compose.yaml` and `.env.example` into a private deployment directory, fill
in `.env`, and follow [self-hosting](https://tnl.dev/docs/self-hosting) for DNS,
certificates, sign-in, migrations, and startup checks.

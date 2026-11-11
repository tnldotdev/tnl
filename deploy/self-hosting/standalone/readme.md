# standalone server

This Compose file runs `tnld` in standalone mode against your PostgreSQL database.
Bring an existing HTTPS edge for control; visitor and relay traffic stays raw.

Copy `compose.yaml` and `.env.example` into a private deployment directory, fill
in `.env`, and follow [self-hosting](https://tnl.dev/docs/self-hosting) for DNS,
certificates, sign-in, migrations, and startup checks.

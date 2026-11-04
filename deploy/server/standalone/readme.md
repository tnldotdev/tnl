# run a standalone server

Run control, ingress, and two logical relay services in one `tnld` process.
You'll need Docker Compose, the `tnl` CLI, a digest-pinned `TNL_IMAGE`, and:

- A fresh PostgreSQL database: `TNLD_DATABASE_DIRECT_URL` for migration and
  `TNLD_DATABASE_URL` for the pooled serving connection.
- Delegated public Route 53 zones for `TNLD_SERVER_DOMAIN` and `TNLD_MANAGED_DOMAIN`.
  Fill their zone IDs in `.env`. Give `tnld` AWS credentials to manage both zones;
  you can add `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, and, for temporary
  credentials, `AWS_SESSION_TOKEN` to `.env`.
- Two distinct host addresses: `TNL_CONTROL_BIND` for Caddy and `TNL_PUBLIC_BIND`
  for `tnld`. With server domain `example.com`, point `control.example.com` at
  Caddy; point `ingress-a.example.com` and `relay.example.com` at the public address.
  Set `TNLD_INGRESS_IPV4_ADDRESSES` to that public address. Allow TCP 80/443 to Caddy,
  TCP/UDP 443 to `tnld`, and TCP 20000–20015 for public service endpoints.
- An OIDC client supporting authorization code with PKCE. Set `TNLD_OIDC_ISSUER`,
  `TNLD_OIDC_CLIENT_ID`, and `TNLD_OIDC_CLIENT_SECRET` if the provider requires one
  (otherwise leave it empty). Set `TNLD_INITIAL_ADMINISTRATORS` to your exact
  subject at that issuer so you can run the admin command below.

Register both OIDC callbacks, replacing the hostname with yours:

```text
https://control.example.com/v1/auth/device/callback
https://control.example.com/v1/browser/callback
```

Keep `compose.yaml`, `Caddyfile`, and `.env.example` together in a private directory:

```sh
cp .env.example .env
chmod 600 .env
openssl rand -base64 32 | tr '+/' '-_' | tr -d '='
```

Save the generated value as `TNLD_STORAGE_KEY`. Fill the remaining `.env` fields,
including your ACME email and terms acceptance. Keep `.env` out of Git.
Start and check the stack, using your control hostname:

```sh
docker compose --env-file .env config --quiet
docker compose --env-file .env up -d
curl --fail https://control.example.com/v1/ready
tnl auth login --server https://control.example.com --open
tnl admin server status --server https://control.example.com
```

Compose migrates before starting `tnld`. Back up PostgreSQL with `TNLD_STORAGE_KEY`,
which decrypts its saved secrets. Keep Caddy's named volumes across restarts.

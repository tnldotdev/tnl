# run a split server

Run control, two ingress processes, and two relay services on one host.
You'll need Docker Compose, the `tnl` CLI, a digest-pinned `TNL_IMAGE`, and:

- A fresh PostgreSQL database: `TNLD_DATABASE_DIRECT_URL` for migration and
  `TNLD_DATABASE_URL` for the pooled serving connection.
- Delegated public Route 53 zones for `TNLD_SERVER_DOMAIN` and `TNLD_MANAGED_DOMAIN`.
  Fill their zone IDs in `.env`, including `TNL_SERVER_ZONE_ID`. Give control AWS
  credentials to manage both zones; you can add `AWS_ACCESS_KEY_ID`,
  `AWS_SECRET_ACCESS_KEY`, and, for temporary credentials, `AWS_SESSION_TOKEN` to `.env`.
- Five distinct host bind addresses: one for Caddy, two for ingress, two for relays.
  Under your server domain, point `control`, `ingress-a`, `ingress-b`, `relay-a`, and
  `relay-b` DNS names at their matching addresses. Set `TNLD_INGRESS_IPV4_ADDRESSES`
  to a health-aware public address forwarding raw TCP to the ingress processes.
  Allow TCP 80/443 to Caddy, TCP/UDP 443 to ingress and relays, and TCP 20000–20015
  to ingress. Keep internal ports 9443, 9445, and 9090 private.
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
openssl rand -base64 32 | tr '+/' '-_' | tr -d '=' # TNLD_STORAGE_KEY
openssl rand -hex 32 # TNLD_CLUSTER_SECRET
```

Save the generated values in `.env` and fill its remaining fields, including ACME
email and terms acceptance. Provide `certs/control.crt` and `certs/control.key` for
the control hostname, with their issuer in `certs/cluster-ca.pem`. Make all three
readable by container UID 65532; keep the key private. Keep `.env` and the key out of Git.
Start and check the stack, using your control hostname:

```sh
docker compose --env-file .env config --quiet
docker compose --env-file .env up -d
curl --fail https://control.example.com/v1/ready
tnl auth login --server https://control.example.com --open
tnl admin server status --server https://control.example.com
```

Compose migrates before starting control. Back up PostgreSQL with `TNLD_STORAGE_KEY`,
which decrypts its saved secrets. Retain the certificates, cluster secret, and Caddy volumes.

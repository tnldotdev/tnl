# split server

This Compose file runs control, two ingress processes, and two relay services
against your PostgreSQL database on one host. Separate containers do not provide
independent host failure boundaries. Bring an existing HTTPS edge for control.

In a private deployment directory, copy `compose.yaml`, `.env.example` to `.env`,
`control.env.example` to `control.env`, and `relay-slots.example.json` to
`relay-slots.json`. Set the public and private addresses in the inventory to
match the addresses each relay advertises. Give each relay a distinct random
credential of at least 32 bytes and put it in both its inventory entry and its
own `.env` setting. Generate two more credentials: one for ingress to call
control, and one for ingress to forward connections to relays. Keep the files
private and make the inventory readable by the control container.

Follow [self-hosting](https://tnl.dev/docs/self-hosting) for DNS, certificates,
sign-in, migrations, and startup checks.

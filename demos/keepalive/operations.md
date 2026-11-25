# Keepalive operations

Cloudflare serves `keepthisalive.com` and `start.keepthisalive.com`. The
`keepalive` team delegates only `hosts.keepthisalive.com` to tnl. The Worker
discovers browser hosts through `prod.live.hosts.keepthisalive.com`. Each
publisher gets its own address under `live.hosts.keepthisalive.com`, covered
by the wildcard certificate `*.live.hosts.keepthisalive.com`.

The Worker redirects plain HTTP on both public hostnames to HTTPS on the same
hostname, path, and query. For a Worker-only rollout, compare the new release
ID with `https://keepthisalive.com/__keepalive/release` before deploying. A
different release ID can exclude currently serving browsers.

The Worker reads the team, project, and deployment ID from `wrangler.jsonc`.
Set `DEPLOYMENT_CREDENTIAL` as a Worker secret. It can manage only the
`production` service on the `keepalive` deployment. Don't use a personal
access token or add connection or publication permissions. When the Worker
checks an invitation or an allowed seed, it exchanges the credential for a
short-lived access token. The browser receives only a one-use enrollment key.

## rotate the Worker credential

Signing credentials expire after at most 30 days (`720h`). Rotate around day 25. Expiry blocks new browser enrollments, not already-running hosts.

1. Sign in to `tnl` as a `keepalive` team manager and authenticate Wrangler.
   From the repository root, run the following with the matching `tnl`
   binary on `PATH`. It changes only the secret and doesn't print it.

   ```sh
   credential_name="keepalive-worker-$(date -u +%Y%m%d%H%M%S)"
   request_id=$(uuidgen)
   (
     set +x
     set -e
     credential=$(tnl auth credential create "$credential_name" \
       --team keepalive --server https://control.tnl.dev \
       --project-key project-4f913a3d642157c67aba9a09bb376e5529dd1bafe419aba2 \
       --deployment-id dpl_jfno225mc4djOzCX7VmduV --manage production \
       --expires-in 720h --idempotency-key "$request_id")
     case "$credential" in tnc_?*) ;; *) exit 1 ;; esac
     printf '%s\n' "$credential" |
       mise exec -- wrangler secret put DEPLOYMENT_CREDENTIAL \
         --config demos/keepalive/wrangler.jsonc
   )
   ```

   If the upload fails, rerun the subshell with the same name and request ID.
   Keep the credential out of files, chat, and logs.

2. Check the separate start endpoint:

   ```sh
   curl --fail --silent --show-error --output /dev/null --write-out '%{http_code}\n' \
     -X POST -H 'Origin: https://start.keepthisalive.com' \
     https://start.keepthisalive.com/__keepalive/config
   ```

   `200` checks the binding, not the token exchange. Use a fresh browser profile
   to verify enrollment. Volunteer on the main site if hosts are already serving;
   otherwise start a host from the separate start site.

3. After the new enrollment works, use `tnl publisher list --team keepalive
   --server https://control.tnl.dev` to identify the previous Worker credential.
   Revoke only that `pub_…` identity, not a browser publisher or the replacement:

   ```sh
   tnl publisher revoke OLD_PUBLISHER_ID \
     --team keepalive --server https://control.tnl.dev
   ```

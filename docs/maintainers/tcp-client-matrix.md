# tcp client matrix

Manual compatibility results for PR #288 at `bebaf470cd62a0888cbb3040c31b1e09b0607934`, run on 2026-10-13. This checks the PostgreSQL, MySQL, Redis, and SSH publisher paths, not the PR's Linux client-state encryption. No product code was changed, committed, or pushed.

## scope and setup

The CLI and language clients connected to disposable services through a local publisher listener. A temporary fixture supplied the publisher with trusted PROXY v2 original source and destination metadata. Most manual cases therefore cover **client → publisher → private target**, not the deployed ingress/relay path. The repository's targeted PostgreSQL integration tests under `go:test:integration:postgres-tls`, targeted publisher forwarding tests, and `TestIntegrationDatabaseClientMySQLLogin` also passed where run; this session did not run the complete `go:test:integration:tcp-clients` target as one invocation.

The disposable services were PostgreSQL 17.6, MySQL 8.4, Redis 7.4, and an SSH server with a pinned ED25519 host key. Public-test certificates were explicitly trusted by clients. Separate target-TLS tests used test-owned certificates and checked the configured private hostname; SSH clients pinned the SSH host key instead of using TLS. Language tooling and clients were installed temporarily or run in disposable containers. Redis's Python and Node checks were repeated with the project mise versions, Python 3.13.9 and Node 22.23.2. Tests used only disposable credentials. All manual listeners, fixtures, test-owned containers, and temporary client installs were removed after the TablePlus checks.

Results below distinguish an operation completing from the client closing cleanly. `pass` means the stated operation, verification, and close completed. `query pass; close timeout` is **not** a complete pass. `not run` means the case was not exercised; a direct-target failure is not counted as a publisher failure.

## postgresql

Modes: **P** is verified visitor TLS to a plaintext private target; **S** is verified visitor and target TLS with the _same_ certificate leaf; **D** is verified TLS on both sides with _different_ certificate leaves; **T** is visitor TLS passthrough to a target serving the public hostname certificate. PostgreSQL reported `ssl=false` for P and `ssl=true` for S, D, and T. The operations included `SELECT 1`, the prepared/bound operation listed, 1,000 rows, and close.

| client / runtime                         | prepared and bulk checks                          | P                             | S    | D                             | T    |
| ---------------------------------------- | ------------------------------------------------- | ----------------------------- | ---- | ----------------------------- | ---- |
| `psql` 18.6 / macOS                      | SQL `PREPARE`/`EXECUTE`; `COPY` 1,000 rows        | pass                          | pass | pass with binding disabled    | pass |
| psycopg 3.3.6 / Python 3.13.9            | parameterized query; `COPY` 1,000 rows            | pass                          | pass | pass with binding disabled    | pass |
| psycopg2 2.9.13 / Python 3.13.9          | parameterized query; `COPY` 1,000 rows            | pass                          | pass | pass with binding disabled    | pass |
| asyncpg 0.32.0 / Python 3.13.9           | prepared argument; 1,000-row cursor               | **query pass; close timeout** | pass | **query pass; close timeout** | pass |
| node-postgres `pg` 8.23.1 / Node 22.23.2 | named bound query; cursor and `COPY` 1,000 rows   | pass                          | pass | pass with channel binding off | pass |
| JDBC 42.7.8 / Java 21.0.9                | `PreparedStatement`; fetch-sized 1,000-row cursor | pass                          | pass | pass with binding disabled    | pass |
| Npgsql 8.0.8 / .NET 8.0.31               | prepared command; sequential 1,000-row reader     | pass                          | pass | pass with binding disabled    | pass |
| SQLx 0.8.6, native TLS / Rust 1.91       | bound query; 1,000-row stream                     | pass                          | pass | pass                          | pass |
| PDO_pgsql / PHP 8.4.26                   | `PDO::prepare`; 1,000-row fetch                   | pass                          | pass | pass with binding disabled    | pass |
| `pg` 1.5.9 / Ruby 2.6.10                 | `exec_params`; `COPY` 1,000 rows                  | pass                          | pass | pass with binding disabled    | pass |

Each client rejected the tested wrong public CA, wrong public hostname, and plaintext visitor startup in P. Direct-target controls passed for psql, asyncpg, Node, JDBC, Npgsql, SQLx, PHP, and Ruby. Wrong-hostname attempts usually met the publisher's SNI guard first; those do not separately prove a client-side hostname check.

Channel-binding `require` worked with S and T. With D, selecting `SCRAM-SHA-256-PLUS` produced the publisher's authored PostgreSQL error `28000`, telling the client to disable channel binding or use passthrough. P does not offer PLUS, so clients set to `require` refused it. JDBC and Npgsql chose PLUS by default in D; psql and psycopg also refused D with `channel_binding=prefer`, then passed with `disable`. Node's `enableChannelBinding: true` selected PLUS and refused D. Channel-binding `require` was not separately exercised for asyncpg or SQLx.

**Close finding:** asyncpg completed login, queries, preparation, and the cursor in P and D, but `await connection.close(timeout=4)` raised `TimeoutError`. This reproduced using real TCP with half-closes; direct PostgreSQL TLS, S, and T closed normally. SQLx built with **rustls** likewise completed P and D queries but reached a 15-second close deadline. The native-TLS SQLx build closed in all four modes. The rustls build refused S and T earlier with `CaUsedAsEndEntity` against the fixture's self-signed target leaf; classify that as a fixture/certificate compatibility result, not an established publisher handshake failure. These runs do not isolate the cause of the P/D close timeouts.

A minimal close reproduction needs the same port-addressed publisher fixture with trusted PROXY v2 metadata, a visitor CA for `route.example`, and a real PostgreSQL target:

```python
import asyncio
import ssl
import asyncpg

async def check():
    conn = await asyncpg.connect(
        host="route.example", port=PUBLIC_PORT,
        user="<test-user>", password="<test-password>", database="postgres",
        ssl=ssl.create_default_context(cafile="visitor-ca.pem"), timeout=5,
    )
    assert await conn.fetchval("SELECT 1") == 1
    await conn.close(timeout=4)  # timed out in P and D; succeeded in S and T

asyncio.run(check())
```

In D, the target TLS certificate has a different leaf, verified against its configured private hostname. A psql connection to D using the visitor CA, `sslmode=verify-full`, and `channel_binding=prefer` is the separate expected `28000` binding refusal; changing only to `channel_binding=disable` allowed the query.

## mysql

The default disposable MySQL target accepted a `tnl_client` user using `caching_sha2_password` and had **no private-target TLS**. All rows below passed directly and through verified visitor TLS to the default plaintext target: `SELECT 1`, a prepared or parameterized value of `23`, two result sets, and connection close unless qualified. The target's `Ssl_cipher` was empty on successful default-mode connections. Client identity-check settings differ and are reported rather than inferred.

| client / runtime                                     | public visitor verification                                                     | default-mode result                                                        |
| ---------------------------------------------------- | ------------------------------------------------------------------------------- | -------------------------------------------------------------------------- |
| MySQL CLI 8.4.11 / Linux                             | `VERIFY_IDENTITY` on a later focused rerun; `VERIFY_CA` on the first matrix run | pass; accepted **without SNI** on the allocated MySQL port                 |
| MariaDB CLI 11.8.9 / Linux                           | CA and hostname check                                                           | pass; accepted without SNI                                                 |
| separately linked MariaDB Connector C 3.4.10 / Linux | required TLS, server certificate and hostname verification                      | pass; native `mysql_stmt_prepare`/bind/execute/fetch/close passed          |
| PyMySQL 1.2.3 / Python 3.13.9                        | CA and hostname check                                                           | pass; parameter binding was not proved to be server-side preparation       |
| mysql-connector-python 26.7.0 / Python 3.13.9        | CA and identity check                                                           | pass; prepared cursor                                                      |
| mysql2 3.24.6 / Node 22.23.2                         | visitor TLS with certificate verification                                       | pass; `execute()` prepared statement                                       |
| Connector/J 9.5.0 / Java 21                          | `VERIFY_IDENTITY`                                                               | pass; `PreparedStatement`                                                  |
| MySqlConnector 2.5.0 / .NET 9                        | `VerifyFull`                                                                    | pass; `PrepareAsync`                                                       |
| SQLx 0.8.6 / Rust 1.91                               | `VERIFY_CA`                                                                     | pass; bound query                                                          |
| PDO_mysql / PHP 8.4                                  | certificate verification                                                        | pass; `PDO::prepare` used, native versus emulated preparation not asserted |
| Ruby mysql2 0.5.7 / Ruby 3.3                         | `verify_identity`                                                               | pass; prepared statement                                                   |

A **separate** disposable MySQL server with a certificate covering `db.internal` and `route.example` provided the optional TLS cases. The direct verified-target baseline passed. With `TargetTLS` and target name `db.internal`, PyMySQL, mysql-connector-python, PDO_mysql, and Ruby mysql2 passed; the target reported `TLS_AES_128_GCM_SHA256`. With `VisitorTLSPassthrough`, PyMySQL, PDO_mysql, and Ruby mysql2 passed and the target reported `TLS_AES_256_GCM_SHA384`. The mysql-connector-python passthrough attempt did **not** reach tnl: the temporary fixture's resolver returned `Unknown MySQL server host 'route.example'`. Other clients were **not run** in these optional modes; their default-mode passes do not imply an optional-mode pass.

Wrong public CAs failed in the tested Python, Node, JDBC, SQLx, .NET, PHP, and Ruby clients. PHP's deliberately wrong **nonempty** SNI, `wrong.example`, was rejected in the default mode and passthrough. Setting `servername: 'wrong.example'` on mysql2 did **not** send that SNI—the publisher observed an empty SNI and accepted the allocated port—so it is not evidence that mismatched named SNI is accepted.

MySQL CLI `VERIFY_IDENTITY` failed against an IP absent from the certificate with `ERROR 2026 ... certificate verify failed`; `VERIFY_CA` passed against the same IP/certificate, isolating the hostname check. A separate MariaDB Connector C program, dynamically linked to `libmariadb.so.3` rather than inferred from the CLI, failed the wrong-host test with `TLS/SSL error: Hostname verification failed (2026)`. Its client cipher on the public connection was `TLS_AES_128_GCM_SHA256` and the publisher saw SNI `route.example`.

Node mysql2 `end()` resolved on four direct and four default publisher connections. The earlier passthrough process hang was **not retested with mysql2** on PR #288, so that mode's shutdown remains unverified. Two initial .NET wrong-CA Docker commands timed out; bounded direct and publisher retries returned the same expected certificate error, so that initial command timeout was not isolated as a publisher failure. On a fresh target, early **direct** plaintext PyMySQL attempts sometimes raised `AttributeError: 'NoneType' object has no attribute 'is_auth_switch_request'`, and direct CLI authentication returned `2061` until the auth cache had been warmed. Later direct and public runs passed. These occurred without tnl in the path.

## redis

Redis visitors used verified TLS. **P** is a plaintext Redis target; **T** is a separate, verified TLS Redis target with a certificate for `redis.internal`. Successful workflows included `AUTH`, `PING`, `SET`/`GET`, pipeline, `MULTI`/`EXEC`, a Pub/Sub message received after at least 1.2 seconds subscribed, and close unless qualified. Direct-target comparisons passed for the applicable workflows. RESP2/RESP3 were selected separately where supported.

| client / runtime                    | P    | T    | protocol and close detail                                                            |
| ----------------------------------- | ---- | ---- | ------------------------------------------------------------------------------------ |
| redis-cli 7.4 / Linux               | pass | pass | RESP2 and RESP3; Pub/Sub was stopped by a five-second CLI timeout, not `UNSUBSCRIBE` |
| redis-py 7.0.1 / Python **3.13.9**  | pass | pass | RESP2 and RESP3; repeated with mise-pinned Python                                    |
| node-redis 6.3.0 / Node **22.23.2** | pass | pass | RESP2 and RESP3; repeated with mise-pinned Node                                      |
| ioredis 6.0.0 / Node **22.23.2**    | pass | pass | RESP2 and RESP3; repeated with mise-pinned Node                                      |
| Lettuce 6.8.1.RELEASE / Java 21.0.9 | pass | pass | RESP2 and RESP3                                                                      |
| StackExchange.Redis 2.9.32 / .NET 8 | pass | pass | RESP2; RESP3 not exercised                                                           |
| redis crate 0.32.7 / Rust 1.91      | pass | pass | RESP2 and RESP3                                                                      |
| phpredis 6.3.0 / PHP 8.4.26         | pass | pass | RESP2; RESP3 unsupported in this client test                                         |
| redis gem 4.8.1 / Ruby 2.6.10       | pass | pass | RESP2; RESP3 unsupported in this client test                                         |

Both modes rejected a wrong password, a wrong visitor CA, and a wrong hostname/SNI. For example, redis-py reported `AuthenticationError` or `CERTIFICATE_VERIFY_FAILED` as appropriate; redis-cli reported `WRONGPASS`, certificate verification failure, or a TLS alert. The wrong-hostname request was rejected at the publisher SNI guard, so this is not a separate test of client hostname verification. phpredis and Ruby's RESP3 failures (`got '%' as reply-type byte`) also occurred **directly** against Redis; they were not publisher regressions. redis-py's `MAINT_NOTIFICATIONS` warning appeared on both paths.

An early optional-target-TLS attempt failed after a temporary backend shim retained sockets. The fixture was corrected and the Rust, .NET, and Python target-TLS cases passed on a fresh disposable target; do not count the original shim failure as a product finding.

## ssh

SSH visitors used SSH encryption and **pinned ED25519 host-key verification**, not visitor TLS. Direct-target and publisher-forwarded checks were run with wrong-key rejection, execution, an 11-second session where listed, and clean close. File transfers were uploaded, downloaded, and byte-compared where listed.

| client / runtime                                | direct | publisher | actions and qualifications                                               |
| ----------------------------------------------- | ------ | --------- | ------------------------------------------------------------------------ |
| OpenSSH `ssh`/`scp`/`sftp` 10.3p1 / macOS       | pass   | pass      | exec, long session, SCP and SFTP transfers, wrong key rejected           |
| Paramiko 5.0.0 / Python 3.13.9                  | pass   | pass      | exec, SFTP, wrong key rejected                                           |
| ssh2 1.17.0 / Node 22.23.2                      | pass   | pass      | exec, SFTP, wrong key rejected                                           |
| SSHJ 0.40.0 / Java 21.0.9                       | pass   | pass      | exec, SFTP, wrong key rejected                                           |
| SSH.NET 2025.1.0 / .NET 8.0.426                 | pass   | pass      | exec, SFTP, wrong key rejected                                           |
| net-ssh 7.3.6 / net-sftp 4.0.0 / Ruby 2.6.10    | pass   | pass      | exec, SFTP, wrong key rejected                                           |
| russh 0.55.0 / russh-sftp 2.1.0 / Rust 1.91     | pass   | pass      | exec, SFTP, wrong key rejected                                           |
| phpseclib 3.0.57 / PHP 8.5.9 via temporary mise | pass   | pass      | exec, 11-second session, SFTP, wrong key rejected                        |
| Plink 0.85 / temporary mise-built client        | pass   | pass      | exec, 11-second session, wrong key rejected; no Plink file-transfer test |

The disposable server initially had `AllowTcpForwarding no`. OpenSSH `-L` failed with `administratively prohibited` both directly and through the publisher. After changing **only that disposable server** to allow forwarding, pinned-key OpenSSH and Plink `-L` connections returned the SSH server banner on both paths. Direct Plink connections to `localhost` timed out, while `127.0.0.1` on the same mapped target port worked. Wrong-key OpenSSH exited 255 with `Host key verification failed`; Plink exited 1 with `Host key not in manually configured list`. No host-key check was disabled to obtain a passing result.

## tableplus

The user tested these three live disposable **default-mode** publisher connections in TablePlus, using `db.127.0.0.1.nip.io` and a temporary public certificate. The app version was not recorded. This is user-reported GUI evidence and is separate from the scripted client checks.

| protocol   | tableplus setting reported | operation reported                                                     | result                                                                                                                                                                                 |
| ---------- | -------------------------- | ---------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| PostgreSQL | **Verify Full**            | `SELECT 1`; `SELECT ssl FROM pg_stat_ssl WHERE pid = pg_backend_pid()` | `1`; `false` (private target plaintext)                                                                                                                                                |
| MySQL      | **Verify Identity**        | `SELECT 1`; `SHOW SESSION STATUS LIKE 'Ssl_cipher'`                    | `1`; empty target cipher                                                                                                                                                               |
| Redis      | **Verify Peer**            | requested `PING`, `SET`, `GET`, and `DEL`                              | user reported the Redis check worked; individual outputs were not supplied. Verify Peer is recorded as reported—hostname verification was **not** independently established in the UI. |

The TablePlus listener ports were temporary and are now closed; the only user-requested artifact left outside the repository is `/Users/chase/Downloads/tnl-pr288-tableplus-ca.pem`, a public certificate expiring 2026-10-14 02:54:19 UTC. The file was moved to Downloads on request and was not deleted during fixture cleanup.

## cleanup and interpretation

Every manual protocol agent removed its temporary fixture, test-owned containers, and temporary language dependencies. The three TablePlus disposable targets and publisher listener exited, and their visitor and backend ports were verified closed. All five test-owned detached scratch worktrees were clean and removed. PR #288 remained at `bebaf470cd62a0888cbb3040c31b1e09b0607934` throughout. The tests changed no product code, made no commits or pushes, and ran no deployed benchmarks. This report was published separately after testing and cleanup.

The asyncpg and rustls close timeouts above are reproducible publisher-path findings, not confirmed root causes. The other recorded failures are distinguished as expected boundary rejections, direct-target behavior, fixture limits, or unrun cases. A future change should be checked against those distinctions rather than converting query success into a blanket connection-lifecycle pass.

# tcp client compatibility

Publisher-path checks on PR #288 (`bebaf470`, 2026-10-13), with affected cases rerun on [PR #294](https://github.com/tnldotdev/tnl/pull/294) (`159c76fa`). `ok` means a verified connection, operation, and clean close; `ok*` means the case was rerun after the #294 fix. `—` means not run. Tests used disposable services and a trusted PROXY v2 header; the manual matrix did not include ingress or relay. The PostgreSQL split-topology integration test passed separately.

## postgresql

**P:** visitor TLS → plaintext target. **S:** verified TLS on both sides with the same certificate. **D:** verified TLS with different certificates. **T:** visitor TLS passthrough. Each client ran a query, a prepared/bound operation, and 1,000 rows.

| client / runtime                    | P   | S   | D               | T   |
| ----------------------------------- | --- | --- | --------------- | --- |
| `psql` 18.6 / macOS                 | ok  | ok  | ok, binding off | ok  |
| psycopg 3.3.6 / Python 3.13.9       | ok  | ok  | ok, binding off | ok  |
| psycopg2 2.9.13 / Python 3.13.9     | ok  | ok  | ok, binding off | ok  |
| asyncpg 0.32.0 / Python 3.13.9      | ok* | ok* | ok*             | ok* |
| node-postgres 8.23.1 / Node 22.23.2 | ok  | ok  | ok, binding off | ok  |
| JDBC 42.7.8 / Java 21               | ok  | ok  | ok, binding off | ok  |
| Npgsql 8.0.8 / .NET 8               | ok  | ok  | ok, binding off | ok  |
| SQLx 0.8.6, native TLS / Rust 1.91  | ok  | ok  | ok              | ok  |
| SQLx 0.8.6, rustls / Rust 1.91      | ok* | ok* | ok*             | ok* |
| PDO_pgsql / PHP 8.4                 | ok  | ok  | ok, binding off | ok  |
| `pg` 1.5.9 / Ruby 2.6               | ok  | ok  | ok, binding off | ok  |

The #294 write-half-close fix removed asyncpg and SQLx/rustls close timeouts in P and D. A proper test CA and signed server certificate removed rustls's `CaUsedAsEndEntity` rejection in S and T. `SCRAM-SHA-256-PLUS` still receives the authored `28000` error in D; requiring channel binding works in S and T. Wrong CA, wrong hostname, and plaintext visitor checks were rejected as expected.

## mysql

**P:** verified visitor TLS → plaintext target. **T:** separate verified target TLS. **V:** visitor TLS passthrough. Clients ran `SELECT 1`, a prepared/parameterized value of `23`, two result sets, and close unless qualified.

| client / runtime              | P   | T   | V                    |
| ----------------------------- | --- | --- | -------------------- |
| MySQL CLI 8.4.11              | ok  | —   | —                    |
| MariaDB CLI 11.8.9            | ok  | —   | —                    |
| MariaDB Connector C 3.4.10    | ok  | —   | —                    |
| PyMySQL 1.2.3 / Python 3.13.9 | ok  | ok  | ok                   |
| mysql-connector-python 26.7.0 | ok  | ok  | C: no SNI; pure: ok* |
| mysql2 3.24.6 / Node 22.23.2  | ok* | ok* | ok*                  |
| Connector/J 9.5.0 / Java 21   | ok  | —   | —                    |
| MySqlConnector 2.5.0 / .NET 9 | ok  | —   | —                    |
| SQLx 0.8.6 / Rust 1.91        | ok  | —   | —                    |
| PDO_mysql / PHP 8.4           | ok  | ok  | ok                   |
| Ruby mysql2 0.5.7 / Ruby 3.3  | ok  | ok  | ok                   |

The MySQL and MariaDB CLIs worked without SNI in P on their allocated port; the MySQL CLI also passed `VERIFY_IDENTITY`. With #294, node-mysql2's query, `end()`, and process exit passed **5/5** in V, without `destroy()`; direct, P, and T controls also exited **5/5**. In V, mysql-connector-python's C extension sent no SNI and was rejected **3/3**; `use_pure=True` sent the public hostname and passed **3/3**. Exact SNI remains required for passthrough. Wrong CA and nonempty wrong-SNI attempts were rejected. Fresh-target direct MySQL authentication sometimes failed before its cache was warm, also without tnl in the path.

## redis

Redis visitor TLS was verified in both modes: **P** is a plaintext target; **T** is a separately verified TLS target. The checks covered `AUTH`, `PING`, `SET`/`GET`, pipeline, transactions, Pub/Sub delivery, and close.

| client / runtime                    | P   | T   | RESP3                          |
| ----------------------------------- | --- | --- | ------------------------------ |
| redis-cli 7.4                       | ok  | ok  | ok; Pub/Sub stopped by timeout |
| redis-py 7.0.1 / Python 3.13.9      | ok  | ok  | ok                             |
| node-redis 6.3.0 / Node 22.23.2     | ok  | ok  | ok                             |
| ioredis 6.0.0 / Node 22.23.2        | ok  | ok  | ok                             |
| Lettuce 6.8.1 / Java 21             | ok  | ok  | ok                             |
| StackExchange.Redis 2.9.32 / .NET 8 | ok  | ok  | —                              |
| redis crate 0.32.7 / Rust 1.91      | ok  | ok  | ok                             |
| phpredis 6.3.0 / PHP 8.4            | ok  | ok  | unsupported by client          |
| redis gem 4.8.1 / Ruby 2.6          | ok  | ok  | unsupported by client          |

Wrong credentials, CA, and hostname were rejected. phpredis and Ruby RESP3 failures also occurred directly against Redis; they are not publisher failures. Python and Node results were repeated with the mise-pinned runtimes.

## ssh

All clients verified the disposable target's pinned ED25519 host key, rejected a wrong key, ran a command, and closed on both direct and publisher paths. File-transfer coverage is noted below; SSH uses its own encryption rather than visitor TLS.

| client / runtime                  | direct | publisher | transfer |
| --------------------------------- | ------ | --------- | -------- |
| OpenSSH `ssh`/`scp`/`sftp` 10.3p1 | ok     | ok        | SCP/SFTP |
| Paramiko 5.0.0 / Python 3.13.9    | ok     | ok        | SFTP     |
| ssh2 1.17.0 / Node 22.23.2        | ok     | ok        | SFTP     |
| SSHJ 0.40.0 / Java 21             | ok     | ok        | SFTP     |
| SSH.NET 2025.1.0 / .NET 8         | ok     | ok        | SFTP     |
| net-ssh / net-sftp / Ruby 2.6     | ok     | ok        | SFTP     |
| russh / russh-sftp / Rust 1.91    | ok     | ok        | SFTP     |
| phpseclib 3.0.57 / PHP 8.5.9      | ok     | ok        | SFTP     |
| Plink 0.85                        | ok     | ok        | —        |

OpenSSH and Plink `-L` worked directly and through the publisher after enabling forwarding **only on the disposable SSH server**; its default setting denied both paths.

## tableplus and limits

The user tested the default publisher path with TablePlus on PR #288 (not rerun on #294): PostgreSQL **Verify Full** returned `SELECT 1` → `1` and private-target `ssl=false`; MySQL **Verify Identity** returned `1` and an empty private-target `Ssl_cipher`; Redis **Verify Peer** worked, but hostname verification was not independently established. The TablePlus version and individual Redis command outputs were not recorded.

All test-owned fixtures, containers, and temporary dependencies were removed. The public CA PEM moved to Downloads at the user's request and was not removed. The manual matrix did not exercise the full ingress/relay path or PR #288's Linux client-state encryption; a separate PostgreSQL split-topology integration test passed. PR #294's CI should be read separately from these local client results.

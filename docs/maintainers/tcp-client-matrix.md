# tcp client compatibility

These checks exercise TCP visitors at the local publisher with disposable targets.
Run `mise exec -- task go:test:integration:tcp-clients` for the real-client
cases; `mise exec -- task go:test:integration:postgres-tls` covers PostgreSQL
target TLS. The [publisher tests](../../internal/publisher/) are the source for
the modes below. P means verified visitor TLS with a plaintext target; T means
a separate, certificate-verified TLS connection to the target. SSH checks its
own host key instead of using visitor TLS.

| protocol   | current test client        | verified mode and operation                              |
| ---------- | -------------------------- | -------------------------------------------------------- |
| PostgreSQL | Go pgx/v5                  | P: `verify-full`, query, close; T: query and cancel.     |
| MySQL      | Go `go-sql-driver/mysql`   | P: query, prepared statement, multiple results, error.   |
| Redis      | Go TLS client sending RESP | P: `AUTH`, `PING`, `SET`/`GET`; T: TLS test target only. |
| SSH        | Go `x/crypto/ssh`          | Pinned ED25519 key, command, wrong-key rejection.        |

PostgreSQL P uses a plaintext target; T accepts required channel binding with
matching certificates, rejects it with different certificates, and supports
encrypted cancellation with binding disabled for a different-certificate target.
The [PostgreSQL TLS tests](../../internal/publisher/postgres_tls_integration_test.go)
also check cancellation with a plaintext target. MySQL P reports an empty
private `Ssl_cipher`. The [Redis test](../../internal/publisher/redis_forwarding_test.go)
checks real Redis only in P; T uses a test TLS target, not Redis. SSH uses no
visitor TLS. These are local publisher checks; separate split-topology tests in
[#332](https://github.com/tnldotdev/tnl/pull/332) are on another branch.

## historical tableplus checks

A user performed these checks on old [#291](https://github.com/tnldotdev/tnl/pull/291)
against the default publisher path before the TCP write-half-close fix in
[#294](https://github.com/tnldotdev/tnl/pull/294). They were not rerun after
that fix or on this stack; the TablePlus version was not recorded.

| protocol   | old user-performed check                 | boundary                                                                                 |
| ---------- | ---------------------------------------- | ---------------------------------------------------------------------------------------- |
| PostgreSQL | Verify Full, `SELECT 1` returned `1`     | Private target reported `ssl=false` (P).                                                 |
| MySQL      | Verify Identity, `SELECT 1` returned `1` | Private target `Ssl_cipher` was empty (P).                                               |
| Redis      | Verify Peer connected                    | P; hostname verification and individual command outputs were not independently recorded. |

The old matrix reported affected client retests after #294. Current
[write-half-close tests](../../internal/publisher/database_inspection_conn_test.go)
and [Redis drain tests](../../internal/publisher/redis_inspection_test.go) cover
response-after-EOF behavior in this stack; they do not rerun the old client
survey or the TablePlus checks.

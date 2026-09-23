# automation

Use machine-readable output when another program needs tunnel state. Do not
parse human diagrams: their layout is for terminals, not automation.

## choose an output

| Command                       | Output       | Use it for                                          |
| ----------------------------- | ------------ | --------------------------------------------------- |
| `tnl publish --output=ndjson` | Event stream | Following one tunnel as it starts and runs          |
| `tnl status --output=json`    | Snapshot     | Inspecting all matching local tunnels at one moment |

Both formats use `schema_version: 1`.

## read the correct stream

Finite command results go to stdout. Prompts, warnings, lifecycle diagrams, and
errors go to stderr.

Important exceptions are:

- `tnl publish --output=ndjson` writes events to stdout;
- `tnl status --output=json` writes one JSON object to stdout;
- `tnl team invite create` writes one tab-separated credential line to stdout;
- `tnl version` writes one raw version line to stdout;
- `tnl dev` preserves the child process's stdin, stdout, and stderr.

An NDJSON terminal error can therefore appear on stdout while the rendered
top-level diagnostic appears on stderr.

## follow publish events

Each line from `tnl publish --output=ndjson` is one JSON object. Every event has:

| Field            | Type             | Meaning                                        |
| ---------------- | ---------------- | ---------------------------------------------- |
| `schema_version` | integer          | Always `1`.                                    |
| `type`           | string           | Event type.                                    |
| `cursor`         | unsigned integer | Increases from 1 during this command.          |
| `tunnel_id`      | string           | Local tunnel ID, or empty before registration. |

The cursor orders events from one process. It is not a replay token and is not
stable across invocations.

Event types are:

| Type         | Additional fields                                               | Meaning                                                 |
| ------------ | --------------------------------------------------------------- | ------------------------------------------------------- |
| `starting`   | `target`                                                        | The local tunnel was registered.                        |
| `current_ip` | `ip`                                                            | The current client IP was added to a restricted policy. |
| `warning`    | Varies below                                                    | The tunnel continues, but something needs attention.    |
| `ready`      | `url`, `route_version`                                          | The route version became ready.                         |
| `error`      | `message`, `retryable`; optional `code`, `help_url`, `retry_at` | The command failed.                                     |
| `stopped`    | `reason`                                                        | The command stopped; the current reason is `canceled`.  |

Warning variants are:

| Warning              | Fields                                                                 | Meaning                                                     |
| -------------------- | ---------------------------------------------------------------------- | ----------------------------------------------------------- |
| Provisioning stalled | `message`, `code`, `help_url`, `retryable: true`, `route_version`      | Certificate or publisher-connection work is still retrying. |
| Transport fallback   | `message`, `retryable: false`, `route_version`, `transport: "tls-tcp"` | TLS/TCP established before QUIC.                            |

The stream does not emit events for ordinary provisioning progress, route
assignment, draining, or blocked-visitor totals.

Example:

```json
{"schema_version":1,"type":"starting","cursor":1,"tunnel_id":"tunnel_00000000000000000000000000000000","target":"http://127.0.0.1:3000"}
{"schema_version":1,"type":"current_ip","cursor":2,"tunnel_id":"tunnel_00000000000000000000000000000000","ip":"192.0.2.10"}
{"schema_version":1,"type":"ready","cursor":3,"tunnel_id":"tunnel_00000000000000000000000000000000","url":"https://api.alice-fake.example.test","route_version":4}
{"schema_version":1,"type":"stopped","cursor":4,"tunnel_id":"tunnel_00000000000000000000000000000000","reason":"canceled"}
```

After an `error` event, the process exits unsuccessfully. After a `stopped`
event caused by cancellation, the process exits normally.

## read a status snapshot

`tnl status --output=json` writes one object followed by a newline:

```json
{
  "schema_version": 1,
  "observed_at": "2030-01-01T12:00:00Z",
  "summary": {
    "total": 1,
    "starting": 0,
    "provisioning": 0,
    "ready": 1,
    "draining": 0,
    "stale": 0
  },
  "tunnels": [
    {
      "tunnel_id": "tunnel_00000000000000000000000000000000",
      "command": "dev",
      "state": "ready",
      "process_id": 12345,
      "server": "https://control.example.test",
      "project": "/Users/example/work/hello",
      "service": "web",
      "route_id": "route_00000000000000000000000000000000",
      "route_version": 7,
      "hostname": "web.alice-fake.example.test",
      "public_url": "https://web.alice-fake.example.test",
      "target": "http://127.0.0.1:5173",
      "framework": "vite",
      "started_at": "2030-01-01T11:59:00Z",
      "updated_at": "2030-01-01T11:59:10Z",
      "heartbeat_at": "2030-01-01T11:59:55Z",
      "lease_expires_at": "2030-01-01T12:00:15Z"
    }
  ]
}
```

Every tunnel includes:

| Field                                                          | Type              |
| -------------------------------------------------------------- | ----------------- |
| `tunnel_id`, `command`, `state`, `server`, `project`           | string            |
| `process_id`                                                   | integer           |
| `started_at`, `updated_at`, `heartbeat_at`, `lease_expires_at` | RFC3339 timestamp |

These fields are optional and omitted when unknown:

| Field                                                                  | Type             |
| ---------------------------------------------------------------------- | ---------------- |
| `service`, `route_id`, `hostname`, `public_url`, `target`, `framework` | string           |
| `route_version`                                                        | unsigned integer |

Tunnel states are `starting`, `provisioning`, `ready`, `draining`, and `stale`.
The `summary` object contains a count for every state plus `total`.

Without `--all`, status selects the current project. With `--all`, it includes
every local project known to the selected client state directory.

## handle diagnostics

Classified diagnostics have a stable code and help URL. Programs should use the
code rather than matching human text.

| Code                                 | Meaning                                                    |
| ------------------------------------ | ---------------------------------------------------------- |
| `TNL_TARGET_UNAVAILABLE`             | The publisher cannot connect to the target.                |
| `TNL_TARGET_INVALID`                 | The target is not a supported local HTTP origin or port.   |
| `TNL_ROUTE_INVALID`                  | The publisher cannot use the assigned hostname.            |
| `TNL_REQUEST_REJECTED`               | The publisher rejected a request before the local service. |
| `TNL_FRAMEWORK_REGISTRATION_TIMEOUT` | The framework did not register in time.                    |
| `TNL_TARGET_MISMATCH`                | A framework reported a different forced port.              |
| `TNL_AUTHENTICATION_TIMEOUT`         | Interactive authentication expired.                        |
| `TNL_SERVICE_AMBIGUOUS`              | Several services exist and none was selected.              |
| `TNL_ROUTE_CONFLICT`                 | Existing route state conflicts with the request.           |
| `TNL_PROVISIONING_STALLED`           | Provisioning is incomplete while retries continue.         |

Unclassified errors have no stable code. Treat their text as a human diagnostic,
not an API.

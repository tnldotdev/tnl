"""installed psycopg against the real prepared owner, ingress and TLS provider."""

from __future__ import annotations

import asyncio
import json
import sys
import tempfile
import threading
import time
from pathlib import Path

import psycopg
from psycopg import pq

import tnl


async def main() -> None:
    handle = tnl.connect("database")
    settings = await handle
    assert isinstance(settings, tnl.PostgresConnection)
    assert settings.ssl.check_hostname and settings.ca
    with tempfile.TemporaryDirectory(prefix="tnl-psycopg-") as directory:
        ca = Path(directory) / "ca.pem"
        ca.write_text(settings.ca)

        def connect(selected: tnl.PostgresConnection) -> psycopg.Connection[tuple[object, ...]]:
            return psycopg.connect(
                host=selected.server_hostname,
                hostaddr=selected.host,
                port=selected.port,
                sslmode="verify-full",
                sslrootcert=str(ca),
                channel_binding="disable",
                gssencmode="disable",
                user="tnl_client",
                password="testpass",
                dbname="tnl_fixture",
                connect_timeout=5,
                autocommit=True,
            )

        wrong = await tnl.connect("wrong-name")
        assert isinstance(wrong, tnl.PostgresConnection)
        try:
            connect(wrong).close()
        except psycopg.OperationalError:
            pass
        else:
            raise AssertionError("psycopg accepted the wrong TLS name")

        with connect(settings) as original, connect(settings) as independent:
            pid = original.info.backend_pid
            assert original.execute(
                "SELECT current_user, ssl FROM pg_stat_ssl WHERE pid=pg_backend_pid()"
            ).fetchone() == ("tnl_client", True)
            original.execute("CREATE TEMP SEQUENCE cancel_attempt")
            original.execute("SET statement_timeout='1800ms'")
            errors: list[psycopg.Error] = []

            def sleep() -> None:
                try:
                    original.execute("SELECT nextval('cancel_attempt'); SELECT pg_sleep(10)")
                except psycopg.Error as error:
                    errors.append(error)

            worker = threading.Thread(target=sleep)
            worker.start()
            try:
                deadline = time.monotonic() + 3
                while time.monotonic() < deadline:
                    if independent.execute(
                        "SELECT EXISTS (SELECT 1 FROM pg_stat_activity "
                        "WHERE pid=%s AND wait_event='PgSleep')",
                        (pid,),
                    ).fetchone() == (True,):
                        break
                    time.sleep(0.01)
                else:
                    raise AssertionError("psycopg query never reached PgSleep")
                # this installed libpq's ordinary cancellation request is not an
                # authenticated continuation of the original managed session.
                original.cancel()
                assert independent.execute("SELECT 1").fetchone() == (1,)
            finally:
                worker.join(timeout=4)
            assert not worker.is_alive() and len(errors) == 1
            assert errors[0].sqlstate == "57014" and "statement timeout" in str(errors[0])
            assert original.info.backend_pid == pid
            assert original.execute("SELECT last_value FROM cancel_attempt").fetchone() == (1,)
        await handle.aclose()
    print(
        json.dumps(
            {
                "driver": "psycopg",
                "version": psycopg.__version__,
                "python": sys.version.split()[0],
                "libpq": pq.version(),
                "tls": "verify-full; hostaddr=loopback; channel_binding=disable",
                "native_cancel": "unsupported; query bounded by statement_timeout; no replay",
                "wrong_name": "rejected",
            }
        )
    )


try:
    asyncio.run(main())
except Exception:
    # do not expose SQL, credentials or raw driver exceptions from this consumer.
    print(json.dumps({"driver": "psycopg", "status": "CHECK_FAILED"}))
    raise SystemExit(1) from None

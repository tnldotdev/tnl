"""ordinary psycopg pools over the built native owner's verified TLS settings."""

import asyncio
import sys
import tempfile
from pathlib import Path

from psycopg_pool import AsyncConnectionPool

import tnl
from tnl import _connections

_connections.native_binary = lambda: Path(sys.argv[1])


async def main() -> None:
    closed: list[AsyncConnectionPool] = []
    with tempfile.TemporaryDirectory(prefix="tnl-psycopg-ca-") as directory:

        async def create(connection: tnl.Connection | tnl.LocalConnection) -> AsyncConnectionPool:
            assert isinstance(connection, tnl.PostgresConnection)
            assert connection.ca is not None
            ca = Path(directory) / "ca.pem"
            ca.write_text(connection.ca)
            pool = AsyncConnectionPool(
                open=False,
                min_size=0,
                max_size=1,
                timeout=5,
                kwargs={
                    "host": connection.server_hostname,
                    "hostaddr": connection.host,
                    "port": connection.port,
                    "sslmode": "verify-full",
                    "sslrootcert": str(ca),
                    "channel_binding": "disable",
                    "gssencmode": "disable",
                    "user": "tnl_client",
                    "password": "testpass",
                    "dbname": "tnl_fixture",
                    "connect_timeout": 5,
                },
            )
            await pool.open()
            return pool

        async def close(pool: AsyncConnectionPool) -> None:
            await pool.close()
            closed.append(pool)

        async def pid(pool: AsyncConnectionPool) -> int:
            async with pool.connection() as connection:
                cursor = await connection.execute(
                    "SELECT pg_backend_pid(), current_user, ssl "
                    "FROM pg_stat_ssl WHERE pid=pg_backend_pid()"
                )
                row = await cursor.fetchone()
                assert row is not None and row[1] == "tnl_client" and row[2] is True
                assert isinstance(row[0], int)
                return row[0]

        deployment = tnl.create_client(
            project="fixture/driver-fixture", services={"database": {"protocol": "postgres"}}
        ).deployment("production")
        get = deployment.client("database", create=create, close=close)
        try:
            first = await get()
            original = await pid(first)
            assert all(value is first for value in await asyncio.gather(*(get() for _ in range(8))))
            assert await pid(first) == original and closed == []
            print("binding-a", flush=True)
            assert await asyncio.to_thread(input) == "next"
            second = await get()
            assert second is not first and await pid(second) != original
            assert await pid(first) == original and closed == []
            print("binding-b", flush=True)
            assert await asyncio.to_thread(input) == "next"
            assert await get() is first and await pid(first) == original
            await asyncio.gather(get.aclose(), get.aclose())
            assert len(closed) == 2 and first in closed and second in closed
            await get.aclose()
            assert len(closed) == 2
            try:
                await get()
            except tnl.TnlError as error:
                assert error.code == "sdk.client_closed"
            else:
                raise AssertionError("closed factory reused a database pool")
            assert first.closed and second.closed
            print("closed", flush=True)
        finally:
            await get.aclose()
            await deployment.aclose()


asyncio.run(main())

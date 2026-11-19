import { expect, test } from "vitest";
import type { TnlTLSStream } from "@tnldotdev/tnl";
import { concat, MAX_PACKET, text, uint32, utf8, Wire } from "./bytes.ts";
import { MySQLFixtureClient } from "./mysql.ts";
import { PostgresFixtureClient } from "./postgres.ts";

// these unit fixtures only validate the bounded application wire helpers. they
// do not qualify the SDK, create an admission, or replace the integration topology.
function input(chunks: Uint8Array[]) {
  const writes: Uint8Array[] = [];
  let closed = false;
  let upgrades = 0;
  const stream: TnlTLSStream = {
    readable: new ReadableStream({
      start(controller) {
        for (const chunk of chunks) controller.enqueue(chunk);
        controller.close();
      },
    }),
    writable: new WritableStream({
      write(bytes) {
        writes.push(bytes.slice());
      },
    }),
    async close() {
      closed = true;
    },
    async startTls() {
      expect(writes).toHaveLength(1);
      expect(writes[0]?.byteLength).toBe(36);
      expect(writes[0]?.[3]).toBe(1);
      upgrades++;
    },
  };
  return { stream, writes, closed: () => closed, upgrades: () => upgrades };
}

const credentials = { user: "fixture", password: "fixture-password", database: "fixture" };
function postgres(kind: string, body = new Uint8Array(0)): Uint8Array {
  return concat(text.encode(kind), uint32(body.byteLength + 4), body);
}
function mysql(sequence: number, body: Uint8Array): Uint8Array {
  return concat(new Uint8Array([body.byteLength & 255, body.byteLength >> 8, 0, sequence]), body);
}

test("wire joins fragments and rejects unbounded or truncated packets", async () => {
  const fixture = input([new Uint8Array([1]), new Uint8Array([2, 3]), new Uint8Array([4])]);
  const wire = new Wire(fixture.stream);
  expect(await wire.read(3)).toEqual(new Uint8Array([1, 2, 3]));
  expect(await wire.read(1)).toEqual(new Uint8Array([4]));
  await expect(wire.read(MAX_PACKET + 1)).rejects.toThrow("bound");
  await expect(wire.read(1)).rejects.toThrow("complete");
  await wire.close();
  expect(fixture.closed()).toBe(true);
});

test("PostgreSQL simple-query helper handles rows without surfacing server data", async () => {
  const row = concat(
    new Uint8Array([0, 2]),
    uint32(2),
    text.encode("42"),
    uint32(3),
    text.encode("123"),
  );
  const fixture = input([
    postgres("R", uint32(0)),
    postgres("Z", text.encode("I")),
    postgres("D", row),
    postgres("C", text.encode("SELECT 1\0")),
    postgres("Z", text.encode("I")),
  ]);
  const client = await PostgresFixtureClient.connect(fixture.stream, credentials);
  expect(await client.query("SELECT 42,123")).toEqual([["42", "123"]]);
  expect(utf8.decode(fixture.writes[1]?.subarray(5))).toBe("SELECT 42,123\0");
  await client.close();
  expect(fixture.closed()).toBe(true);
});

test("PostgreSQL authentication errors close their stream and redact server messages", async () => {
  const fixture = input([postgres("E", text.encode("secret echoed by target"))]);
  await expect(PostgresFixtureClient.connect(fixture.stream, credentials)).rejects.toThrow(
    "PostgreSQL rejected the fixture operation",
  );
  expect(fixture.closed()).toBe(true);
});

test("PostgreSQL rejects unsupported authentication instead of sending a password", async () => {
  const fixture = input([postgres("R", concat(uint32(5), new Uint8Array(4)))]);
  await expect(PostgresFixtureClient.connect(fixture.stream, credentials)).rejects.toThrow(
    "unsupported",
  );
  expect(fixture.writes).toHaveLength(1);
  expect(fixture.closed()).toBe(true);
});

test("MySQL helper sends SSLRequest and upgrades before sending a login", async () => {
  const flags = (1 << 9) | (1 << 11) | (1 << 13) | (1 << 15) | (1 << 19) | (1 << 3);
  const greeting = concat(
    new Uint8Array([10]),
    text.encode("8.4.0\0"),
    uint32(123, true),
    text.encode("abcdefgh"),
    new Uint8Array([
      0,
      flags & 255,
      (flags >> 8) & 255,
      45,
      0,
      0,
      (flags >> 16) & 255,
      (flags >> 24) & 255,
      21,
    ]),
    new Uint8Array(10),
    text.encode("ijklmnopqrst\0caching_sha2_password\0"),
  );
  const fixture = input([
    mysql(0, greeting),
    mysql(3, new Uint8Array([1, 4])),
    mysql(5, new Uint8Array([0])),
    mysql(1, new Uint8Array([2])),
    mysql(2, new Uint8Array([1])),
    mysql(3, new Uint8Array([1])),
    mysql(4, new Uint8Array([0xfe, 0, 0, 0, 0])),
    mysql(
      5,
      concat(new Uint8Array([2]), text.encode("42"), new Uint8Array([3]), text.encode("123")),
    ),
    mysql(6, new Uint8Array([0xfe, 0, 0, 0, 0])),
  ]);
  const client = await MySQLFixtureClient.connect(fixture.stream, credentials);
  expect(fixture.upgrades()).toBe(1);
  expect(fixture.writes[0]?.byteLength).toBe(36);
  expect(fixture.writes[1]?.[3]).toBe(2);
  expect(utf8.decode(fixture.writes[2]?.subarray(4))).toBe("fixture-password\0");
  expect(await client.query()).toEqual({ value: 42, connectionID: 123 });
  await client.close();
  expect(fixture.closed()).toBe(true);
});

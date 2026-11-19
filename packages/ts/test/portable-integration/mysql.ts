import type { TnlTLSStream } from "@tnldotdev/tnl";
import { check, type Credentials } from "./fixture.ts";
import { concat, MAX_PACKET, text, uint32, utf8, Wire } from "./bytes.ts";

const CLIENT_PROTOCOL_41 = 1 << 9;
const CLIENT_SSL = 1 << 11;
const CLIENT_TRANSACTIONS = 1 << 13;
const CLIENT_SECURE_CONNECTION = 1 << 15;
const CLIENT_PLUGIN_AUTH = 1 << 19;
const CLIENT_CONNECT_WITH_DB = 1 << 3;

async function scramble(password: string, seed: Uint8Array, plugin: string): Promise<Uint8Array> {
  check(
    plugin === "caching_sha2_password" || plugin === "mysql_native_password",
    "unsupported MySQL fixture authentication",
  );
  const hash = async (value: Uint8Array) =>
    new Uint8Array(
      await crypto.subtle.digest(
        plugin === "caching_sha2_password" ? "SHA-256" : "SHA-1",
        new Uint8Array(value),
      ),
    );
  const first = await hash(text.encode(password));
  const second = await hash(first);
  const mask = await hash(
    plugin === "caching_sha2_password" ? concat(second, seed) : concat(seed, second),
  );
  return Uint8Array.from(first, (value, index) => value ^ (mask[index] ?? 0));
}

function zeroString(bytes: Uint8Array, start: number): { value: string; next: number } {
  const end = bytes.indexOf(0, start);
  check(end >= start, "MySQL greeting has no string terminator");
  return { value: utf8.decode(bytes.subarray(start, end)), next: end + 1 };
}

// only the greeting/login and one text query are needed here. relay selection,
// MySQL SSLRequest, and verified visitor TLS still run through the real SDK.
export class MySQLFixtureClient {
  private readonly wire: Wire;

  private constructor(wire: Wire) {
    this.wire = wire;
  }

  static async connect(
    stream: TnlTLSStream,
    credentials: Credentials,
  ): Promise<MySQLFixtureClient> {
    const client = new MySQLFixtureClient(new Wire(stream));
    try {
      await client.start(stream, credentials);
      return client;
    } catch (error) {
      await client.close();
      throw error;
    }
  }

  private async receive(): Promise<{ sequence: number; body: Uint8Array }> {
    const header = await this.wire.read(4);
    const size = (header[0] ?? 0) + ((header[1] ?? 0) << 8) + ((header[2] ?? 0) << 16);
    check(size > 0 && size <= MAX_PACKET, "invalid MySQL fixture packet size");
    const body = await this.wire.read(size);
    check(body[0] !== 0xff, "MySQL rejected the fixture operation");
    return { sequence: header[3] ?? 0, body };
  }

  private send(body: Uint8Array, sequence: number): Promise<void> {
    check(body.byteLength < 1 << 24, "oversized MySQL fixture write");
    return this.wire.write(
      concat(
        new Uint8Array([
          body.byteLength & 255,
          (body.byteLength >> 8) & 255,
          (body.byteLength >> 16) & 255,
          sequence,
        ]),
        body,
      ),
    );
  }

  private async start(stream: TnlTLSStream, credentials: Credentials): Promise<void> {
    const greeting = await this.receive();
    check(greeting.sequence === 0 && greeting.body[0] === 10, "invalid MySQL greeting");
    const version = zeroString(greeting.body, 1);
    const capabilities = version.next + 4 + 8 + 1;
    check(greeting.body.byteLength >= capabilities + 31, "truncated MySQL greeting");
    const view = new DataView(
      greeting.body.buffer,
      greeting.body.byteOffset,
      greeting.body.byteLength,
    );
    const offered =
      view.getUint16(capabilities, true) | (view.getUint16(capabilities + 5, true) << 16);
    const required =
      CLIENT_PROTOCOL_41 |
      CLIENT_SSL |
      CLIENT_TRANSACTIONS |
      CLIENT_SECURE_CONNECTION |
      CLIENT_PLUGIN_AUTH |
      CLIENT_CONNECT_WITH_DB;
    check((offered & required) === required, "MySQL fixture requires TLS and protocol 4.1");
    let seed = concat(
      greeting.body.slice(version.next + 4, version.next + 12),
      greeting.body.slice(capabilities + 18, capabilities + 30),
    );
    let plugin = zeroString(greeting.body, capabilities + 31).value;
    const flags = concat(
      uint32(required, true),
      uint32(MAX_PACKET, true),
      new Uint8Array([45]),
      new Uint8Array(23),
    );
    await this.send(flags, 1);
    await stream.startTls();
    const proof = await scramble(credentials.password, seed, plugin);
    await this.send(
      concat(
        flags,
        text.encode(credentials.user + "\0"),
        new Uint8Array([proof.byteLength]),
        proof,
        text.encode(credentials.database + "\0" + plugin + "\0"),
      ),
      2,
    );
    for (let step = 0; step < 8; step++) {
      const packet = await this.receive();
      const kind = packet.body[0];
      if (kind === 0) return;
      if (kind === 0xfe) {
        const replacement = zeroString(packet.body, 1);
        plugin = replacement.value;
        seed = packet.body.slice(replacement.next);
        if (seed[seed.byteLength - 1] === 0) seed = seed.slice(0, -1);
        await this.send(await scramble(credentials.password, seed, plugin), packet.sequence + 1);
      } else if (kind === 1 && packet.body[1] === 3) {
        // caching_sha2_password's fast authentication success precedes OK.
        continue;
      } else if (kind === 1 && packet.body[1] === 4) {
        // visitor TLS is already verified. the publisher independently owns
        // target-side TLS or RSA password translation on a plaintext target.
        await this.send(text.encode(credentials.password + "\0"), packet.sequence + 1);
      } else {
        throw new Error("unsupported MySQL authentication exchange");
      }
    }
    throw new Error("MySQL authentication exceeded fixture bounds");
  }

  async query(): Promise<{ value: number; connectionID: number }> {
    await this.send(concat(new Uint8Array([3]), text.encode("SELECT 42, CONNECTION_ID()")), 0);
    const count = await this.receive();
    check(count.body.byteLength === 1 && count.body[0] === 2, "unexpected MySQL column count");
    await this.receive();
    await this.receive();
    const fieldsEnd = await this.receive();
    check(
      fieldsEnd.body[0] === 0xfe && fieldsEnd.body.byteLength < 9,
      "MySQL field terminator is missing",
    );
    const row = await this.receive();
    let offset = 0;
    const values: string[] = [];
    for (let column = 0; column < 2; column++) {
      const size = row.body[offset++];
      check(
        size !== undefined && size < 251 && offset + size <= row.body.byteLength,
        "invalid MySQL fixture result",
      );
      values.push(utf8.decode(row.body.subarray(offset, offset + size)));
      offset += size;
    }
    check(offset === row.body.byteLength, "MySQL result has trailing bytes");
    const end = await this.receive();
    check(end.body[0] === 0xfe && end.body.byteLength < 9, "MySQL row terminator is missing");
    const value = Number(values[0]);
    const connectionID = Number(values[1]);
    check(
      value === 42 && Number.isSafeInteger(connectionID) && connectionID > 0,
      "MySQL application query did not match",
    );
    return { value, connectionID };
  }

  close(): Promise<void> {
    return this.wire.close();
  }
}

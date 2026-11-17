import type { TnlStream } from "@tnldotdev/tnl";
import { check, type Credentials } from "./fixture.ts";
import { concat, MAX_PACKET, number32, text, uint32, utf8, Wire } from "./bytes.ts";

function base64(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes));
}
function unbase64(value: string): Uint8Array<ArrayBuffer> {
  return Uint8Array.from(atob(value), (character) => character.charCodeAt(0));
}
async function digest(bytes: Uint8Array): Promise<Uint8Array<ArrayBuffer>> {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", new Uint8Array(bytes)));
}
async function hmac(key: Uint8Array, value: string): Promise<Uint8Array<ArrayBuffer>> {
  const imported = await crypto.subtle.importKey(
    "raw",
    new Uint8Array(key),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  return new Uint8Array(await crypto.subtle.sign("HMAC", imported, text.encode(value)));
}
function attributes(value: string): Map<string, string> {
  const result = new Map<string, string>();
  for (const entry of value.split(",")) {
    check(entry.length > 2 && entry[1] === "=", "invalid SCRAM attribute");
    const key = entry[0];
    check(key !== undefined && !result.has(key), "duplicate SCRAM attribute");
    result.set(key, entry.slice(2));
  }
  return result;
}

// minimal simple-query client for this fixture. authentication still reaches the
// real application database, including SCRAM proof and server signature checks.
export class PostgresFixtureClient {
  private readonly wire: Wire;

  private constructor(wire: Wire) {
    this.wire = wire;
  }

  static async connect(
    stream: TnlStream,
    credentials: Credentials,
  ): Promise<PostgresFixtureClient> {
    const client = new PostgresFixtureClient(new Wire(stream));
    try {
      await client.start(credentials);
      return client;
    } catch (error) {
      await client.close();
      throw error;
    }
  }

  private message(kind: string, body: Uint8Array): Promise<void> {
    return this.wire.write(concat(text.encode(kind), uint32(body.byteLength + 4), body));
  }

  private async receive(): Promise<{ kind: string; body: Uint8Array }> {
    const header = await this.wire.read(5);
    const size = number32(header.subarray(1)) - 4;
    check(size >= 0 && size <= MAX_PACKET, "invalid PostgreSQL message size");
    const kind = String.fromCharCode(header[0] ?? 0);
    const body = await this.wire.read(size);
    // never surface server errors: they may echo a query or an application secret.
    check(kind !== "E", "PostgreSQL rejected the fixture operation");
    return { kind, body };
  }

  private async start(credentials: Credentials): Promise<void> {
    const startup = concat(
      uint32(196608),
      text.encode(
        `user\0${credentials.user}\0database\0${credentials.database}\0client_encoding\0UTF8\0\0`,
      ),
    );
    await this.wire.write(concat(uint32(startup.byteLength + 4), startup));
    let first = "";
    let nonce = "";
    let expectedSignature = "";
    let signatureVerified = false;
    let authenticated = false;
    for (;;) {
      const { kind, body } = await this.receive();
      if (kind === "Z") {
        check(authenticated, "PostgreSQL became ready without authentication");
        return;
      }
      if (kind !== "R") continue;
      const method = number32(body);
      if (method === 0) {
        check(
          expectedSignature === "" || signatureVerified,
          "PostgreSQL omitted its SCRAM server signature",
        );
        authenticated = true;
      } else if (method === 3) {
        await this.message("p", text.encode(credentials.password + "\0"));
      } else if (method === 10) {
        check(
          utf8.decode(body.subarray(4)).split("\0").includes("SCRAM-SHA-256"),
          "PostgreSQL requires unsupported authentication",
        );
        nonce = base64(crypto.getRandomValues(new Uint8Array(18)));
        first = `n=,r=${nonce}`;
        const initial = text.encode("n,," + first);
        await this.message(
          "p",
          concat(text.encode("SCRAM-SHA-256\0"), uint32(initial.byteLength), initial),
        );
      } else if (method === 11) {
        const serverFirst = utf8.decode(body.subarray(4));
        const fields = attributes(serverFirst);
        const serverNonce = fields.get("r");
        const salt = fields.get("s");
        const iterations = Number(fields.get("i"));
        check(
          nonce !== "" &&
            serverNonce?.startsWith(nonce) &&
            serverNonce.length > nonce.length &&
            salt !== undefined,
          "invalid SCRAM server challenge",
        );
        check(
          Number.isSafeInteger(iterations) && iterations >= 4096 && iterations <= 100_000,
          "SCRAM iteration count exceeds fixture bounds",
        );
        const key = await crypto.subtle.importKey(
          "raw",
          text.encode(credentials.password),
          "PBKDF2",
          false,
          ["deriveBits"],
        );
        const salted = new Uint8Array(
          await crypto.subtle.deriveBits(
            { name: "PBKDF2", hash: "SHA-256", salt: unbase64(salt), iterations },
            key,
            256,
          ),
        );
        const final = `c=biws,r=${serverNonce}`;
        const auth = `${first},${serverFirst},${final}`;
        const clientKey = await hmac(salted, "Client Key");
        const clientSignature = await hmac(await digest(clientKey), auth);
        const proof = Uint8Array.from(
          clientKey,
          (value, index) => value ^ (clientSignature[index] ?? 0),
        );
        expectedSignature = base64(await hmac(await hmac(salted, "Server Key"), auth));
        await this.message("p", text.encode(`${final},p=${base64(proof)}`));
      } else if (method === 12) {
        check(
          expectedSignature !== "" &&
            attributes(utf8.decode(body.subarray(4))).get("v") === expectedSignature,
          "SCRAM server signature did not match",
        );
        signatureVerified = true;
      } else {
        throw new Error("PostgreSQL requires unsupported fixture authentication");
      }
    }
  }

  async query(sql: string): Promise<(string | null)[][]> {
    await this.message("Q", text.encode(sql + "\0"));
    const rows: (string | null)[][] = [];
    for (;;) {
      const { kind, body } = await this.receive();
      if (kind === "Z") return rows;
      if (kind !== "D") continue;
      const view = new DataView(body.buffer, body.byteOffset, body.byteLength);
      const columns = view.getUint16(0);
      check(columns <= 32 && rows.length < 128, "PostgreSQL fixture result exceeds its bound");
      const row: (string | null)[] = [];
      let offset = 2;
      for (let column = 0; column < columns; column++) {
        const length = view.getInt32(offset);
        offset += 4;
        check(length >= -1 && length <= body.byteLength - offset, "invalid PostgreSQL row");
        row.push(length === -1 ? null : utf8.decode(body.subarray(offset, offset + length)));
        if (length !== -1) offset += length;
      }
      check(offset === body.byteLength, "PostgreSQL row has trailing bytes");
      rows.push(row);
    }
  }

  close(): Promise<void> {
    return this.wire.close();
  }
}

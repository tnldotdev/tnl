import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import {
  createTnl,
  type TnlApplicationCredential,
  type TnlApplicationResource,
  type TnlInstance,
  type TnlHTTPConnection,
  type TnlClientFactory,
} from "@tnldotdev/tnl/web";
import { createTnl as createNativeTnl } from "@tnldotdev/tnl";

const [file, resource, origin, mode] = process.argv.slice(2);
if (
  file === undefined ||
  resource === undefined ||
  origin === undefined ||
  !resource.startsWith("url_") ||
  !["ready", "denied"].includes(mode ?? "")
)
  throw new Error("select credential file, exact URL ID, expected origin and authority state");
const credential: unknown = JSON.parse(await readFile(file, "utf8"));

const constructors: readonly ((options: {
  credential: TnlApplicationCredential;
}) => TnlInstance<TnlApplicationResource>)[] = [createTnl, createNativeTnl];
for (const create of constructors) {
  // @ts-expect-error the public runtime, not a fixture-only parser, validates this external document.
  const app = create({ credential });
  try {
    if (mode === "denied") {
      await assert.rejects(async () => app.connect(resource as `url_${string}`), {
        code: "sdk.credential_denied",
      });
    } else {
      const get: TnlClientFactory<TnlHTTPConnection> = app.client<TnlHTTPConnection>(
        resource as `url_${string}`,
        {
          create: (settings) => settings,
          close: async () => {},
        },
      );
      const connection: TnlHTTPConnection = await get();
      assert.equal(connection.url, origin);
      assert.equal(typeof connection.fetch, "function");
      assert.equal(await get(), connection);
      await assert.rejects(async () => app.connect(`url_${"X".repeat(22)}`), {
        code: "sdk.credential_denied",
      });
    }
  } finally {
    await app.close();
  }
}

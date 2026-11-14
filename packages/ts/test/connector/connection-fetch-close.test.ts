import { expect, test, vi } from "vitest";
import { managedFetch } from "../../src/internal/connector/connection.js";
import { parseConnectionSnapshot } from "../../src/internal/connector/snapshot.js";

const loading = vi.hoisted(() => ({
  started: Promise.withResolvers<void>(),
  resume: Promise.withResolvers<void>(),
  pool: vi.fn(),
  fetch: vi.fn(),
}));
vi.mock("undici/index.js", async () => {
  loading.started.resolve();
  await loading.resume.promise;
  return {
    Pool: loading.pool,
    buildConnector: vi.fn(),
    fetch: loading.fetch,
  };
});

test("close during the first transport import cannot create or dispatch a late pool", async () => {
  const fetch = managedFetch("https://api.tnl.invalid", async () =>
    parseConnectionSnapshot({
      schema: 1,
      protocol: "http",
      host: "127.0.0.1",
      port: 8443,
      url: "https://api.tnl.invalid",
      expires_at: new Date(Date.now() + 60_000).toISOString(),
      transport_id: "ctg_aaaaaaaaaaaaaaaaaaaaaa",
      ssl: { servername: "api.tnl.invalid", rejectUnauthorized: true },
    }),
  );
  const cancel = vi.fn();
  const pending = fetch("/upload", {
    method: "POST",
    body: new ReadableStream<Uint8Array>({ cancel }),
  });
  const rejected = expect(pending).rejects.toMatchObject({ code: "sdk.client_closed" });
  try {
    await loading.started.promise;
    await fetch.close();
  } finally {
    loading.resume.resolve();
  }
  await rejected;
  expect(loading.pool).not.toHaveBeenCalled();
  expect(loading.fetch).not.toHaveBeenCalled();
  expect(cancel).toHaveBeenCalledOnce();
  await fetch.close();
});

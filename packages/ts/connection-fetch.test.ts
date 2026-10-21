import { createServer } from "node:https";
import { createSecureContext } from "node:tls";
import { expect, test, vi } from "vitest";
import { managedFetch, parseConnection } from "./src/internal/connection.js";

test.each(["failed", "cancelled", "uncooperative"])(
  "upload ownership ends when preparation is %s",
  async (mode) => {
    const cancel = vi.fn();
    const upload = new ReadableStream<Uint8Array>({ cancel });
    const controller = new AbortController();
    const reason = new Error("preparation stopped");
    const fetch = managedFetch("https://api.tnl.invalid", async (signal) => {
      if (mode === "failed") throw reason;
      if (mode === "uncooperative") {
        queueMicrotask(() => controller.abort(reason));
        return new Promise<never>(() => {});
      }
      controller.abort(reason);
      signal?.throwIfAborted();
      throw reason;
    });
    await expect(
      fetch("/upload", { method: "POST", body: upload, signal: controller.signal }),
    ).rejects.toBe(reason);
    expect(cancel).toHaveBeenCalledOnce();
  },
);

// public, self-signed test material, used only by this loopback fixture.
const key = `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg38XI2n6ek76hHFMs
GeDTPzwK3T8Gw0P5SgVUt8jfrF+hRANCAASekR2HaAKCU23j/BdXhQo4hup1vA0R
oB4CWD3Ol+60Lyy8hR4NzTAqS1NsBSymmmkNMVldHlkw1JWN+wV3tAqB
-----END PRIVATE KEY-----`;
const cert = `-----BEGIN CERTIFICATE-----
MIIBpjCCAU2gAwIBAgIUYQx8GwbGw/9Rv86i11LkgMDXam4wCgYIKoZIzj0EAwIw
GjEYMBYGA1UEAwwPYXBpLnRubC5pbnZhbGlkMCAXDTI2MTAyMTAxNDc0M1oYDzIx
MjYwOTI3MDE0NzQzWjAaMRgwFgYDVQQDDA9hcGkudG5sLmludmFsaWQwWTATBgcq
hkjOPQIBBggqhkjOPQMBBwNCAASekR2HaAKCU23j/BdXhQo4hup1vA0RoB4CWD3O
l+60Lyy8hR4NzTAqS1NsBSymmmkNMVldHlkw1JWN+wV3tAqBo28wbTAdBgNVHQ4E
FgQUPhqn8uDz8+ZrpbDm75xHj7UL1M0wHwYDVR0jBBgwFoAUPhqn8uDz8+ZrpbDm
75xHj7UL1M0wDwYDVR0TAQH/BAUwAwEB/zAaBgNVHREEEzARgg9hcGkudG5sLmlu
dmFsaWQwCgYIKoZIzj0EAwIDRwAwRAIgM/qab/WbniJ4oxQ8qLR3qGHdGVcjstFt
ADmHF4YmHasCIDcHidjHix7QJVQA1k64xv1vRY5j3bsMEB4GydHwvXuc
-----END CERTIFICATE-----`;

test("HTTP keeps the managed origin, Host and SNI while dialing verified loopback TLS", async () => {
  const origin = "https://api.tnl.invalid:8443";
  const sni: string[] = [];
  const visits: { host: string | undefined; authorization: string | undefined }[] = [];
  const server = createServer(
    {
      key,
      cert,
      SNICallback(name, callback) {
        sni.push(name);
        callback(null, createSecureContext({ key, cert }));
      },
    },
    (request, response) => {
      visits.push({ host: request.headers.host, authorization: request.headers.authorization });
      if (request.url === "/redirect") {
        response.writeHead(302, { Location: "https://outside.tnl.invalid/" }).end();
      } else if (request.url === "/body-hang") {
        response.writeHead(200).write("partial");
      } else {
        const chunks: Buffer[] = [];
        request.on("data", (chunk: Buffer) => chunks.push(chunk));
        request.on("end", () => response.writeHead(201).end(Buffer.concat(chunks)));
      }
    },
  );
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  try {
    const address = server.address();
    if (address === null || typeof address === "string")
      throw new Error("missing fixture listener");
    const value = {
      schema: 1,
      protocol: "http",
      host: "127.0.0.1",
      port: address.port,
      url: origin,
      expires_at: new Date(Date.now() + 60_000).toISOString(),
      transport_id: "ctg_aaaaaaaaaaaaaaaaaaaaaa",
      ssl: { servername: "api.tnl.invalid", rejectUnauthorized: true, ca: cert },
    };
    const fetch = managedFetch(origin, async () => parseConnection(value));
    const response = await fetch(
      new Request(`${origin}/echo`, {
        method: "POST",
        body: "application-body",
        headers: { Host: "ignored.tnl.invalid", Authorization: "Bearer application-owned" },
      }),
    );
    expect(response.status).toBe(201);
    expect(response.url).toBe(`${origin}/echo`);
    const cloned = response.clone();
    expect(cloned.url).toBe(response.url);
    expect(await cloned.text()).toBe("application-body");
    expect(await response.text()).toBe("application-body");
    expect(visits).toEqual([
      { host: "api.tnl.invalid:8443", authorization: "Bearer application-owned" },
    ]);
    expect(sni).toEqual(["api.tnl.invalid"]);

    await expect(fetch("https://outside.tnl.invalid/")).rejects.toMatchObject({
      code: "sdk.configuration_invalid",
    });
    const redirect = await fetch("/redirect", { redirect: "follow" });
    expect(redirect.status).toBe(302);
    expect(redirect.headers.get("location")).toBe("https://outside.tnl.invalid/");
    await redirect.body?.cancel();
    expect(visits).toHaveLength(2);
    const untrusted = managedFetch(origin, async () =>
      parseConnection({
        ...value,
        ssl: { servername: "api.tnl.invalid", rejectUnauthorized: true },
      }),
    );
    await expect(untrusted("/")).rejects.toThrow();
    expect(visits).toHaveLength(2);

    const upload = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(new TextEncoder().encode("streamed-"));
        controller.enqueue(new TextEncoder().encode("upload"));
        controller.close();
      },
    });
    const uploaded = await fetch("/echo", {
      method: "POST",
      body: upload,
      headers: { Authorization: "Bearer application-owned" },
    });
    expect(await uploaded.text()).toBe("streamed-upload");
    const connections = sni.length;
    for (let i = 0; i < 6; i++) {
      const pooled = await fetch("/echo", { method: "POST", body: "pooled" });
      expect(await pooled.text()).toBe("pooled");
    }
    expect(sni.length).toBeLessThanOrEqual(connections + 1);

    const abort = new AbortController();
    const streaming = await fetch("/body-hang", { signal: abort.signal });
    const body = streaming.text();
    abort.abort();
    await expect(body).rejects.toMatchObject({ name: "AbortError" });
  } finally {
    const closed = new Promise<void>((resolve, reject) =>
      server.close((error) => (error ? reject(error) : resolve())),
    );
    server.closeAllConnections();
    await closed;
  }
});

test("streamed response bodies can outlive 30 seconds without an SDK total abort", async () => {
  const server = createServer({ key, cert }, (_request, response) => {
    response.writeHead(200).write("start\n");
    const heartbeat = setInterval(() => response.write("tick\n"), 100);
    const finish = setTimeout(() => response.end("done\n"), 31_000);
    response.once("close", () => {
      clearInterval(heartbeat);
      clearTimeout(finish);
    });
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  try {
    const address = server.address();
    if (address === null || typeof address === "string") throw new Error("missing listener");
    const origin = "https://api.tnl.invalid:8443";
    const fetch = managedFetch(origin, async () =>
      parseConnection({
        schema: 1,
        protocol: "http",
        host: "127.0.0.1",
        port: address.port,
        url: origin,
        expires_at: new Date(Date.now() + 3600_000).toISOString(),
        transport_id: "ctg_aaaaaaaaaaaaaaaaaaaaaa",
        ssl: { servername: "api.tnl.invalid", rejectUnauthorized: true, ca: cert },
      }),
    );
    const response = await fetch("/stream");
    expect((await response.text()).endsWith("done\n")).toBe(true);
  } finally {
    const closed = new Promise<void>((resolve, reject) =>
      server.close((error) => (error ? reject(error) : resolve())),
    );
    server.closeAllConnections();
    await closed;
  }
}, 40_000);

test("session generation changes replace a same-address pool without replay or transferring an old stream", async () => {
  const sockets = new WeakMap<object, number>();
  let sequence = 0;
  const bodies: string[] = [];
  let finishOld: (() => void) | undefined;
  const server = createServer({ key, cert }, (request, response) => {
    if (request.url === "/old-stream") {
      response.writeHead(200).write("old-start\n");
      finishOld = () => response.end("old-finish\n");
      return;
    }
    const chunks: Buffer[] = [];
    request.on("data", (chunk: Buffer) => chunks.push(chunk));
    request.on("end", () => {
      const body = Buffer.concat(chunks).toString();
      bodies.push(body);
      if (request.url === "/drop") {
        response.destroy();
        return;
      }
      response.end(`${sockets.get(request.socket)}:${body}`);
    });
  });
  server.on("secureConnection", (socket) => sockets.set(socket, ++sequence));
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  try {
    const address = server.address();
    if (address === null || typeof address === "string") throw new Error("missing listener");
    const origin = "https://api.tnl.invalid:8443";
    let generation = "ctg_aaaaaaaaaaaaaaaaaaaaaa";
    const fetch = managedFetch(origin, async () =>
      parseConnection({
        schema: 1,
        protocol: "http",
        host: "127.0.0.1",
        port: address.port,
        url: origin,
        ssl: { servername: "api.tnl.invalid", rejectUnauthorized: true, ca: cert },
        expires_at: new Date(Date.now() + 3600_000).toISOString(),
        transport_id: generation,
      }),
    );
    await (await fetch("/echo", { method: "POST", body: "warm" })).text();
    const old = await fetch("/old-stream");
    const reader = old.body?.getReader();
    if (reader === undefined) throw new Error("missing body");
    expect(new TextDecoder().decode((await reader.read()).value)).toBe("old-start\n");
    const idle = await (await fetch("/echo", { method: "POST", body: "idle" })).text();
    generation = "ctg_bbbbbbbbbbbbbbbbbbbbbb";
    const current = await (await fetch("/echo", { method: "POST", body: "once" })).text();
    expect(current.split(":")[0]).not.toBe(idle.split(":")[0]);
    finishOld?.();
    expect(new TextDecoder().decode((await reader.read()).value)).toBe("old-finish\n");
    expect((await reader.read()).done).toBe(true);
    expect(bodies).toEqual(["warm", "idle", "once"]);
    await expect(fetch("/drop", { method: "POST", body: "drop-once" })).rejects.toThrow();
    expect(bodies).toEqual(["warm", "idle", "once", "drop-once"]);
  } finally {
    server.closeAllConnections();
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
});

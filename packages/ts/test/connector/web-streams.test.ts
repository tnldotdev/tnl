import { createServer } from "node:https";
import { Agent, getGlobalDispatcher, setGlobalDispatcher } from "undici";
import { expect, test } from "vitest";
import { createTnl } from "@tnldotdev/tnl/web";
import { cert, key } from "../fixtures/workload_tls.js";

const credential = `vsh1.shr_${"A".repeat(22)}.${"A".repeat(43)}`;

test("standard Fetch response bodies retain identity and stop with only their HTTP scope", async () => {
  const visits: (string | undefined)[] = [];
  const server = createServer({ key, cert }, (request, response) => {
    visits.push(request.headers["tnl-visitor-token"]?.toString());
    if (request.url === "/stream") response.writeHead(200).write("partial");
    else response.end("complete");
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const original = getGlobalDispatcher();
  const agent = new Agent({ connect: { ca: cert } });
  setGlobalDispatcher(agent);
  const first = createTnl({ credential });
  const sibling = createTnl({ credential });
  try {
    const address = server.address();
    if (address === null || typeof address === "string") throw new Error("missing listener");
    const origin = `https://localhost:${address.port}` as const;
    const api = first.connect(origin);
    const complete = await api.fetch("/complete");
    expect(complete.url).toBe(`${origin}/complete`);
    expect(await complete.clone().text()).toBe("complete");
    expect(await complete.text()).toBe("complete");

    const response = await api.fetch("/stream");
    const body = response.text().catch((cause: unknown) => cause);
    await first.close();
    expect(await body).toBeInstanceOf(Error);
    expect(await (await sibling.connect(origin).fetch("/complete")).text()).toBe("complete");
    expect(visits).toEqual([credential, credential, credential]);
  } finally {
    await Promise.all([first.close(), sibling.close()]);
    setGlobalDispatcher(original);
    await agent.destroy();
    server.closeAllConnections();
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
});

test("failed client cleanup retains a live response until cleanup is retried", async () => {
  let disconnected = false;
  const server = createServer({ key, cert }, (_request, response) => {
    response.writeHead(200).write("partial");
    response.once("close", () => {
      disconnected = true;
    });
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const original = getGlobalDispatcher();
  const agent = new Agent({ connect: { ca: cert } });
  setGlobalDispatcher(agent);
  const app = createTnl({ credential });
  let fail = true;
  try {
    const address = server.address();
    if (address === null || typeof address === "string") throw new Error("missing listener");
    const api = app.connect(`https://localhost:${address.port}`);
    const get = app.client(api.url, {
      create: () => ({}),
      close: () => {
        if (fail) throw new Error("client drain failed");
      },
    });
    await get();
    const response = await api.fetch("/stream");
    const body = response.text().catch((cause: unknown) => cause);
    await expect(app.close()).rejects.toBeInstanceOf(AggregateError);
    expect(disconnected).toBe(false);
    await expect(api.fetch("/")).rejects.toHaveProperty("code", "sdk.client_closed");
    fail = false;
    await app.close();
    expect(await body).toBeInstanceOf(Error);
  } finally {
    fail = false;
    await app.close();
    setGlobalDispatcher(original);
    await agent.destroy();
    server.closeAllConnections();
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
});

import { expect, test, vi } from "vitest";
import { clientFactory } from "../../src/internal/connector/client_factory.js";

test("an owner fence rejects late client delivery without starting cleanup ahead of publication drain", async () => {
  let active = true;
  const gate = Promise.withResolvers<void>();
  const entered = Promise.withResolvers<void>();
  const client = {};
  const close = vi.fn();
  const get = clientFactory(
    async () => ({ key: "binding", connection: {} }),
    {
      async create() {
        entered.resolve();
        await gate.promise;
        return client;
      },
      close,
    },
    () => active,
  );
  const waiting = get().catch((cause: unknown) => cause);
  await entered.promise;
  active = false;
  gate.resolve();
  expect(await waiting).toHaveProperty("code", "sdk.client_closed");
  expect(close).not.toHaveBeenCalled();
  await get.close();
  expect(close).toHaveBeenCalledExactlyOnceWith(client);
});

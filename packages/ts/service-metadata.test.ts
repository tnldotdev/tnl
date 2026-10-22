import { expect, test } from "vitest";
import { serviceMetadata } from "./src/internal/service_metadata.js";

test("optional metadata and serialization do not invent a preparation error", async () => {
  const services = serviceMetadata({ namespace: "team.example", dev: false, services: {} });
  expect(services.worker?.hostname).toBeUndefined();
  expect(Reflect.get(services, "toJSON")).toBeUndefined();
  expect(JSON.stringify(services)).toBe("{}");
  await expect(Promise.resolve(services)).resolves.toBe(services);
});

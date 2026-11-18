import { expect, test } from "vitest";
import {
  resolveServiceCertificate,
  serviceCertificateSourceSchema,
} from "../../src/internal/publication_certificate.js";

test("supplied certificate providers receive cancellation and return bounded private material", async () => {
  const controller = new AbortController();
  const first = { certificatePEM: "certificate-one", privateKeyPEM: "private-one" };
  const second = { certificatePEM: "certificate-two", privateKeyPEM: "private-two" };
  let selected = first;
  const provider = (signal: AbortSignal) => {
    expect(signal).toBe(controller.signal);
    return selected;
  };
  expect(serviceCertificateSourceSchema.safeParse(provider).success).toBe(true);
  const initial = await resolveServiceCertificate(provider, controller.signal);
  expect(initial).toEqual(first);
  expect(Object.isFrozen(initial)).toBe(true);
  selected = second;
  expect(await resolveServiceCertificate(provider, controller.signal)).toEqual(second);
  controller.abort();
  await expect(resolveServiceCertificate(provider, controller.signal)).rejects.toMatchObject({
    name: "AbortError",
  });
});

test("provider failures and invalid material never expose PEM through parser diagnostics", async () => {
  const signal = new AbortController().signal;
  const secret = "PRIVATE KEY MATERIAL";
  const provider = () => {
    throw new Error(secret);
  };
  await expect(resolveServiceCertificate(provider, signal)).rejects.toMatchObject({
    code: "sdk.configuration_invalid",
    message: expect.not.stringContaining(secret),
  });
  await expect(
    resolveServiceCertificate(
      {
        certificatePEM: "certificate",
        privateKeyPEM: secret.repeat(16384),
      },
      signal,
    ),
  ).rejects.toMatchObject({
    code: "sdk.configuration_invalid",
    message: expect.not.stringContaining(secret),
  });
});

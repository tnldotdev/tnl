import * as z from "zod";
import { TnlError } from "../errors.js";

export interface ServiceCertificate {
  readonly certificatePEM: string;
  readonly privateKeyPEM: string;
}

/** polled during publication; honor the signal and return replacement material before expiry. */
export type ServiceCertificateSource =
  | ServiceCertificate
  | ((signal: AbortSignal) => ServiceCertificate | Promise<ServiceCertificate>);

export const serviceCertificateSchema = z
  .strictObject({
    certificatePEM: z.string().min(1).max(131072),
    privateKeyPEM: z.string().min(1).max(16384),
  })
  .readonly();

export interface ExportedCertificate {
  readonly certificate: ServiceCertificate;
  /** the installed certificate's validity deadline in Unix milliseconds. */
  readonly expiresAt: number;
}

export const exportedCertificateSchema = z
  .strictObject({
    certificate: serviceCertificateSchema,
    expiresAt: z.int().positive(),
  })
  .readonly();

export const serviceCertificateSourceSchema = z.union([
  serviceCertificateSchema,
  z.custom<Exclude<ServiceCertificateSource, ServiceCertificate>>(
    (value) => typeof value === "function",
  ),
]);

export async function resolveServiceCertificate(
  source: ServiceCertificateSource,
  signal: AbortSignal,
): Promise<ServiceCertificate> {
  try {
    signal.throwIfAborted();
    const result = serviceCertificateSchema.parse(
      typeof source === "function" ? await source(signal) : source,
    );
    signal.throwIfAborted();
    return Object.freeze(result);
  } catch {
    if (signal.aborted) throw new DOMException("publication canceled", "AbortError");
    // provider exceptions and parser diagnostics may contain private key bytes.
    throw new TnlError("sdk.certificate_invalid");
  }
}

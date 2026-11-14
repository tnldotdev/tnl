import * as z from "zod";

export const serviceNameSchema = z.string().regex(/^[a-z](?:[a-z0-9-]{0,30}[a-z0-9])?$/);
export function isServiceName(value: unknown): value is string {
  return serviceNameSchema.safeParse(value).success;
}
export const protocolSchema = z.enum(["http", "postgres", "mysql", "tcp", "kubernetes"]);
export const portSchema = z.int().min(1).max(65535);
export const pathTextSchema = z
  .string()
  .min(1)
  .max(4096)
  .refine((value) => !value.includes("\0"));
export const digestSchema = z.string().regex(/^[0-9a-f]{64}$/);
export const timestampSchema = z.string().refine((value) => Number.isFinite(Date.parse(value)));
export const deadlineSchema = timestampSchema
  .transform(Date.parse)
  .refine((value) => value > Date.now());

export const hostnameSchema = z
  .string()
  .min(1)
  .max(253)
  .refine((value) => {
    const labels = value.split(".");
    if (labels.some((label) => !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label))) return false;
    if (
      labels.length === 4 &&
      labels.every((label) => /^[0-9]+$/.test(label) && Number(label) <= 255)
    )
      return false;
    return labels.every((label) => {
      if (!label.startsWith("xn--")) return true;
      const url = URL.parse(`https://${label}.example`);
      return url?.hostname === `${label}.example`;
    });
  });

export const httpsOriginSchema = z.templateLiteral(["https://", z.string()]).refine((value) => {
  const url = URL.parse(value);
  return url !== null && url.origin === value && url.username === "" && url.password === "";
});

export const publicHTTPOriginSchema = httpsOriginSchema.refine((value) => {
  const url = URL.parse(value);
  return (
    url !== null &&
    hostnameSchema.safeParse(url.hostname).success &&
    (url.port === "" || (Number(url.port) >= 1024 && Number(url.port) <= 65535))
  );
});

export const serviceIDSchema = z
  .templateLiteral(["svc_", z.string().regex(/^[A-Za-z0-9]{22}$/)])
  .brand<"ServiceID">();
export const workloadSessionIDSchema = z
  .templateLiteral(["wls_", z.string().regex(/^[A-Za-z0-9]{22}$/)])
  .brand<"WorkloadSessionID">();
export const transportIDSchema = z
  .templateLiteral(["ctg_", z.string().regex(/^[A-Za-z0-9]{22}$/)])
  .brand<"TransportID">();
export const registrationIDSchema = z
  .templateLiteral(["reg_", z.string().regex(/^[a-f0-9]{32}$/)])
  .brand<"RegistrationID">();
export const invocationIDSchema = z
  .templateLiteral(["ivk_", z.string().regex(/^[A-Za-z0-9]{22}$/)])
  .brand<"InvocationID">();

export type ServiceID = z.output<typeof serviceIDSchema>;
export type WorkloadSessionID = z.output<typeof workloadSessionIDSchema>;
export type TransportID = z.output<typeof transportIDSchema>;
export type RegistrationID = z.output<typeof registrationIDSchema>;
export type InvocationID = z.output<typeof invocationIDSchema>;

/** one server-side signing identity, prepared by `tnl auth register`. */
export type TnlApplicationCredential = Readonly<{
  version: 1;
  control_url: `https://${string}`;
  client_id: string;
  key_id: string;
  team_id: string;
  private_key: string;
  grants: readonly TnlApplicationGrant[];
}>;

export type TnlApplicationGrant = Readonly<
  { id: string; expires_at?: string | undefined } & (
    | { operation: "visit" | "publish"; kind: "saved_public_url"; public_url_id: string }
    | { operation: "visit" | "publish"; kind: "service"; service_id: string }
    | { operation: "allocate"; kind: "namespace"; domain_id: string; namespace: string }
  )
>;

export type TnlApplicationResource = `url_${string}` | `svc_${string}`;

/** one approved workload; provider acquisition stays inside runtime startup. */
export type TnlWorkloadCredential = Readonly<
  { workload: string } & (
    | { token?: never; tokenFile?: never }
    | { token: () => Promise<string>; tokenFile?: never }
    | { tokenFile: string; token?: never }
  )
>;

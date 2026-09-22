// Target only the transport under experiment; control, DNS, and resource
// collection keep their ordinary paths. Each returned endpoint owns its qdisc.
export type ImpairmentScenario = "latency" | "packet-loss";
export type NetworkPath = "forwarding" | "publisher";
export type RuntimeService = "ingress" | "publishers" | "relay-a" | "relay-b";

export interface ImpairmentEndpoint {
  readonly filters: string[][];
  readonly service: RuntimeService;
}

export function impairmentEndpoints(
  path: string | undefined,
  addresses: Readonly<Record<RuntimeService, string>>,
): [ImpairmentEndpoint, ...ImpairmentEndpoint[]] {
  if (path !== "forwarding" && path !== "publisher") throw new Error("invalid network path");
  const source = path === "forwarding" ? "ingress" : "publishers";
  const port = path === "forwarding" ? "8443" : "443";
  const protocols = path === "forwarding" ? ["6"] : ["6", "17"];
  const forward: ImpairmentEndpoint = { service: source, filters: [] };
  const endpoints: [ImpairmentEndpoint, ...ImpairmentEndpoint[]] = [forward];
  for (const relay of ["relay-a", "relay-b"] as const) {
    const reverse: ImpairmentEndpoint = { service: relay, filters: [] };
    for (const protocol of protocols) {
      forward.filters.push([
        "match",
        "ip",
        "dst",
        addresses[relay],
        "match",
        "ip",
        "protocol",
        protocol,
        "0xff",
        "match",
        "ip",
        "dport",
        port,
        "0xffff",
      ]);
      reverse.filters.push([
        "match",
        "ip",
        "dst",
        addresses[source],
        "match",
        "ip",
        "protocol",
        protocol,
        "0xff",
        "match",
        "ip",
        "sport",
        port,
        "0xffff",
      ]);
    }
    endpoints.push(reverse);
  }
  return endpoints;
}

export function netemOptions(
  scenario: ImpairmentScenario,
  rtt: string | undefined,
  loss: string | undefined,
  seed: string | undefined,
): string[] {
  let options: string[];
  if (scenario === "latency") {
    if (rtt !== "20ms" && rtt !== "50ms" && rtt !== "100ms")
      throw new Error("RTT must be 20ms, 50ms, or 100ms");
    options = ["delay", `${Number.parseInt(rtt, 10) / 2}ms`];
  } else if (scenario === "packet-loss") {
    if (![0.1, 1].includes(Number(loss))) throw new Error("LOSS must be 0.1 or 1 percent");
    options = ["loss", "random", `${loss}%`];
  } else throw new Error("invalid impairment scenario");
  if (!Number.isSafeInteger(Number(seed)) || Number(seed) < 0 || Number(seed) > 0xffffffff)
    throw new Error("invalid netem seed");
  if (Number(seed) !== 0) options.push("seed", String(seed));
  return options;
}

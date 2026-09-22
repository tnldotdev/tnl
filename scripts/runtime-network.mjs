// Target only the transport under experiment; control, DNS, and resource
// collection keep their ordinary paths. Each returned endpoint owns its qdisc.
export function impairmentEndpoints(path, addresses) {
  if (!["forwarding", "publisher"].includes(path)) throw new Error("invalid network path");
  const source = path === "forwarding" ? "ingress" : "publishers";
  const port = path === "forwarding" ? "8443" : "443";
  const protocols = path === "forwarding" ? ["6"] : ["6", "17"];
  const endpoints = [{ service: source, filters: [] }];
  for (const relay of ["relay-a", "relay-b"]) {
    const reverse = { service: relay, filters: [] };
    for (const protocol of protocols) {
      endpoints[0].filters.push([
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

export function netemOptions(scenario, rtt, loss, seed) {
  let options;
  if (scenario === "latency") {
    if (!["20ms", "50ms", "100ms"].includes(rtt))
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

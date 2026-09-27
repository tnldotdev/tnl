import { readFile, writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { z } from "zod";

const root = new URL("../docs/benchmarks/", import.meta.url);
const dataURL = new URL("data/local-capacity.json", root);
const number = z.number().finite().nonnegative();
const measuredRun = { run: z.string().min(1) };
const dataSchema = z.object({
  bandwidth: z.array(
    z.object({ ...measuredRun, target_mbps: number, elapsed_seconds: number, passed: z.boolean() }),
  ),
  publisher_cpu: z.array(
    z.object({
      ...measuredRun,
      public_urls: number,
      cpus: number,
      p95_ms: number,
      offered: number,
      successful: number,
    }),
  ),
  combined: z.array(
    z.object({
      ...measuredRun,
      public_urls: number,
      p95_ms: number,
      offered: number,
      successful: number,
      missed: number,
      publisher_connection_limit: number,
    }),
  ),
  relay_cpu: z.array(
    z.object({
      ...measuredRun,
      cpus: number,
      p95_ms: number,
      offered: number,
      successful: number,
      missed: number,
    }),
  ),
});

const data = dataSchema.parse(JSON.parse(await readFile(dataURL, "utf8")) as unknown);
for (const row of [...data.publisher_cpu, ...data.combined, ...data.relay_cpu]) {
  if (row.successful > row.offered) throw new Error(`Invalid counts: ${row.run}`);
}

const blue = "#185abc";
const orange = "#b84b16";
const gray = "#485665";
const svg = (title: string, description: string, body: string) =>
  `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 660 310" role="img" aria-labelledby="title description">\n<title id="title">${title}</title><desc id="description">${description}</desc>\n<rect width="660" height="310" fill="#fff"/><g font-family="system-ui, sans-serif" fill="#1d2730">${body}</g></svg>\n`;
const text = (
  x: number,
  y: number,
  label: string,
  size = 13,
  anchor = "middle",
  color = "#1d2730",
) =>
  `<text x="${x}" y="${y}" text-anchor="${anchor}" fill="${color}" font-size="${size}">${label}</text>`;
const circle = (x: number, y: number, color: string) =>
  `<circle cx="${x}" cy="${y}" r="6" fill="${color}" stroke="#fff" stroke-width="2"/>`;
const plot = (maximum: number, ticks: number[], label: string) => {
  const y = (value: number) => 245 - (value / maximum) * 170;
  const lines = ticks
    .map(
      (tick) =>
        `<path d="M80 ${y(tick)}H625" stroke="#d9e1e8"/>${text(70, y(tick) + 4, String(tick), 12, "end", gray)}`,
    )
    .join("");
  return { y, body: `${lines}${text(80, 42, label, 13, "start", gray)}` };
};
const labels = (values: number[]) =>
  values.map((value, index) => {
    const x = 175 + index * (390 / Math.max(1, values.length - 1));
    return { value, x };
  });

const bandwidth = () => {
  const axis = plot(4.5, [0, 1, 2, 3, 4], "Seconds past the 30-second transfer window");
  const groups = labels([2200, 2400, 2600]);
  const marks = data.bandwidth
    .map((row) => {
      const group = groups.find(({ value }) => value === row.target_mbps);
      if (!group) throw new Error(`Unknown bandwidth target: ${row.run}`);
      const repeats = data.bandwidth.filter((item) => item.target_mbps === row.target_mbps);
      const offset = (repeats.indexOf(row) - (repeats.length - 1) / 2) * 20;
      return circle(group.x + offset, axis.y(row.elapsed_seconds - 30), row.passed ? blue : orange);
    })
    .join("");
  const threshold = `<path d="M80 ${axis.y(1)}H625" stroke="${orange}" stroke-dasharray="5 4"/>${text(625, axis.y(1) - 6, "1-second allowance", 12, "end", orange)}`;
  return svg(
    "Bandwidth completion time",
    "Thirty-second bidirectional transfers at 2,200, 2,400, and 2,600 Mbit/sec per direction. Each dot is one run. Blue passed; orange missed the completion deadline.",
    `${axis.body}${threshold}${marks}${groups.map(({ value, x }) => text(x, 270, String(value))).join("")}${text(330, 296, "Target Mbit/sec per direction", 13)}`,
  );
};

const publisherCPU = () => {
  const axis = plot(60, [0, 15, 30, 45, 60], "Successful fresh-request p95 (ms)");
  const groups = labels([1875, 2000]);
  const marks = data.publisher_cpu
    .map((row) => {
      const x = groups.find(({ value }) => value === row.public_urls)?.x;
      if (x === undefined) throw new Error(`Unknown public URL count: ${row.run}`);
      const repeats = data.publisher_cpu.filter(
        (item) => item.public_urls === row.public_urls && item.cpus === row.cpus,
      );
      return circle(
        x + (row.cpus === 2 ? -24 : 24) + (repeats.indexOf(row) - (repeats.length - 1) / 2) * 15,
        axis.y(row.p95_ms),
        row.cpus === 2 ? orange : blue,
      );
    })
    .join("");
  return svg(
    "Publisher generator CPU comparison",
    "Five-minute matched combined runs at 1,875 and 2,000 public URLs. Orange is two generator CPUs; blue is four. Each dot is one run.",
    `${axis.body}${marks}${groups.map(({ value, x }) => text(x, 270, String(value))).join("")}${text(330, 296, "Public URLs · orange: 2 publisher CPUs · blue: 4 publisher CPUs", 13)}`,
  );
};

const combined = () => {
  const axis = plot(2000, [0, 500, 1000, 1500, 2000], "Successful fresh-request p95 (ms)");
  const groups = labels([4000, 4500, 5000]);
  const marks = data.combined
    .map((row) => {
      const x = groups.find(({ value }) => value === row.public_urls)?.x;
      if (x === undefined) throw new Error(`Unknown public URL count: ${row.run}`);
      const repeats = data.combined.filter((item) => item.public_urls === row.public_urls);
      return circle(
        x + (repeats.indexOf(row) - (repeats.length - 1) / 2) * 20,
        axis.y(row.p95_ms),
        row.successful === row.offered ? blue : orange,
      );
    })
    .join("");
  return svg(
    "Combined load results",
    "One-minute combined traffic on a 16 GiB Docker VM. Each dot is a complete run; orange runs missed or failed fresh requests. Offered load and the relay connection ceiling changed with the public URL count.",
    `${axis.body}${marks}${groups.map(({ value, x }) => text(x, 270, String(value))).join("")}${text(330, 296, "Public URLs · blue: all offers succeeded · orange: failed", 13)}`,
  );
};

const charts = [
  ["bandwidth.svg", bandwidth()],
  ["publisher-cpu.svg", publisherCPU()],
  ["combined.svg", combined()],
] as const;

for (const [name, contents] of charts) {
  const path = new URL(`figures/${name}`, root);
  if (process.argv.includes("--check")) {
    if ((await readFile(path, "utf8")) !== contents)
      throw new Error(`Outdated chart: ${fileURLToPath(path)}`);
  } else {
    await writeFile(path, contents);
  }
}

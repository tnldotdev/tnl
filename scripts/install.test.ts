import { execFileSync, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  chmodSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, expect, test } from "vitest";

const script = fileURLToPath(new URL("install.sh", import.meta.url));
const temporary: string[] = [];
const toolPath = (tool: string): string =>
  execFileSync("sh", ["-c", 'command -v "$1"', "--", tool], { encoding: "utf8" }).trim();
const shellQuote = (value: string): string => `'${value.replaceAll("'", "'\\''")}'`;
const release = (tag: string, extra: Record<string, unknown> = {}): Record<string, unknown> => ({
  tag_name: tag,
  draft: false,
  prerelease: tag.includes("-"),
  published_at: "2026-10-01T00:00:00Z",
  ...extra,
});

afterEach(() => {
  for (const path of temporary.splice(0)) rmSync(path, { recursive: true, force: true });
});

function fixture(
  options: {
    os?: string;
    arch?: string;
    checksum?: "sha256sum" | "shasum";
    omit?: string;
    symlink?: string;
  } = {},
) {
  const root = mkdtempSync(join(tmpdir(), "tnl-install-test-"));
  temporary.push(root);
  const tools = join(root, "tools");
  const home = join(root, "home");
  const downloads = join(root, "downloads");
  const scratch = join(root, "tmp");
  const files = join(root, "files");
  for (const dir of [tools, home, downloads, scratch, files]) mkdirSync(dir);
  for (const name of ["awk", "tar", "mktemp", "mkdir", "cp", "mv", "chmod", "rm"])
    symlinkSync(toolPath(name), join(tools, name));
  const mock = (name: string, contents: string) => {
    writeFileSync(join(tools, name), `#!/bin/sh\n${contents}\n`);
    chmodSync(join(tools, name), 0o755);
  };
  mock(
    "uname",
    'case "$1" in -s) printf "%s\\n" "$MOCK_OS";; -m) printf "%s\\n" "$MOCK_ARCH";; esac',
  );
  const hasher = options.checksum ?? "shasum";
  mock(
    hasher,
    `exec ${shellQuote(toolPath("shasum"))} ${hasher === "sha256sum" ? "-a 256" : ""} "$@"`,
  );
  mock(
    "curl",
    `
output=
write_status=
url=
while [ "$#" -gt 0 ]; do
  case "$1" in
    --output) output=$2; shift ;;
    --write-out) write_status=1; shift ;;
    https://*) url=$1 ;;
  esac
  shift
done
printf '%s\\n' "$url" >> "$MOCK_DOWNLOADS/requests"
if [ -f "$MOCK_DOWNLOADS/network-failure" ]; then
  printf 'provider error includes secret-value\\n' >&2
  exit 7
fi
case "$url" in
  */releases/latest)
    cp "$MOCK_DOWNLOADS/stable.json" "$output"
    [ -z "$write_status" ] || { IFS= read -r status < "$MOCK_DOWNLOADS/status"; printf '%s' "$status"; }
    ;;
  */releases?per_page=100) cp "$MOCK_DOWNLOADS/candidates.json" "$output" ;;
  */checksums.txt)
    [ ! -f "$MOCK_DOWNLOADS/checksum-failure" ] || exit 22
    cp "$MOCK_DOWNLOADS/checksums.txt" "$output"
    ;;
  *.tar.gz) cp "$MOCK_DOWNLOADS/archive.tar.gz" "$output" ;;
  *) exit 22 ;;
esac
`,
  );
  writeFileSync(join(downloads, "status"), "200\n");
  writeFileSync(join(downloads, "stable.json"), JSON.stringify(release("v1.2.3")));
  writeFileSync(join(downloads, "candidates.json"), JSON.stringify([release("v0.1.0-rc.40")]));
  const entries = ["tnl", "LICENSE", "NOTICE", "THIRD_PARTY_LICENSES.txt"].filter(
    (name) => name !== options.omit,
  );
  for (const name of entries) {
    if (name === options.symlink) symlinkSync("missing-file", join(files, name));
    else
      writeFileSync(
        join(files, name),
        name === "tnl" ? "#!/bin/sh\nprintf 'fixture version\\n'\n" : `${name} fixture\n`,
      );
  }
  execFileSync("tar", ["-czf", join(downloads, "archive.tar.gz"), "-C", files, ...entries]);
  const manifest = (version = "1.2.3", content?: string) => {
    const digest = createHash("sha256")
      .update(readFileSync(join(downloads, "archive.tar.gz")))
      .digest("hex");
    const rows = ["darwin", "linux"].flatMap((os) =>
      ["amd64", "arm64"].map((arch) => `${digest}  tnl_${version}_${os}_${arch}.tar.gz`),
    );
    writeFileSync(join(downloads, "checksums.txt"), content ?? `${rows.join("\n")}\n`);
    return rows;
  };
  manifest();
  const run = (environment: Record<string, string> = {}, source = readFileSync(script, "utf8")) => {
    const result = spawnSync("/bin/sh", [], {
      input: source,
      encoding: "utf8",
      env: {
        NODE_ENV: "test",
        PATH: tools,
        HOME: home,
        TMPDIR: scratch,
        MOCK_DOWNLOADS: downloads,
        MOCK_OS: options.os ?? "Darwin",
        MOCK_ARCH: options.arch ?? "arm64",
        ...environment,
      },
    });
    if (result.error) throw result.error;
    return result;
  };
  return {
    root,
    tools,
    home,
    downloads,
    scratch,
    manifest,
    run,
    binary: join(home, ".local/bin/tnl"),
  };
}

function assertFrames(output: string) {
  for (const frame of output.trim().split(/\n\n+/)) {
    const lines = frame.split("\n");
    const width = lines[0]?.length;
    expect(width).toBeLessThanOrEqual(72);
    expect(lines[0]).toMatch(/^\+--\[ tnl install \]-- /);
    for (const [index, line] of lines.entries()) {
      expect(line.length).toBe(width);
      expect(line).toMatch(/^[\x20-\x7e]+$/);
      expect(line.endsWith(index === 0 || index === lines.length - 1 ? "+" : "|")).toBe(true);
    }
  }
}

test.each([
  ["Darwin", "x86_64", "darwin", "amd64", "shasum"],
  ["Darwin", "arm64", "darwin", "arm64", "sha256sum"],
  ["Linux", "amd64", "linux", "amd64", "shasum"],
  ["Linux", "aarch64", "linux", "arm64", "sha256sum"],
] as const)("installs on %s/%s using %s/%s", (os, arch, expectedOS, expectedArch, checksum) => {
  const f = fixture({ os, arch, checksum });
  const result = f.run();
  expect(result.status, result.stderr).toBe(0);
  expect(result.stdout).toContain("installed");
  expect(result.stdout).toContain("PATH=");
  expect(result.stderr).toContain("downloading");
  expect(result.stderr).toContain("verifying");
  assertFrames(result.stdout);
  assertFrames(result.stderr);
  expect(readFileSync(join(f.downloads, "requests"), "utf8")).toContain(
    `tnl_1.2.3_${expectedOS}_${expectedArch}.tar.gz`,
  );
  expect(execFileSync(f.binary, ["version"], { encoding: "utf8" })).toBe("fixture version\n");
  expect(readdirSync(join(f.home, ".local/bin/tnl-notices"))).toEqual([
    "LICENSE",
    "NOTICE",
    "THIRD_PARTY_LICENSES.txt",
  ]);
  expect(readdirSync(f.scratch)).toEqual([]);
  expect(readdirSync(join(f.home, ".local/bin"))).toEqual(["tnl", "tnl-notices"]);
});

test("falls back only when stable is absent and selects the newest published candidate", () => {
  const f = fixture();
  writeFileSync(join(f.downloads, "status"), "404\n");
  writeFileSync(
    join(f.downloads, "candidates.json"),
    JSON.stringify([
      release("v0.1.0-rc.41", { draft: true, published_at: null }),
      release("v0.1.0-rc.39", { published_at: "2026-09-01T00:00:00Z" }),
      release("v0.1.0-rc.40", { body: '"tag_name":"v9.9.9"', assets: [{ tag_name: "v9.9.9" }] }),
      release("v0.1.0-beta.99"),
    ]),
  );
  f.manifest("0.1.0-rc.40");
  const result = f.run();
  expect(result.status, result.stderr).toBe(0);
  expect(result.stdout).toContain("0.1.0-rc.40");
  expect(readFileSync(join(f.downloads, "requests"), "utf8")).toContain("/releases?per_page=100");
});

test("an exact version skips metadata and supports custom paths and replacement", () => {
  const f = fixture();
  const dir = join(f.root, "bin '$HOME");
  mkdirSync(dir);
  writeFileSync(join(dir, "tnl"), "old binary");
  f.manifest("0.1.0-rc.40");
  const result = f.run({ TNL_VERSION: "v0.1.0-rc.40", TNL_INSTALL: dir });
  expect(result.status, result.stderr).toBe(0);
  expect(readFileSync(join(f.downloads, "requests"), "utf8")).not.toContain("api.github.com");
  expect(readFileSync(join(dir, "tnl"), "utf8")).not.toBe("old binary");
  expect(result.stdout).toContain("'\\''$HOME'");
  assertFrames(result.stdout);
  const second = f.run({ TNL_VERSION: "0.1.0-rc.40", TNL_INSTALL: dir, PATH: `${f.tools}:${dir}` });
  expect(second.status).toBe(0);
  expect(second.stdout).not.toContain("PATH=");
});

test.each(["403", "429", "500"])("does not fall back after GitHub HTTP %s", (status) => {
  const f = fixture();
  writeFileSync(join(f.downloads, "status"), `${status}\n`);
  const result = f.run();
  expect(result.status).toBe(1);
  expect(result.stdout).toBe("");
  expect(result.stderr).toContain("could not select a release");
  expect(readFileSync(join(f.downloads, "requests"), "utf8")).not.toContain("per_page");
  assertFrames(result.stderr);
});

test.each([
  "not json",
  '{"tag_name":"v1.2.3"}',
  JSON.stringify(release("v../../bad")),
  JSON.stringify(release("v1.2.3", { draft: true })),
  `${JSON.stringify(release("v1.2.3"))} trailing`,
])("rejects invalid release metadata: %s", (metadata) => {
  const f = fixture();
  writeFileSync(join(f.downloads, "stable.json"), metadata);
  const result = f.run();
  expect(result.status).toBe(1);
  expect(result.stderr).toContain("metadata is invalid");
  expect(readdirSync(f.scratch)).toEqual([]);
});

test.each(["../bad", "1.2.3\n1.2.4", "1.2.3;touch bad"])(
  "rejects invalid version %s before downloading",
  (version) => {
    const f = fixture();
    const result = f.run({ TNL_VERSION: version });
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("TNL_VERSION");
    expect(readdirSync(f.scratch)).toEqual([]);
    expect(readdirSync(f.downloads)).not.toContain("requests");
  },
);

test.each(["missing", "duplicate", "invalid", "mismatch"])(
  "rejects a %s checksum and preserves the installed binary",
  (mode) => {
    const f = fixture();
    mkdirSync(join(f.home, ".local/bin"), { recursive: true });
    writeFileSync(f.binary, "old binary");
    const rows = f.manifest();
    const row = rows.find((value) => value.endsWith("darwin_arm64.tar.gz"));
    expect(row).toBeDefined();
    const checksum =
      mode === "missing"
        ? ""
        : mode === "duplicate"
          ? `${row}\n${row}\n`
          : `${mode === "invalid" ? "xyz" : "0".repeat(64)}  tnl_1.2.3_darwin_arm64.tar.gz\n`;
    f.manifest("1.2.3", checksum);
    const result = f.run();
    expect(result.status).toBe(1);
    expect(result.stdout).toBe("");
    expect(result.stderr).toContain("checksum");
    assertFrames(result.stderr);
    expect(readFileSync(f.binary, "utf8")).toBe("old binary");
    expect(readdirSync(f.scratch)).toEqual([]);
  },
);

test.each(["network-failure", "checksum-failure"])(
  "presents %s once without leaking tool errors",
  (mode) => {
    const f = fixture();
    writeFileSync(join(f.downloads, mode), "");
    const result = f.run();
    expect(result.status).toBe(1);
    expect(result.stderr.match(/\]-- failed/g)).toHaveLength(1);
    expect(result.stderr).not.toContain("secret-value");
    assertFrames(result.stderr);
    expect(readdirSync(f.scratch)).toEqual([]);
  },
);

test.each(["corrupt", "missing", "symlink"])("rejects a %s archive", (mode) => {
  const f = fixture({
    ...(mode === "missing" ? { omit: "tnl" } : {}),
    ...(mode === "symlink" ? { symlink: "NOTICE" } : {}),
  });
  if (mode === "corrupt") {
    writeFileSync(join(f.downloads, "archive.tar.gz"), "not an archive");
    f.manifest();
  }
  const result = f.run();
  expect(result.status).toBe(1);
  expect(result.stderr).toContain("extract");
  expect(readdirSync(f.scratch)).toEqual([]);
});

test.each([{ os: "Windows_NT" }, { arch: "i686" }])(
  "rejects unsupported platforms before downloading: %o",
  (options) => {
    const f = fixture(options);
    const result = f.run();
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("not supported");
    assertFrames(result.stderr);
    expect(readdirSync(f.downloads)).not.toContain("requests");
  },
);

test("truncating the script before its final invocation does not install anything", () => {
  const f = fixture();
  const source = readFileSync(script, "utf8");
  const result = f.run({}, source.slice(0, source.lastIndexOf("tnl_install")));
  expect(result.stdout).toBe("");
  expect(readdirSync(f.downloads)).not.toContain("requests");
  expect(readdirSync(f.home)).toEqual([]);
});

test("a failed final replacement leaves the old binary and removes staging files", () => {
  const f = fixture();
  const dir = join(f.home, ".local/bin");
  mkdirSync(dir, { recursive: true });
  writeFileSync(f.binary, "old binary");
  rmSync(join(f.tools, "mv"));
  writeFileSync(join(f.tools, "mv"), "#!/bin/sh\nprintf 'sensitive tool failure\\n' >&2\nexit 1\n");
  chmodSync(join(f.tools, "mv"), 0o755);
  const result = f.run();
  expect(result.status).toBe(1);
  expect(result.stderr).toContain("could not install the binary");
  expect(result.stderr).not.toContain("sensitive tool failure");
  expect(readFileSync(f.binary, "utf8")).toBe("old binary");
  expect(readdirSync(f.scratch)).toEqual([]);
  expect(readdirSync(dir)).toEqual(["tnl", "tnl-notices"]);
});

test("missing awk still produces a pre-rendered branded diagnostic", () => {
  const f = fixture();
  rmSync(join(f.tools, "awk"));
  const result = f.run();
  expect(result.status).toBe(1);
  expect(result.stderr).toContain("awk is required");
  assertFrames(result.stderr);
});

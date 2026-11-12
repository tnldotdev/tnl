import { spawnSync } from "node:child_process";
import { appendFileSync } from "node:fs";
import { resolve } from "node:path";
import { setTimeout } from "node:timers/promises";
import { pathToFileURL } from "node:url";

const transient =
  /\b(?:408 Request Timeout|429 Too Many Requests|500 Internal Server Error|502 Bad Gateway|503 Service Unavailable|504 Gateway Timeout)\b|INTERNAL_ERROR|connection reset|TLS handshake timeout|i\/o timeout|temporary failure in name resolution/i;
const permanent =
  /checksum mismatch|SECURITY ERROR|verification failed|certificate signed by unknown authority|\b(?:401 Unauthorized|403 Forbidden|404 Not Found|410 Gone)\b|unknown revision|invalid version|no space left on device/i;

export function retryableDownload(output: string): boolean {
  return transient.test(output) && !permanent.test(output);
}

function run(directory: string) {
  const result = spawnSync("go", ["mod", "download"], {
    cwd: directory,
    encoding: "utf8",
    maxBuffer: 16 * 1024 * 1024,
    timeout: 180_000,
  });
  if (result.stdout) process.stdout.write(result.stdout);
  if (result.stderr) process.stderr.write(result.stderr);
  if (result.error) console.error(result.error.message);
  return {
    status: result.status,
    output: `${result.stdout ?? ""}\n${result.stderr ?? ""}`,
    interrupted: Boolean(result.signal || result.error),
  };
}

export async function downloadModules(
  directory: string,
  execute = run,
  wait: (milliseconds: number) => Promise<unknown> = setTimeout,
  summarize = (line: string) => {
    if (process.env.GITHUB_STEP_SUMMARY)
      appendFileSync(process.env.GITHUB_STEP_SUMMARY, `${line}\n`);
  },
): Promise<number> {
  for (let attempt = 1; attempt <= 3; attempt++) {
    console.log(`go mod download (${directory}), attempt ${attempt}/3`);
    const result = execute(directory);
    if (result.status === 0 && !result.interrupted) {
      summarize(`- Go dependencies (\`${directory}\`): downloaded on attempt ${attempt}/3.`);
      return 0;
    }
    if (result.interrupted || !retryableDownload(result.output) || attempt === 3) {
      summarize(
        `- Go dependencies (\`${directory}\`): failed on attempt ${attempt}/3; see the download log. Tests were not retried.`,
      );
      return result.status || 1;
    }
    console.error(
      "transient Go download failure; retrying the same proxy and checksum verification",
    );
    await wait(attempt * 5_000);
  }
  throw new Error("unreachable download attempt");
}

if (process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url) {
  for (const directory of [".", "tools/testharness"]) {
    const status = await downloadModules(directory);
    if (status !== 0) {
      process.exitCode = status;
      break;
    }
    const verified = spawnSync("go", ["mod", "verify"], { cwd: directory, stdio: "inherit" });
    if (verified.status !== 0) {
      process.exitCode = verified.status || 1;
      break;
    }
  }
}

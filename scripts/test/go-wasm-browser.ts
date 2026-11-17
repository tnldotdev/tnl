import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { readFile } from "node:fs/promises";
import { createServer } from "node:http";
import path from "node:path";
import { promisify } from "node:util";
import { chromium } from "playwright";

// used by go test -exec: Go builds the test binary and supplies its arguments.
const binary = process.argv[2];
assert(binary, "go-wasm-browser requires a Go/WASM test binary");
const { stdout: goroot } = await promisify(execFile)("go", ["env", "GOROOT"]);
const [wasm, runtime] = await Promise.all([
  readFile(binary),
  readFile(path.join(goroot.trim(), "lib/wasm/wasm_exec.js")),
]);
const server = createServer((request, response) => {
  response.setHeader("Cache-Control", "no-store");
  switch (request.url) {
    case "/":
      response.setHeader("Content-Type", "text/html");
      response.end('<!doctype html><script src="/wasm_exec.js"></script>');
      break;
    case "/test.wasm":
      response.setHeader("Content-Type", "application/wasm");
      response.end(wasm);
      break;
    case "/wasm_exec.js":
      response.setHeader("Content-Type", "text/javascript");
      response.end(runtime);
      break;
    default:
      response.writeHead(404).end();
  }
});
await new Promise<void>((resolve, reject) => {
  server.once("error", reject);
  server.listen(0, "127.0.0.1", resolve);
});
try {
  const address = server.address();
  assert(address && typeof address !== "string");
  const browser = await chromium.launch({ channel: "chrome" });
  try {
    const page = await browser.newPage();
    const errors: Error[] = [];
    page.on("console", (message) => console.log(message.text()));
    page.on("pageerror", (error) => errors.push(error));
    page.setDefaultTimeout(300_000);
    await page.goto(`http://127.0.0.1:${address.port}/`);
    const code = await page.evaluate(async (argv) => {
      interface Runtime {
        argv: string[];
        importObject: WebAssembly.Imports;
        exit(code: number): void;
        run(instance: WebAssembly.Instance): Promise<void>;
      }
      const globals = globalThis as typeof globalThis & { Go?: new () => Runtime };
      if (!globals.Go) throw new Error("Go runtime did not load");
      const go = new globals.Go();
      go.argv = argv;
      let exitCode: number | undefined;
      go.exit = (code) => {
        exitCode = code;
      };
      const { instance } = await WebAssembly.instantiateStreaming(
        fetch("/test.wasm"),
        go.importObject,
      );
      await go.run(instance);
      if (exitCode === undefined) throw new Error("Go test exited without a result");
      return exitCode;
    }, process.argv.slice(2));
    if (errors.length !== 0) throw new AggregateError(errors, "browser Go/WASM test failed");
    process.exitCode = code;
  } finally {
    await browser.close();
  }
} finally {
  server.closeAllConnections();
  await new Promise<void>((resolve, reject) =>
    server.close((error) => (error ? reject(error) : resolve())),
  );
}

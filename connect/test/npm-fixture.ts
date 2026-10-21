import { cp, mkdir, readFile, realpath, writeFile } from "node:fs/promises";
import path from "node:path";

// installed only on the test PATH. exercises the real installer child boundary
// without contacting npm or selecting a released version for the user.
const [source, ...args] = process.argv.slice(2);
if (!source) throw new Error("missing fixture package directory");
const prefix = args[args.indexOf("--prefix") + 1];
if (!prefix) throw new Error("missing npm prefix");
await writeFile(path.join(source, "npm-args.json"), JSON.stringify(args));
if ((await readFile(path.join(source, "fixture.json"), "utf8")).includes('"npmFail":true')) {
  process.stdout.write("fixture-private-npm-stdout");
  process.stderr.write("fixture-private-npm-stderr");
  process.exit(1);
}
const launcher = await realpath(path.join(source, "node_modules/@tnldotdev/tnl"));
const scope = path.join(prefix, "node_modules/@tnldotdev");
await mkdir(scope, { recursive: true });
await cp(launcher, path.join(scope, "tnl"), { recursive: true });
const native = `tnl-${process.platform}-${process.arch}`;
await cp(path.join(path.dirname(launcher), native), path.join(scope, native), { recursive: true });

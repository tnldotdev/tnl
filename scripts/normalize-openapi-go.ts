import { readFile, writeFile } from "node:fs/promises";

const [file] = process.argv.slice(2);
if (!file) {
  throw new Error("generated Go file is required");
}

const source = await readFile(file, "utf8");
const normalized = source
  .replaceAll('fmt.Errorf("Header parameter ', 'fmt.Errorf("header parameter ')
  .replaceAll(
    "// Client which conforms to the OpenAPI3 specification for this service.",
    "// Client calls this service's HTTP API.",
  )
  .replaceAll(
    "\t// The endpoint of the server conforming to this interface, with scheme,\n" +
      "\t// https://api.deepmap.com for example. This can contain a path relative\n" +
      "\t// to the server, such as https://api.deepmap.com/dev-test, and all the\n" +
      "\t// paths in the swagger spec will be appended to the server.",
    "\t// server URL; operation paths are appended to it.",
  )
  .replaceAll(
    "\t// Doer for performing requests, typically a *http.Client with any\n" +
      "\t// customized settings, such as certificate chains.",
    "\t// Client sends requests; callers can supply an http.Client with custom settings.",
  )
  .replaceAll(
    "\t// A list of callbacks for modifying requests which are generated before sending over\n" +
      "\t// the network.",
    "\t// RequestEditors modify requests before they are sent.",
  )
  .replaceAll(
    "// Creates a new Client, with reasonable defaults",
    "// NewClient creates a client with default options.",
  )
  .replaceAll("\t// create a client with sane default values\n", "")
  .replaceAll("\t// mutate client and add all optional params\n", "")
  .replaceAll("\t// ensure the server URL always has a trailing slash\n", "")
  .replaceAll("\t// create httpClient, if not already present\n", "")
  .replace(/^(\s*\/\/ )(.*)$/gm, (_line, prefix: string, text: string) => {
    if (text.startsWith("Code generated ") || text.startsWith("Package ")) {
      return prefix + text;
    }
    const genericStart =
      /^(A|An|The|This|These|Defines|Takes|Corresponds|Creates|When|For|If|All|Each|Only|Return|Returns|Use|Using|Parameter)\b/;
    if (genericStart.test(text)) {
      text = text.replace(genericStart, (word) => word.toLowerCase());
    } else {
      // generated field and operation comments begin with an identifier, then prose.
      text = text.replace(
        /^([A-Za-z_][A-Za-z0-9_]* )([A-Z][a-z])/,
        (_match, name: string, letter: string) => {
          return name + letter.toLowerCase();
        },
      );
    }
    text = text.replaceAll("publicURL version", "publish run number");
    return (
      prefix +
      text.replace(
        /(\.\s+)(A|An|The|This|These|When|For|If|All|Each|Only|Sparse|Returns|No|Inputs|Ingress|Equals|Dense|Cannot|After)\b/g,
        (_match, gap: string, word: string) => gap + word.toLowerCase(),
      )
    );
  });
await writeFile(file, normalized);

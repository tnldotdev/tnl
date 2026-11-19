import { config } from "zod";

// keep schema validation compatible with the site's CSP, including in blob workers.
config({ jitless: true });

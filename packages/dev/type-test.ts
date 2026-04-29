import {
  readDevEnvironment,
  registerTarget,
  type RegisteredTnlDevSession,
  type TnlDevSession,
} from "./dist/index.js";

const session: TnlDevSession | null = readDevEnvironment({});
const registered: Promise<RegisteredTnlDevSession | null> = registerTarget("vite", 5173, {});

export { registered, session };

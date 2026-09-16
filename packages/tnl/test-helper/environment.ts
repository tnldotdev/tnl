// Both in-process tests and child frameworks start outside any inherited tnl invocation.
export const environmentBaseline = {
  TNL_DEV_PROTOCOL: undefined,
  TNL_DEV_SOCKET: undefined,
  TNL_DEV_PORT: undefined,
  TNL_PROJECT_RUNTIME: undefined,
  TNL_FIXTURE_HOST: undefined,
  TNL_FIXTURE_PORT: undefined,
  XDG_RUNTIME_DIR: undefined,
  __NEXT_PRIVATE_ORIGIN: undefined,
  __VITE_ADDITIONAL_SERVER_ALLOWED_HOSTS: undefined,
  PORT: undefined,
  NODE_ENV: undefined,
} satisfies Record<string, string | undefined>;

export function subprocessEnvironment(
  overrides: Readonly<Record<string, string | undefined>> = {},
): NodeJS.ProcessEnv {
  return {
    ...process.env,
    ...environmentBaseline,
    NODE_OPTIONS: undefined,
    NODE_ENV: "development",
    NEXT_TELEMETRY_DISABLED: "1",
    ...overrides,
  };
}

export async function withProcessEnvironment<T>(
  environment: Readonly<Record<string, string | undefined>>,
  callback: () => T | Promise<T>,
): Promise<T> {
  const previous = new Map<string, string | undefined>();
  for (const [name, value] of Object.entries({ ...environmentBaseline, ...environment })) {
    previous.set(name, process.env[name]);
    setEnvironment(name, value);
  }
  try {
    return await callback();
  } finally {
    for (const [name, value] of previous) setEnvironment(name, value);
  }
}

function setEnvironment(name: string, value: string | undefined): void {
  if (value === undefined) delete process.env[name];
  else process.env[name] = value;
}

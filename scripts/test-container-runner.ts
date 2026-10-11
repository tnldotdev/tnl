import { spawn, type ChildProcess } from "node:child_process";
import process from "node:process";

// own one disposable test container and the child test process until both exit.
export class TestContainerRunner {
  private readonly container: string;
  private testProcess: ChildProcess | undefined;
  private stopping = false;

  constructor(container: string) {
    this.container = container;
    for (const signal of ["SIGINT", "SIGTERM"] as const) {
      process.once(signal, async () => {
        if (this.stopping) return;
        this.stopping = true;
        this.testProcess?.kill(signal);
        await this.remove();
        process.exitCode = 1;
      });
    }
  }

  async remove(): Promise<void> {
    await this.run("docker", ["rm", "--force", this.container], false, true);
  }

  async port(containerPort: number): Promise<string> {
    const mapping = (
      await this.output("docker", ["port", this.container, `${containerPort}/tcp`])
    ).trim();
    const port = mapping.match(/:([0-9]+)$/)?.[1];
    if (port === undefined) throw new Error(`unexpected TCP port mapping ${mapping}`);
    return port;
  }

  output(executable: string, arguments_: readonly string[]): Promise<string> {
    return new Promise((resolve, reject) => {
      const child = spawn(executable, arguments_, { stdio: ["ignore", "pipe", "pipe"] });
      let stdout = "";
      let stderr = "";
      child.stdout.setEncoding("utf8").on("data", (data: string) => (stdout += data));
      child.stderr.setEncoding("utf8").on("data", (data: string) => (stderr += data));
      child.once("error", reject);
      child.once("close", (code) => {
        if (code === 0) resolve(stdout);
        else reject(new Error(`${executable} exited with ${code}: ${stderr.trim()}`));
      });
    });
  }

  run(
    executable: string,
    arguments_: readonly string[],
    inherited = false,
    allowFailure = false,
  ): Promise<number> {
    return new Promise((resolve, reject) => {
      const child = spawn(executable, arguments_, {
        stdio: inherited ? "inherit" : ["ignore", "ignore", "pipe"],
      });
      let stderr = "";
      child.stderr?.setEncoding("utf8").on("data", (data: string) => {
        stderr = (stderr + data).slice(-4096);
      });
      if (inherited) this.testProcess = child;
      child.once("error", reject);
      child.once("close", (code, signal) => {
        if (inherited) this.testProcess = undefined;
        if (code === 0 || allowFailure) resolve(code ?? 1);
        else reject(new Error(`${executable} exited with ${signal ?? code}: ${stderr.trim()}`));
      });
    });
  }
}

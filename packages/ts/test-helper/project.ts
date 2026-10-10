import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { onTestFinished } from "vitest";

export async function temporaryDirectory(prefix: string): Promise<string> {
  const directory = await mkdtemp(path.join(os.tmpdir(), prefix));
  onTestFinished(() => rm(directory, { force: true, recursive: true }));
  return directory;
}

export async function createProjectFixture(prefix: string) {
  const root = await temporaryDirectory(prefix);
  const serviceDirectory = path.join(root, "apps", "api");
  await mkdir(path.join(root, ".tnl"), { recursive: true });
  await mkdir(serviceDirectory, { recursive: true });
  await writeFile(
    path.join(root, ".tnl", "project.json"),
    `${JSON.stringify(testProjectDocument())}\n`,
  );
  return { root, serviceDirectory };
}

export function testProjectDocument() {
  return {
    namespace: "member.example",
    dev: false,
    serviceDirectories: { api: "apps/api", web: "apps/web" },
    services: {
      api: {
        hostname: "api.member.example",
        namespace: "member.example",
        url: "https://api.member.example",
      },
      web: {
        hostname: "web.member.example",
        namespace: "member.example",
        url: "https://web.member.example",
      },
    },
    version: 2,
  };
}

export function testPublicProject(dev: boolean) {
  const project = testProjectDocument();
  return { namespace: project.namespace, dev, services: project.services };
}

export function testAliasAssignment() {
  const project = testPublicProject(true);
  return {
    hostname: "api.member.example",
    publicURL: "https://api.member.example",
    service: "api",
    project: {
      ...project,
      services: {
        ...project.services,
        web: {
          ...project.services.web,
          paths: {
            "/api": { service: "api", url: "https://web.member.example/api", stripPrefix: true },
          },
        },
        worker: {
          namespace: "member.example",
          hostname: "worker.member.example",
          url: "https://worker.member.example",
        },
      },
      aliases: {
        api: {
          service: "api",
          hostname: "review-api.member.example",
          url: "https://review-api.member.example",
        },
        web: {
          service: "web",
          hostname: "review-web.member.example",
          url: "https://review-web.member.example",
        },
        worker: {
          service: "worker",
          hostname: "review-worker.member.example",
          url: "https://review-worker.member.example",
        },
      },
    },
  };
}

export async function withCurrentDirectory<T>(
  directory: string,
  callback: () => T | Promise<T>,
): Promise<T> {
  const previous = process.cwd();
  process.chdir(directory);
  try {
    return await callback();
  } finally {
    process.chdir(previous);
  }
}

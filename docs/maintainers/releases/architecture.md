# release architecture

One root release carries `tnl`, `tnld`, the TypeScript SDK and four native npm
packages, and four Python platform wheels. The action remains a separate package.
CI publishes artifacts and images; deployment remains an operator action.

## artifact ownership

| Owner                                               | Responsibility                                                                                                                  |
| --------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------- |
| `.goreleaser.yaml`, `.github/workflows/release.yml` | Command archives, checksums/SBOMs, provenance, signed image, npm/PyPI publication, and release completion                       |
| `scripts/package`, `tasks/packaging.yml`            | Manifest-driven native npm/SDK packaging, installed npm/pnpm consumers, Python wheels, legal files, hashes, and platform checks |
| `scripts/release`                                   | Version derivation, publication adapter, Homebrew update, and deployed release-check driver                                     |
| `scripts/installer`, `internal/clioutput`           | Installer source/rendering and generated externally consumed `scripts/install.sh`                                               |
| `packages/ts/native`, `packages/py`                 | Platform manifest inputs and Python distribution sources/type marker                                                            |
| `connect`                                           | Independent action inputs, outputs, OIDC acquisition, cleanup, and committed bundles                                            |
| `deploy/server/{standalone,split}`                  | Generic self-hosted server Compose units and role-specific environment/proxy files                                              |
| `deploy/publisher/{compose,fargate}`                | Publisher container/template and generated offline infrastructure examples                                                      |

The tag determines the combined product version. Preserve placeholder source
versions, exact native dependency versions in release artifacts, executable
modes, binary hashes, export conditions, and required `LICENSE`, `NOTICE`, and
`THIRD_PARTY_LICENSES.txt`. Four native targets are Darwin/Linux arm64/x64. Local
execution on one platform does not qualify the others.

The source pack and release packer are separate checks. `task js:pack` checks
source packaging; `task release:snapshot`, then `task release:npm-package` checks
real archive-derived native tarballs installed through both npm and pnpm.
`task py:build` checks archive-derived platform wheels. Public root and Node-only
workload ESM/CommonJS exports, browser restrictions, error identity, and the shared
workload singleton must survive packaging. Private native IPC is not a public
extension export.

## deployment and qualification

Generic templates retain digest pins, nonroot permissions, ports, private mounts,
health checks, and direct migration versus pooled serving URLs. Generated Fargate
outputs come from `internal/publisher/deployment`; operators supply deployment
parameters and independently provisioned replica identities. A user's generated
default `deploy/publishers/aws.json` path is distinct from this repository's
`deploy/publisher/fargate` reference templates.

Hosted Fly deployment, selected production image digests, staging rollout, and
HTTPS/private-connector qualification belong to sibling `tnl.dev`. This source
reorganization does not deploy or qualify an image. Live provider freeze/thaw,
EFS locking/partial restore, and production rollout retain their explicit
qualification boundaries.

See [releasing](releasing.md), [deployed release checks](release-checks.md), and
the [prerelease review ledger](prerelease-review.md). For release assessment,
version or tag work, follow the root-discovered
[release skill](../../../.agents/skills/tnl-release/SKILL.md); for mutating checks,
follow [the release-check skill](../../../.agents/skills/tnl-release-check/SKILL.md).
Those skills retain their signing and approval gates. Large deployed benchmarks
require their separate explicit server/workload approval.

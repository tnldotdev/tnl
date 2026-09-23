# tnl

**A URL for every worktree.**

tnl gives your development app a stable HTTPS URL. Run it on your laptop or a
remote machine, and open it in your browser.

Working with coding agents? Give each one a Git worktree. Each worktree gets
its own URL, so you can try their changes side by side.

```text
main worktree       --> its own URL --> browser tab 1
checkout worktree   --> its own URL --> browser tab 2
redesign worktree   --> its own URL --> browser tab 3
```

## try it

Have an app running on port 3000? From its project directory:

```console
brew install tnldotdev/tap/tnl
tnl publish 3000
```

Sign in when prompted, then open the HTTPS URL tnl prints. Keep tnl running
while you use it. [tnl.dev](https://tnl.dev) hosts the service, so there's no
server to set up.

By default, only connections from the public IP of the machine running tnl
are allowed.

Available for macOS and Linux. [Other ways to install](docs/releases.md).

## make it your dev command

With the [Next.js or Vite integration](packages/tnl/readme.md#initialize-a-project)
set up, start your app with:

```console
tnl dev
```

tnl follows the port your app actually uses, and live reload works through the
URL. Run it in each worktree. Its
[URL stays the same across restarts](docs/project-configuration.md#worktree-urls).

## develop on a remote machine

Let a remote machine run your app and your agents while you review their work
in your laptop's browser. Run tnl beside the app and add your laptop's public
IP with `--allow-ip`. To let anyone connect, use `--allow-all-ips` instead.

## why tnl?

ngrok and Cloudflare Tunnel put apps online too. tnl focuses on the development
workflow: automatic worktree URLs, Next.js and Vite integration, and one command
to start your app. HTTPS stays encrypted until it reaches tnl on your machine.
Use our hosted service or [run your own](docs/self-hosting.md).

## learn more

[Commands](docs/cli-reference.md) ·
[Project setup](docs/project-configuration.md) ·
[Automation](docs/automation.md) ·
[Contributing](contributing.md)

## telemetry

tnl sends usage telemetry by default, including when self-hosted. Disable it
with `TNL_NO_TELEMETRY=true`. [What gets sent](docs/cli-reference.md#telemetry).

## license

Client and server: [MIT](LICENSE). [Dependency notices](THIRD_PARTY_LICENSES.txt).

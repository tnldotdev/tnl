package main

import (
	"context"
	"errors"
	"io"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"github.com/tnldotdev/tnl/internal/client/auth"
	clientauthority "github.com/tnldotdev/tnl/internal/client/authority"
	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	clienttelemetry "github.com/tnldotdev/tnl/internal/client/telemetry"
	"github.com/tnldotdev/tnl/internal/clioutput"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/connector"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/failure/diagnostic"
	"github.com/tnldotdev/tnl/internal/observability"
	"github.com/tnldotdev/tnl/internal/policy/trafficlimits"
	telemetryv1 "github.com/tnldotdev/tnl/pkg/api/integrations/telemetry/v1"
)

type cli struct {
	ConfigPath  string `name:"config" help:"Use a project configuration file; put this flag before the command." type:"path"`
	NoConfig    bool   `name:"no-config" help:"Skip project configuration; put this flag before the command."`
	NoTelemetry bool   `name:"no-telemetry" env:"TNL_NO_TELEMETRY" help:"Disable pseudonymous usage telemetry."`
	Init        initCommand
	Apply       applyCommand
	Deployment  deploymentCommand
	Generate    generateCommand
	Check       struct{}
	Audit       auditCommand
	Runtime     runtimeCommand
	Wait        waitCommand
	Watch       watchCommand
	Publish     publishCommand
	Connect     connectCommand
	Publisher   publisherCommand
	Service     serviceCommand
	Endpoint    endpointCommand
	Detached    detachedCommand
	Status      statusCommand
	Ping        pingCommand
	Inspect     inspectCommand
	Telemetry   telemetryCommand
	Auth        authCommand
	Team        teamCommand
	Domain      domainCommand
	URL         publicURLCommand
	Share       shareCommand
	Feedback    feedbackCommand
	Webhook     webhookCommand
	Alias       aliasCommand
	Admin       adminCommand
	Version     struct{}
}

type openOptions struct {
	Open        bool `name:"open" help:"Open the public URL in the default browser once ready."`
	openFromCLI bool
}

type tunnelFlags struct {
	teamSelectionFlags `embed:""`
	Domain             string                `name:"domain" env:"TNL_DOMAIN" help:"Ready team domain for the public URL. Defaults to the team's default domain."`
	Name               string                `name:"name" env:"TNL_NAME" help:"One label beneath the selected domain or member namespace. Defaults to a service-and-worktree name."`
	PublicURL          string                `name:"hostname" env:"TNL_HOSTNAME" help:"Exact public hostname to publish. Also accepts an HTTPS origin."`
	Anonymous          bool                  `name:"anonymous" help:"Do not require a tnl visitor credential; the local service still owns its own authentication."`
	RequirePostQuantum *bool                 `name:"require-post-quantum" help:"Require hybrid post-quantum key agreement from public HTTPS visitors."`
	IP                 []string              `name:"ip" help:"Restrict visitor source addresses; repeat for each address, CIDR or 'current'."`
	Ephemeral          bool                  `name:"ephemeral" env:"TNL_EPHEMERAL" help:"Remove the public URL when this tunnel stops."`
	Requests           *int                  `name:"requests" env:"TNL_REQUESTS" help:"Total application requests admitted before the tunnel drains."`
	RateRequests       *int                  `name:"rate-requests" env:"TNL_RATE_REQUESTS" help:"Number of requests admitted per rate period. Requires --rate-per."`
	RatePer            string                `name:"rate-per" env:"TNL_RATE_PER" help:"Rate period, such as 1m. Requires --rate-requests."`
	RateBurst          *int                  `name:"rate-burst" help:"Maximum burst of application work admitted by the rate limit."`
	Concurrency        *int                  `name:"concurrency" env:"TNL_CONCURRENCY" help:"Maximum simultaneous HTTP work or TCP connections."`
	TargetCAFile       string                `name:"target-ca-file" env:"TNL_TARGET_CA_FILE" type:"path" help:"Additional PEM certificate authorities for an HTTPS target."`
	InspectionMode     config.InspectionMode `name:"inspection-mode" enum:"none,summary" default:"summary" help:"Local HTTP inspection: summary (default) or none."`

	ephemeralFromCLI         bool
	domainFromCLI            bool
	inspectionModeFromCLI    bool
	inspectionModeFromConfig bool
	httpLimits               *config.WorkLimits
	traffic                  *trafficlimits.Selection
	inspection               *config.Inspection
	access                   *config.Access
}

type remoteFlags struct {
	ServerURL     string `name:"server" env:"TNL_SERVER" help:"Control URL. Defaults to the project or selected server."`
	AccessToken   string `name:"access-token" env:"TNL_ACCESS_TOKEN" help:"Access token. Defaults to the saved session."`
	StateDir      string `name:"state-dir" env:"TNL_STATE_DIR" type:"path" help:"Client state directory."`
	ProjectTeam   string
	SelectedTeam  string
	configArgs    string
	projectServer *string
}

type teamSelectionFlags struct {
	Team string `name:"team" env:"TNL_TEAM" help:"Team name or ID; overrides the project team for this command."`
}

type scopedTeamFlags struct {
	remoteFlags        `embed:""`
	teamSelectionFlags `embed:""`
}

func (flags scopedTeamFlags) selection() remoteFlags {
	selected := flags.remoteFlags
	selected.SelectedTeam = flags.Team
	return selected
}

type webhookCommand struct {
	Use     webhookUseCommand
	Release webhookChoiceCommand
}

type webhookUseCommand struct {
	webhookChoiceCommand `embed:""`
	Force                bool `help:"Replace the selected receiver even if its tunnel is running."`
}

type webhookChoiceCommand struct {
	remoteFlags `embed:""`
	Endpoint    string `arg:"" name:"endpoint" help:"Configured webhook endpoint name."`
}

type aliasCommand struct {
	Use     aliasUseCommand
	Release aliasChoiceCommand
}

type aliasUseCommand struct {
	aliasChoiceCommand `embed:""`
	Force              bool `help:"Deliberately replace another live worktree's selection."`
}

type aliasChoiceCommand struct {
	scopedTeamFlags `embed:""`
	Name            string `arg:"" name:"name" help:"Configured project alias name."`
}

func main() {
	received := make(chan os.Signal, 1)
	signal.Notify(received, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	ctx, stop := processSignalContext((&nativeProcess{}).context(context.Background()), received, func() { signal.Stop(received) })
	defer stop()
	launchCtx := observability.ExtractLaunch(ctx, os.Getenv(observability.LaunchTraceparent))
	_ = os.Unsetenv(observability.LaunchTraceparent)
	err := runNativeProcess(launchCtx, os.Args[1:], os.Stdout, os.Stderr)
	stop() // command observation and the final telemetry flush have already joined.
	if err != nil {
		code, render := terminalResult(err)
		if render != nil {
			writeCommandError(os.Stderr, render)
		}
		if code != 0 {
			os.Exit(code)
		}
	}
}

type nativeProcess struct {
	shutdownMetrics func(context.Context) error
	metricsTimeout  time.Duration
	closeTelemetry  func(context.Context)
	shutdownMu      sync.Mutex
	shutdownUntil   time.Time
}

func (p *nativeProcess) context(ctx context.Context) context.Context {
	ctx = context.WithValue(ctx, nativeProcessKey{}, p)
	return observability.WithShutdownDeadline(ctx, p.limitShutdown)
}

// this is only the deadline handoff between existing owners, not another
// lifetime: command drain, forced I/O closure, and export joins stay with them.
func (p *nativeProcess) limitShutdown(until time.Time) time.Time {
	p.shutdownMu.Lock()
	defer p.shutdownMu.Unlock()
	if p.shutdownUntil.IsZero() || until.Before(p.shutdownUntil) {
		p.shutdownUntil = until
	}
	return p.shutdownUntil
}

func runNativeProcess(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	return runNativeCommand(ctx, func(ctx context.Context, factory telemetryFactory) error {
		return run(ctx, args, stdout, stderr, factory)
	})
}

// the process joins the command before closing either optional export owner.
func runNativeCommand(ctx context.Context, command func(context.Context, telemetryFactory) error) error {
	process, ok := ctx.Value(nativeProcessKey{}).(*nativeProcess)
	if !ok {
		process = &nativeProcess{}
		ctx = process.context(ctx)
	}
	stopped := make(chan struct{})
	stopDeadline := context.AfterFunc(ctx, func() {
		defer close(stopped)
		observability.ShutdownDeadline(ctx, time.Now().Add(10*time.Second))
	})
	defer func() {
		if !stopDeadline() {
			<-stopped
		}
	}()
	result := command(ctx, func(config clienttelemetry.Config) *clienttelemetry.Collector {
		collector, _ := clienttelemetry.New(context.WithoutCancel(ctx), config)
		if collector != nil {
			process.closeTelemetry = collector.Close
		}
		return collector
	})
	if process.shutdownMetrics != nil {
		closeProcessMetrics(ctx, process.metricsTimeout, process.shutdownMetrics)
	}
	if process.closeTelemetry != nil {
		closeTelemetry(ctx, process.closeTelemetry)
	}
	return result
}

func closeProcessMetrics(ctx context.Context, budget time.Duration, shutdown func(context.Context) error) {
	ctx, cancel := processFlushContext(ctx, budget)
	defer cancel()
	_ = shutdown(ctx)
}

func processFlushContext(ctx context.Context, budget time.Duration) (context.Context, context.CancelFunc) {
	until := time.Now().Add(budget)
	if parent, ok := ctx.Deadline(); ok && parent.Before(until) {
		until = parent
	}
	if process, ok := ctx.Value(nativeProcessKey{}).(*nativeProcess); ok {
		process.shutdownMu.Lock()
		// a finite command with no earlier stop starts its bounded final flush
		// here. an export-specific cap must not replace an existing stop limit.
		if process.shutdownUntil.IsZero() {
			process.shutdownUntil = until
		}
		if process.shutdownUntil.Before(until) {
			until = process.shutdownUntil
		}
		process.shutdownMu.Unlock()
	}
	return context.WithDeadline(context.WithoutCancel(ctx), until)
}

// only this registered signal producer turns SIGINT/SIGTERM/SIGHUP into ordinary
// cancellation. parent causes are inherited unchanged; consumers never infer
// signal origin from an opaque error's text, type name or Is method.
func processSignalContext(parent context.Context, received <-chan os.Signal, unregister func()) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(parent)
	stopContext := sync.OnceFunc(cancel)
	stopNotifications := sync.OnceFunc(unregister)
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer stopNotifications()
		for {
			select {
			case value, ok := <-received:
				if !ok {
					return
				}
				if value != os.Interrupt && value != syscall.SIGTERM && value != syscall.SIGHUP {
					continue
				}
				// restore default handling before publishing cancellation, so a
				// second signal can terminate a command that stalls during cleanup.
				stopNotifications()
				observability.ShutdownDeadline(parent, time.Now().Add(10*time.Second))
				stopContext()
				return
			case <-ctx.Done():
				return
			}
		}
	}()
	return ctx, func() { stopNotifications(); stopContext(); <-done }
}

func terminalResult(err error) (int, error) {
	failures, unowned := 0, 0
	var child *connector.ClientExit
	var visit func(error, bool)
	visit = func(err error, owned bool) {
		if err == nil {
			return
		}
		if exit, ok := err.(*connector.ClientExit); ok {
			child = exit
			return
		}
		if reported, ok := err.(*reportedError); ok {
			visit(reported.err, true)
			return
		}
		if joined, ok := err.(interface{ Unwrap() []error }); ok {
			unwrapped := false
			for _, inner := range joined.Unwrap() {
				if inner != nil {
					visit(inner, owned)
					unwrapped = true
				}
			}
			if unwrapped {
				return
			}
		}
		if wrapped, ok := err.(interface{ Unwrap() error }); ok && wrapped.Unwrap() != nil {
			visit(wrapped.Unwrap(), owned)
			return
		}
		if errors.Is(err, context.Canceled) {
			return
		}
		failures++
		if !owned {
			unowned++
		}
	}
	visit(err, false)
	if child != nil {
		if failures == 0 {
			return child.Code, nil
		}
		return child.Code, err
	}
	if failures != 0 {
		if unowned != 0 {
			return 1, err
		}
		return 1, nil
	}
	return 0, nil
}

func writeCommandError(output io.Writer, err error) {
	var machine *machineCommandError
	if errors.As(err, &machine) {
		writeMachineCommandError(output, machine.error)
		return
	}
	err = classifyCommandError(err)
	followup, _ := errors.AsType[*commandFollowup](err)
	message, ok := diagnostic.MessageForError(err)
	if !ok {
		message = humanFailureMessage(err, followup != nil)
	}
	if followup != nil {
		message.Blocks = append(message.Blocks, followup.block)
	}
	_ = clioutput.Write(output, message)
}

func humanFailureMessage(err error, hasFollowup bool) clioutput.Message {
	presented := presentHumanFailure(err)
	if hasFollowup {
		// the concrete resume command replaces the operation-id placeholder.
		switch presented.reason {
		case failure.AuthWaitTimeout:
			presented.action = ""
		case failure.AuthProviderUnavailable:
			presented.action = "Check provider connectivity."
		}
	}
	blocks := []clioutput.Block{clioutput.Text("Error: " + presented.message)}
	if typed, ok := failure.Of(err); ok && typed.Reason() == failure.ObservabilityConfigInvalid && typed.Setting() != "" {
		blocks = append(blocks, clioutput.Fields(clioutput.Field{Label: "setting", Value: string(typed.Setting())}))
	}
	caseID := failure.KnownCase(err)
	if variant := failure.CaseFor(presented.reason, caseID); variant != nil {
		blocks = append(blocks, clioutput.Text(variant.Description), clioutput.Line(variant.Action))
	} else if presented.action != "" {
		blocks = append(blocks, clioutput.Line(presented.action))
	}
	if helpURL := failure.HelpURL(presented.reason, caseID); helpURL != "" {
		blocks = append(blocks, clioutput.Line(string(presented.reason)+"  "+helpURL))
	}
	return clioutput.Message{Blocks: blocks}
}

func classifyCommandError(err error) error {
	if err == nil {
		return nil
	}
	if _, classified := diagnostic.CodeOf(err); classified {
		return err
	}
	if reason, _, owned := failure.Describe(err); owned {
		switch reason {
		case failure.Authentication, failure.ServerUnavailable, failure.ServerRateLimited, failure.DNSPending:
			// common API sentinels have matching CLI diagnostics below.
		default:
			// an operation's more specific meaning takes precedence over its cause.
			return err
		}
	}
	if errors.Is(err, auth.ErrAuthenticationTimeout) {
		return diagnostic.Wrap(diagnostic.AuthenticationTimeout, err)
	}
	if errors.Is(err, clientcontrol.ErrUnauthenticated) || errors.Is(err, clientauthority.ErrUnauthenticated) {
		return diagnostic.Wrap(diagnostic.AuthenticationRequired, err)
	}
	if errors.Is(err, clientcontrol.ErrDNSProofPending) || errors.Is(err, clientauthority.ErrDNSProofPending) {
		return diagnostic.Wrap(diagnostic.DNSSetupPending, err)
	}
	if errors.Is(err, clientcontrol.ErrRateLimited) || errors.Is(err, clientauthority.ErrRateLimited) {
		return diagnostic.Wrap(diagnostic.RateLimited, err)
	}
	if errors.Is(err, clientcontrol.ErrUnavailable) || errors.Is(err, clientauthority.ErrUnavailable) {
		return diagnostic.Wrap(diagnostic.ServerUnavailable, err)
	}
	return err
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer, factories ...telemetryFactory) (result error) {
	command := ""
	machineIntent := false
	defer func() {
		result = classifyCommandError(result)
		if result != nil {
			if _, typed := failure.Of(result); !typed {
				if _, classified := diagnostic.CodeOf(result); !classified {
					result = failure.Wrap(failure.Operation(commandFailureOperation(command)), commandFailureReason(command), result)
				}
			}
		}
		if result != nil && command != "" {
			result = clioutput.WrapCommand(command, result)
		}
		var reported *reportedError
		if result != nil && (machineIntent || machineOutputRequested(args)) && !errors.As(result, &reported) {
			result = &machineCommandError{result}
		}
	}()
	a := commandApp{flags: &cli{}, out: stdout, errOut: stderr, argv: args, factories: factories}
	root := a.root()
	root.SetArgs(args)
	selected, err := root.ExecuteContextC(ctx)
	if selected != nil && selected != root {
		command = clioutput.CommandTitle("tnl", commandID(selected))
		machineIntent = strings.HasPrefix(commandID(selected), "runtime connections ")
	}
	return err
}

func (a *commandApp) execute(parsed *cobra.Command, handle func(commandCall) error) (result error) {
	ctx, flags := parsed.Context(), a.flags
	factories := a.factories
	parsedCommand := commandID(parsed)
	applyTunnelCLIUnits(parsed, flags)
	if parsedCommand == "version" || parsedCommand == "generate" || parsedCommand == "check" || parsedCommand == "init" && flags.Init.DryRun {
		return handle(commandCall{ctx: ctx})
	}
	var err error
	process, native := ctx.Value(nativeProcessKey{}).(*nativeProcess)
	if native {
		var metrics *observability.Metrics
		ctx, metrics, err = observability.StartProcess(ctx, commandObservabilityRole(parsedCommand, *flags).String())
		if err != nil {
			return err
		}
		budget := observability.CLIShutdownTimeout
		if persistentObservabilityOwner(parsedCommand, *flags) {
			budget = observability.ShutdownTimeout
		}
		process.shutdownMetrics, process.metricsTimeout = metrics.Shutdown, budget
	}
	ctx, finishCommand := observability.ClientCommand(ctx, parsedCommand)
	defer func() { finishCommand(result) }()
	if flags.Publish.Install || flags.Publisher.Serve.Install || flags.Connect.Start.Install {
		var finishInstall func(error)
		ctx, finishInstall = observability.ClientOperation(ctx, "client.install")
		defer func() { finishInstall(result) }()
	}
	telemetryCommand, telemetryAction, tracked := selectedTelemetryCommand(parsed)
	serving := parsedCommand == "runtime serve" || parsedCommand == "runtime connections serve" || parsedCommand == "service serve" || parsedCommand == "publisher serve" || parsedCommand == "publish <service-or-target>" || parsedCommand == "connect start <name>"
	root, stateErr := commandStateRoot(parsed)
	enabled, preferenceErr := false, stateErr
	if stateErr == nil && (tracked || serving) {
		enabled, preferenceErr = clientstate.TelemetryEnabledAt(ctx, root)
	}
	disabled := flags.NoTelemetry || preferenceErr != nil || !enabled
	flags.Publish.TelemetryDisabled = flags.NoTelemetry || flags.Publish.Install && disabled
	flags.Connect.Start.telemetryDisabled = flags.NoTelemetry || flags.Connect.Start.Install && disabled
	flags.Publisher.Serve.telemetryDisabled = flags.NoTelemetry || flags.Publisher.Serve.Install && disabled
	config := clienttelemetry.Config{Root: root}
	if parsedCommand == "service serve" {
		options, err := flags.Service.Serve.options()
		if err != nil {
			return err
		}
		config.Root, config.Protection = options.Root, clientstate.ProtectionFile
	}
	var collector *clienttelemetry.Collector
	if !flags.NoTelemetry && stateErr == nil && (tracked || serving) && (enabled || serving) && len(factories) != 0 && factories[0] != nil {
		collector = factories[0](config)
	}
	flags.Publish.telemetry, flags.Connect.Start.telemetry = collector, collector
	flags.Publisher.Serve.telemetry, flags.Service.Serve.telemetry = collector, collector
	flags.Runtime.Serve.telemetry, flags.Runtime.Connections.telemetry = collector, collector
	flags.Runtime.Connections.disabled = flags.NoTelemetry
	failureStage := telemetryv1.Setup
	if collector != nil && tracked && !flags.Publish.Install && !flags.Publish.Detach {
		defer func() {
			outcome := result
			if outcome == nil && ctx.Err() != nil {
				outcome = context.Cause(ctx)
			}
			collector.Report(clienttelemetry.Command(commandOutcome(telemetryCommand, telemetryAction, failureStage, classifyCommandError(outcome))))
		}()
	}
	call := commandCall{ctx: ctx, command: parsed, started: func() { failureStage = telemetryv1.Command }}
	if parsedCommand == "publisher serve" || parsedCommand == "connect start <name>" || parsedCommand == "publish <service-or-target>" {
		return handle(call)
	}
	if projectSensitiveCommand(parsedCommand) {
		call.project, err = a.loadCommandProject(ctx, parsed)
		if err != nil {
			return err
		}
	}
	call.started()
	return handle(call)
}

func (a *commandApp) loadCommandProject(ctx context.Context, parsed *cobra.Command) (projectConfiguration, error) {
	flags, id := a.flags, commandID(parsed)
	if strings.HasPrefix(id, "alias ") {
		selection, _, err := selectProjectConfiguration(ctx, *flags)
		if err != nil {
			return projectConfiguration{}, err
		}
		if selection.Path == "" {
			return projectConfiguration{}, failure.Wrap("select alias", failure.ProjectConfigMissing, errors.New("project configuration with an alias is required"))
		}
	}
	root, err := commandStateRoot(parsed)
	if err != nil {
		return projectConfiguration{}, err
	}
	project, err := loadProjectConfiguration(ctx, *flags, root)
	if err != nil {
		return projectConfiguration{}, err
	}
	return project, applyProjectCommandContext(id, project, flags)
}

type nativeProcessKey struct{}

func persistentObservabilityOwner(command string, flags cli) bool {
	return commandObservabilityRole(command, flags) == observability.RolePublisher || command == "runtime connections serve" || command == "connect start <name>" && !flags.Connect.Start.Detach && !flags.Connect.Start.Install
}

func commandObservabilityRole(command string, flags cli) observability.Role {
	switch command {
	case "publish <service-or-target>":
		if !flags.Publish.Install && !flags.Publish.Detach {
			return observability.RolePublisher
		}
	case "publisher serve":
		if !flags.Publisher.Serve.Detach && !flags.Publisher.Serve.Install {
			return observability.RolePublisher
		}
	case "runtime serve", "service serve":
		return observability.RolePublisher
	}
	return observability.RoleClient
}

func commandFailureOperation(command string) string {
	if command == "" {
		return "parse command"
	}
	return command
}

func commandFailureReason(command string) failure.Reason {
	switch {
	case command == "tnl init":
		return failure.InitFailed
	case command == "tnl check", command == "tnl generate":
		return failure.ProjectConfigInvalid
	case strings.HasPrefix(command, "tnl telemetry "), command == "tnl status":
		return failure.ClientStateUnavailable
	case strings.HasPrefix(command, "tnl auth "):
		return failure.Authentication
	case strings.HasPrefix(command, "tnl publish"):
		return failure.TunnelUnavailable
	case strings.HasPrefix(command, "tnl connect"):
		return failure.TunnelUnavailable
	case strings.HasPrefix(command, "tnl team "):
		return failure.TeamUnavailable
	case strings.HasPrefix(command, "tnl domain "):
		return failure.DomainUnavailable
	case strings.HasPrefix(command, "tnl url "):
		return failure.ServerConflict
	case strings.HasPrefix(command, "tnl deployment "):
		return failure.ServerConflict
	case command == "tnl share", strings.HasPrefix(command, "tnl share "), strings.HasPrefix(command, "tnl feedback "):
		return failure.ServerConflict
	case strings.HasPrefix(command, "tnl webhook "):
		return failure.ServerConflict
	case strings.HasPrefix(command, "tnl admin "):
		return failure.AdminUnavailable
	case command == "tnl version":
		return failure.OutputUnavailable
	default:
		return failure.InvalidCommand
	}
}

func canonicalParsedCommand(command string) string {
	switch command {
	case "share create":
		return "share"
	case "auth login run":
		return "auth login"
	case "publish":
		return "publish <service-or-target>"
	case "publisher enroll":
		return "publisher enroll <service-or-address>"
	case "share link create":
		return "share link create <url>"
	case "share team create":
		return "share team create <url>"
	case "share list":
		return "share list <url>"
	default:
		return command
	}
}

func applyTunnelCLIUnits(parsed *cobra.Command, flags *cli) {
	changed := parsed.Flags().Changed
	publicURL, name, domain, ephemeral, open := changed("hostname"), changed("name"), changed("domain"), changed("ephemeral"), changed("open")
	inspectionMode := changed("inspection-mode")
	apply := func(tunnel *tunnelFlags) {
		tunnel.ephemeralFromCLI = ephemeral
		tunnel.domainFromCLI = domain
		tunnel.inspectionModeFromCLI = inspectionMode
		if publicURL && !name {
			tunnel.Name = ""
		}
		if name && !publicURL {
			tunnel.PublicURL = ""
		}
	}
	switch commandID(parsed) {
	case "publish <service-or-target>":
		apply(&flags.Publish.tunnelFlags)
		flags.Publish.openFromCLI = open
		flags.Publish.demoNameFromCLI = name
		if flags.Publish.Demo && changed("anonymous") && !flags.Publish.Anonymous {
			flags.Publish.access = &config.Access{Mode: "restricted"}
		}
	}
}

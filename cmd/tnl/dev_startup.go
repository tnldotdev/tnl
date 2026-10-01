package main

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/tnldotdev/tnl/internal/clientstate"
	"github.com/tnldotdev/tnl/internal/diagnostic"
	"github.com/tnldotdev/tnl/internal/localproxy"
)

const devRegistrationWait = 30 * time.Second

type devStartupResult struct {
	target        string
	framework     string
	frameworkDone <-chan devFrameworkResult
}

func awaitDevStartup(
	ctx context.Context, timeout time.Duration, forcedTarget string,
	bootstrap *devBootstrap, child *devProcess, tunnel *clientstate.Tunnel,
	assignment devConfigurationResponse,
) (devStartupResult, error) {
	// child exit, framework registration, and target readiness compete during
	// startup. cancel the losing wait without blocking its buffered result.
	var configuration *devConfigurationRequest
	target := forcedTarget
	targetIsReady := false
	var targetReady <-chan error
	var cancelTargetReady context.CancelFunc
	var lateConfiguration <-chan devConfigurationResult
	if target == "" {
		registrationTimeout := min(timeout, devRegistrationWait)
		configurationCtx, cancelConfiguration := context.WithTimeout(ctx, registrationTimeout)
		configured := awaitDevConfiguration(configurationCtx, bootstrap)
		select {
		case <-child.Done():
			cancelConfiguration()
			return devStartupResult{}, childResult(child.Err())
		case configuredResult := <-configured:
			cancelConfiguration()
			if configuredResult.err != nil {
				if errors.Is(configuredResult.err, context.DeadlineExceeded) {
					return devStartupResult{}, diagnostic.WrapMessage(
						diagnostic.FrameworkRegistrationTimeout,
						"development server did not connect to tnl; configure the Next.js or Vite integration, call tnl.register(server) for Node or Bun, or use --port",
						configuredResult.err,
					)
				}
				return devStartupResult{}, configuredResult.err
			}
			configuration = &configuredResult.configuration
		case <-ctx.Done():
			cancelConfiguration()
			return devStartupResult{}, context.Cause(ctx)
		}
	} else {
		configured := awaitDevConfiguration(ctx, bootstrap)
		startupCtx, cancelStartup := context.WithTimeout(ctx, timeout)
		cancelTargetReady = cancelStartup
		defer cancelTargetReady()
		ready := make(chan error, 1)
		targetReady = ready
		go func() { ready <- localproxy.WaitForTarget(startupCtx, target) }()
		select {
		case <-child.Done():
			return devStartupResult{}, childResult(child.Err())
		case configuredResult := <-configured:
			cancelTargetReady()
			targetReady = nil
			if configuredResult.err != nil {
				return devStartupResult{}, configuredResult.err
			}
			configuration = &configuredResult.configuration
		case err := <-targetReady:
			cancelTargetReady()
			if err != nil {
				return devStartupResult{}, devTargetWaitError(target, err)
			}
			targetIsReady = true
			lateConfiguration = configured
		case <-ctx.Done():
			return devStartupResult{}, context.Cause(ctx)
		}
	}

	framework := ""
	completeConfiguration := func(configuration devConfigurationRequest) (string, error) {
		bootstrap.Resolve(assignment, nil)
		targetCtx, cancelTarget := context.WithTimeout(ctx, timeout)
		reported, err := waitForDevTarget(targetCtx, bootstrap, child)
		cancelTarget()
		if err != nil {
			if errors.Is(err, context.DeadlineExceeded) {
				return "", diagnostic.WrapMessage(
					diagnostic.FrameworkRegistrationTimeout,
					"development server did not report its listening target before the startup timeout",
					err,
				)
			}
			return "", err
		}
		if err := tunnel.SetDevTarget(ctx, configuration.Framework, reported.Target); err != nil {
			return "", err
		}
		return reported.Target, nil
	}
	if configuration != nil {
		framework = configuration.Framework
		var err error
		target, err = completeConfiguration(*configuration)
		if err != nil {
			return devStartupResult{}, err
		}
	}

	var frameworkDone <-chan devFrameworkResult
	if lateConfiguration != nil {
		done := make(chan devFrameworkResult, 1)
		frameworkDone = done
		go func() {
			configuredResult := <-lateConfiguration
			if configuredResult.err != nil {
				done <- devFrameworkResult{err: configuredResult.err}
				return
			}
			reportedTarget, err := completeConfiguration(configuredResult.configuration)
			done <- devFrameworkResult{
				framework: configuredResult.configuration.Framework,
				target:    reportedTarget,
				err:       err,
			}
		}()
	}

	if !targetIsReady {
		if targetReady == nil {
			startupCtx, cancelStartup := context.WithTimeout(ctx, timeout)
			defer cancelStartup()
			ready := make(chan error, 1)
			targetReady = ready
			go func() { ready <- localproxy.WaitForTarget(startupCtx, target) }()
		}
		select {
		case <-child.Done():
			return devStartupResult{}, childResult(child.Err())
		case err := <-targetReady:
			if err != nil {
				return devStartupResult{}, devTargetWaitError(target, err)
			}
		case <-ctx.Done():
			return devStartupResult{}, context.Cause(ctx)
		}
	}
	return devStartupResult{target: target, framework: framework, frameworkDone: frameworkDone}, nil
}

func devTargetWaitError(target string, err error) error {
	if errors.Is(err, context.DeadlineExceeded) {
		return diagnostic.WrapMessage(
			diagnostic.TargetUnavailable,
			fmt.Sprintf("development server did not listen on %s before the startup timeout", target),
			err,
		)
	}
	return err
}

type devConfigurationResult struct {
	configuration devConfigurationRequest
	err           error
}

// the buffered result lets startup select child exit or target readiness first.
// configuration exits when its context is canceled or the bootstrap closes.
func awaitDevConfiguration(ctx context.Context, bootstrap *devBootstrap) <-chan devConfigurationResult {
	configured := make(chan devConfigurationResult, 1)
	go func() {
		configuration, err := bootstrap.Configuration(ctx)
		configured <- devConfigurationResult{configuration: configuration, err: err}
	}()
	return configured
}

type devFrameworkResult struct {
	framework string
	target    string
	err       error
}

type devTargetResult struct {
	target devTargetRequest
	err    error
}

func waitForDevTarget(ctx context.Context, bootstrap *devBootstrap, child *devProcess) (devTargetRequest, error) {
	targeted := make(chan devTargetResult, 1)
	go func() {
		target, err := bootstrap.Target(ctx)
		targeted <- devTargetResult{target: target, err: err}
	}()
	select {
	case <-child.Done():
		if err := childResult(child.Err()); err != nil {
			return devTargetRequest{}, err
		}
		return devTargetRequest{}, errors.New("development server command exited before target registration")
	case result := <-targeted:
		return result.target, result.err
	case <-ctx.Done():
		return devTargetRequest{}, context.Cause(ctx)
	}
}

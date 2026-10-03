package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os/exec"
	"runtime"
	"time"
)

const browserDNSWait = 2 * time.Minute

func browserOpener(ctx context.Context, enabled, dnsAutomation bool) func(string) error {
	if !enabled {
		return nil
	}
	return func(target string) error {
		if dnsAutomation {
			parsed, err := url.Parse(target)
			if err != nil || parsed.Hostname() == "" {
				return errors.New("public URL has no valid hostname")
			}
			dnsCtx, cancel := context.WithTimeout(ctx, browserDNSWait)
			defer cancel()
			if err := waitForBrowserDNS(dnsCtx, parsed.Hostname(), net.DefaultResolver.LookupIPAddr, time.Second); err != nil {
				return err
			}
		}
		return openBrowser(target)
	}
}

func waitForBrowserDNS(ctx context.Context, hostname string, lookup func(context.Context, string) ([]net.IPAddr, error), interval time.Duration) error {
	for {
		addresses, err := lookup(ctx, hostname)
		if err == nil && len(addresses) != 0 {
			return nil
		}
		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return fmt.Errorf("public URL DNS for %s is not available on this computer: %w", hostname, errors.Join(ctx.Err(), err))
		case <-timer.C:
		}
	}
}

func openBrowser(target string) error {
	executable, arguments, err := browserCommand(runtime.GOOS, target)
	if err != nil {
		return err
	}
	command := exec.Command(executable, arguments...)
	if err := command.Start(); err != nil {
		return err
	}
	go func() { _ = command.Wait() }()
	return nil
}

func browserCommand(goos, target string) (string, []string, error) {
	switch goos {
	case "darwin":
		return "open", []string{target}, nil
	case "linux":
		return "xdg-open", []string{target}, nil
	default:
		return "", nil, errors.New("opening a browser is not supported on this platform")
	}
}

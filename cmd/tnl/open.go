package main

import (
	"errors"
	"os/exec"
	"runtime"
)

func browserOpener(enabled bool) func(string) error {
	if !enabled {
		return nil
	}
	return openBrowser
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

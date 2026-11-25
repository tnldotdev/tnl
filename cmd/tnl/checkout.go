package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"

	"github.com/tnldotdev/tnl/internal/failure"
)

type checkoutKey struct{}

func resolveCheckout(path string) (string, error) {
	if path == "" {
		return "", nil
	}
	abs, err := filepath.Abs(path)
	if err == nil {
		abs, err = filepath.EvalSymlinks(abs)
	}
	if err == nil {
		var info os.FileInfo
		info, err = os.Stat(abs)
		if err == nil && !info.IsDir() {
			err = errors.New("not a directory")
		}
	}
	if err != nil {
		return "", failure.Wrap("select checkout", failure.CurrentDirectoryUnavailable, err)
	}
	return abs, nil
}

func withCheckout(ctx context.Context, root string) context.Context {
	if root == "" {
		return ctx
	}
	return context.WithValue(ctx, checkoutKey{}, root)
}

func selectedCheckout(ctx context.Context) string {
	root, _ := ctx.Value(checkoutKey{}).(string)
	return root
}

func invocationDirectory(ctx context.Context) (string, error) {
	if root := selectedCheckout(ctx); root != "" {
		return root, nil
	}
	dir, err := os.Getwd()
	return dir, failure.Wrap("read working directory", failure.CurrentDirectoryUnavailable, err)
}

func checkoutArgv(ctx context.Context, args ...string) []string {
	command := append([]string{"tnl"}, checkoutFlags(selectedCheckout(ctx))...)
	return append(command, args...)
}

func checkoutFlags(root string) []string {
	if root == "" {
		return nil
	}
	return []string{"--cwd", root}
}

func checkoutCommand(ctx context.Context, args ...string) string {
	return guidanceCommand(checkoutArgv(ctx, args...))
}

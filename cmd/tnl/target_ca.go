package main

import (
	"path/filepath"

	"github.com/tnldotdev/tnl/internal/localproxy"
)

func targetOptionsForCA(path, projectRoot string) (localproxy.TargetOptions, error) {
	if path == "" {
		return localproxy.TargetOptions{}, nil
	}
	if !filepath.IsAbs(path) {
		path = filepath.Join(projectRoot, path)
	}
	roots, err := localproxy.LoadTargetRootCAs(path)
	if err != nil {
		return localproxy.TargetOptions{}, err
	}
	return localproxy.TargetOptions{RootCAs: roots}, nil
}

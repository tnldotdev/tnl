package proxy

import (
	"path/filepath"
)

func TargetOptionsForCA(path, projectRoot string) (TargetOptions, error) {
	if path == "" {
		return TargetOptions{}, nil
	}
	if !filepath.IsAbs(path) {
		path = filepath.Join(projectRoot, path)
	}
	roots, err := LoadTargetRootCAs(path)
	if err != nil {
		return TargetOptions{}, err
	}
	return TargetOptions{RootCAs: roots}, nil
}

package main

import (
	"github.com/tnldotdev/tnl/internal/localpublisher"

	"github.com/tnldotdev/tnl/internal/localproxy"
)

func targetOptionsForCA(path, projectRoot string) (localproxy.TargetOptions, error) {
	return localpublisher.TargetOptionsForCA(path, projectRoot)
}

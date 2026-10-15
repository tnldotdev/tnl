package main

import "github.com/tnldotdev/tnl/internal/publishertarget"

func init() {
	runtimeTargetResolver = publishertarget.Resolver{}
}

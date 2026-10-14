package main

import (
	"context"

	"github.com/tnldotdev/tnl/internal/clientstate"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/localpublisher"
	"github.com/tnldotdev/tnl/internal/publisher"
)

func inspectionRoots(ctx context.Context, project string) (string, string, error) {
	return localpublisher.InspectionRoots(ctx, project)
}
func newInspectionRecorder(ctx context.Context, tunnel *clientstate.Tunnel, project, service string, flags tunnelFlags) (*clientstate.InspectionRecorder, error) {
	return localpublisher.NewInspectionRecorder(ctx, tunnel, project, service, flags.settings())
}
func httpObservation(recorder *clientstate.InspectionRecorder) func(publisher.RequestObservation) {
	return localpublisher.HTTPObservation(recorder)
}
func sqlObservation(recorder *clientstate.InspectionRecorder, mode config.InspectionMode) func(publisher.DatabaseObservation) {
	return localpublisher.SQLObservation(recorder, mode)
}

func redisObservation(recorder *clientstate.InspectionRecorder) func(publisher.RedisObservation) {
	return localpublisher.RedisObservation(recorder)
}

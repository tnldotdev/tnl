package main

import (
	"github.com/tnldotdev/tnl/internal/clientstate"
	"github.com/tnldotdev/tnl/internal/publisher"
)

func requestObservation(recorder *clientstate.RequestRecorder) func(publisher.RequestObservation) {
	return func(event publisher.RequestObservation) {
		recorder.Observe(clientstate.RequestRecord{
			ReceivedAt: event.ReceivedAt, Method: event.Method, Path: event.Path,
			Status: event.Status, DurationMS: event.Duration.Milliseconds(), Origin: event.Origin,
		})
	}
}

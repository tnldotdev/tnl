package peer

import "time"

type ConnectivityState string

const (
	ConnectivityChecking ConnectivityState = "checking"
	ConnectivityDirect   ConnectivityState = "direct"
	ConnectivityRelay    ConnectivityState = "relay"
)

// connectivity settings belong to the socket owner, never an application opening.
type ConnectivityOptions struct {
	DisableDirect   bool
	IncludeLoopback bool
	Observe         func(ConnectivityState)
	ObserveAttempt  func(ConnectivityAttempt)
	ObserveFallback func()
}

type ConnectivityAttempt struct {
	Outcome  string
	Duration time.Duration
}

type ConnectivityBinding struct {
	Revision       BindingRevision
	DeliveryID     string
	RelayAddresses [2]string
}

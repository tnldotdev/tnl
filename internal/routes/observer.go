package routes

import "time"

type StoreOperation string

const (
	StoreOperationHostnameClaim     StoreOperation = "hostname_claim"
	StoreOperationHostnameRelease   StoreOperation = "hostname_release"
	StoreOperationRouteCreate       StoreOperation = "route_create"
	StoreOperationRouteAcquire      StoreOperation = "route_acquire"
	StoreOperationTransportRegister StoreOperation = "transport_register"
	StoreOperationRouteReady        StoreOperation = "route_ready"
	StoreOperationLeaseHeartbeat    StoreOperation = "lease_heartbeat"
	StoreOperationLeaseExpire       StoreOperation = "lease_expire"
	StoreOperationLeaseAuthenticate StoreOperation = "lease_authenticate"
)

type StoreObserver func(operation StoreOperation, duration time.Duration, err error)

type HeartbeatResult string

const (
	HeartbeatResultSuccess  HeartbeatResult = "success"
	HeartbeatResultRejected HeartbeatResult = "rejected"
	HeartbeatResultError    HeartbeatResult = "error"
)

type RouteRemovalReason string

const (
	RouteRemovalClaimReleased     RouteRemovalReason = "claim_released"
	RouteRemovalDeleted           RouteRemovalReason = "deleted"
	RouteRemovalLeaseExpired      RouteRemovalReason = "lease_expired"
	RouteRemovalOwnerDisconnected RouteRemovalReason = "owner_disconnected"
	RouteRemovalOwnerDraining     RouteRemovalReason = "owner_draining"
	RouteRemovalReplaced          RouteRemovalReason = "replaced"
)

type CoordinatorConfig struct {
	ObserveHeartbeat               func(HeartbeatResult)
	ObserveRouteRemoval            func(RouteRemovalReason)
	ObserveWorkerCapacityRejection func()
}

type HealthStats struct {
	Provisioning                    int
	Active                          int
	ConnectedOwners                 int
	MinimumProvisioningLeaseSeconds float64
	MinimumActiveLeaseSeconds       float64
}

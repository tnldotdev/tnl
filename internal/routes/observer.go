package routes

import (
	"context"
	"time"
)

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

type CoordinatorStage string

const (
	CoordinatorStageTransportRouteLockWait CoordinatorStage = "transport_route_lock_wait"
	CoordinatorStageTransportWorkerAttach  CoordinatorStage = "transport_worker_attach"
	CoordinatorStageReadyRouteLockWait     CoordinatorStage = "ready_route_lock_wait"
	CoordinatorStageReadyPublish           CoordinatorStage = "ready_publish"
	CoordinatorStageHeartbeatRouteLockWait CoordinatorStage = "heartbeat_route_lock_wait"
	CoordinatorStageHeartbeatStateUpdate   CoordinatorStage = "heartbeat_state_update"
)

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
	PublicationReady               func(context.Context, string) error
	ObserveHeartbeat               func(HeartbeatResult)
	ObserveRouteRemoval            func(RouteRemovalReason)
	ObserveWorkerCapacityRejection func()
	ObserveStage                   func(CoordinatorStage, time.Duration)
}

type HealthStats struct {
	Provisioning                    int
	Active                          int
	ConnectedOwners                 int
	MinimumProvisioningLeaseSeconds float64
	MinimumActiveLeaseSeconds       float64
}

package routes

import (
	"context"
	"time"
)

type StoreOperation string

const (
	StoreOperationHostnameClaim       StoreOperation = "hostname_claim"
	StoreOperationHostnameRelease     StoreOperation = "hostname_release"
	StoreOperationRouteCreate         StoreOperation = "route_create"
	StoreOperationSessionCreate       StoreOperation = "session_create"
	StoreOperationTransportRegister   StoreOperation = "transport_register"
	StoreOperationRouteReady          StoreOperation = "route_ready"
	StoreOperationSessionHeartbeat    StoreOperation = "session_heartbeat"
	StoreOperationSessionExpire       StoreOperation = "session_expire"
	StoreOperationSessionAuthenticate StoreOperation = "session_authenticate"
)

type StoreObserver func(operation StoreOperation, duration time.Duration, err error)

type CoordinatorStage string

const (
	CoordinatorStageTransportRouteLockWait CoordinatorStage = "transport_route_lock_wait"
	CoordinatorStageTransportWorkerAttach  CoordinatorStage = "transport_worker_attach"
	CoordinatorStageReadyRouteLockWait     CoordinatorStage = "ready_route_lock_wait"
	CoordinatorStageReadyPublish           CoordinatorStage = "ready_publish"
	CoordinatorStageHeartbeatRouteLockWait CoordinatorStage = "heartbeat_route_lock_wait"
	CoordinatorStageHeartbeatPersistence   CoordinatorStage = "heartbeat_persistence"
)

type HeartbeatResult string

const (
	HeartbeatResultSuccess  HeartbeatResult = "success"
	HeartbeatResultRejected HeartbeatResult = "rejected"
	HeartbeatResultError    HeartbeatResult = "error"
)

type RouteRemovalReason string

const (
	RouteRemovalHostnameRemoved      RouteRemovalReason = "hostname_removed"
	RouteRemovalDeleted              RouteRemovalReason = "deleted"
	RouteRemovalSessionExpired       RouteRemovalReason = "session_expired"
	RouteRemovalWorkerDisconnected   RouteRemovalReason = "worker_disconnected"
	RouteRemovalWorkerDraining       RouteRemovalReason = "worker_draining"
	RouteRemovalRouteVersionReplaced RouteRemovalReason = "route_version_replaced"
	RouteRemovalSuspended            RouteRemovalReason = "suspended"
	RouteRemovalHostnameQuarantined  RouteRemovalReason = "hostname_quarantined"
)

type CoordinatorConfig struct {
	CheckHostnamePublishability    func(context.Context, string) error
	ObserveHeartbeat               func(HeartbeatResult)
	ObserveRouteRemoval            func(RouteRemovalReason)
	ObserveWorkerCapacityRejection func()
	ObserveStage                   func(CoordinatorStage, time.Duration)
}

type HealthStats struct {
	Provisioning                      int
	Routable                          int
	ConnectedWorkers                  int
	MinimumProvisioningSessionSeconds float64
	MinimumRoutableSessionSeconds     float64
}

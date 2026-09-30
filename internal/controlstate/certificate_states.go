package controlstate

// ACMEOrderState is the persisted stage of one public URL certificate issuance.
// certificate availability and publisher installation are separate transitions.
type ACMEOrderState string

const (
	ACMEOrderPending           ACMEOrderState = "pending"
	ACMEOrderAuthorizing       ACMEOrderState = "authorizing"
	ACMEOrderReadyToFinalize   ACMEOrderState = "ready_to_finalize"
	ACMEOrderFinalizing        ACMEOrderState = "finalizing"
	ACMEOrderWaitingForInstall ACMEOrderState = "waiting_for_install"
	ACMEOrderInstalled         ACMEOrderState = "installed"
	ACMEOrderFailed            ACMEOrderState = "failed"
	ACMEOrderCanceled          ACMEOrderState = "canceled"
)

func (state ACMEOrderState) valid() bool {
	switch state {
	case ACMEOrderPending, ACMEOrderAuthorizing, ACMEOrderReadyToFinalize, ACMEOrderFinalizing,
		ACMEOrderWaitingForInstall, ACMEOrderInstalled, ACMEOrderFailed, ACMEOrderCanceled:
		return true
	default:
		return false
	}
}

// ACMEAuthorizationState is the persisted stage for one identifier in an order.
// cleaning records intent before a DNS provider call; complete records cleanup.
type ACMEAuthorizationState string

const (
	ACMEAuthorizationPending    ACMEAuthorizationState = "pending"
	ACMEAuthorizationPresenting ACMEAuthorizationState = "presenting"
	ACMEAuthorizationPresented  ACMEAuthorizationState = "presented"
	ACMEAuthorizationValidating ACMEAuthorizationState = "validating"
	ACMEAuthorizationValid      ACMEAuthorizationState = "valid"
	ACMEAuthorizationCleaning   ACMEAuthorizationState = "cleaning"
	ACMEAuthorizationComplete   ACMEAuthorizationState = "complete"
	ACMEAuthorizationFailed     ACMEAuthorizationState = "failed"
	ACMEAuthorizationCanceled   ACMEAuthorizationState = "canceled"
)

func (state ACMEAuthorizationState) valid() bool {
	switch state {
	case ACMEAuthorizationPending, ACMEAuthorizationPresenting, ACMEAuthorizationPresented,
		ACMEAuthorizationValidating, ACMEAuthorizationValid, ACMEAuthorizationCleaning,
		ACMEAuthorizationComplete, ACMEAuthorizationFailed, ACMEAuthorizationCanceled:
		return true
	default:
		return false
	}
}

// RelayCertificateOrderState is the persisted stage of relay transport certificate issuance.
// cleaning precedes installation; failed_cleaning preserves cleanup after failure.
type RelayCertificateOrderState string

const (
	RelayCertificatePending         RelayCertificateOrderState = "pending"
	RelayCertificateAuthorizing     RelayCertificateOrderState = "authorizing"
	RelayCertificatePresenting      RelayCertificateOrderState = "presenting"
	RelayCertificatePresented       RelayCertificateOrderState = "presented"
	RelayCertificateValidating      RelayCertificateOrderState = "validating"
	RelayCertificateReadyToFinalize RelayCertificateOrderState = "ready_to_finalize"
	RelayCertificateFinalizing      RelayCertificateOrderState = "finalizing"
	RelayCertificateCleaning        RelayCertificateOrderState = "cleaning"
	RelayCertificateFailedCleaning  RelayCertificateOrderState = "failed_cleaning"
	RelayCertificateComplete        RelayCertificateOrderState = "complete"
	RelayCertificateFailed          RelayCertificateOrderState = "failed"
)

func (state RelayCertificateOrderState) valid() bool {
	switch state {
	case RelayCertificatePending, RelayCertificateAuthorizing, RelayCertificatePresenting,
		RelayCertificatePresented, RelayCertificateValidating, RelayCertificateReadyToFinalize,
		RelayCertificateFinalizing, RelayCertificateCleaning, RelayCertificateFailedCleaning,
		RelayCertificateComplete, RelayCertificateFailed:
		return true
	default:
		return false
	}
}

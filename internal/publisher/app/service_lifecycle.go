package app

import "time"

// these transitions operate on the unchanged journal DTO, not a second model.
// registration, publication, and readiness are independent axes. the manager
// owns locking, live-owner fences, cancel/join ordering, and atomic journal writes.
type reservedRegistration struct {
	id, publicURL string
}

type boundListener struct {
	target, framework string
}

// PublicationUpdate carries completed worker facts to the existing publication
// transition. the manager's callback supplies the registration and worker fence.
type PublicationUpdate struct {
	RunNumber uint64
	Routable  bool
	TunnelID  string
	Target    string
	PublicURL string
}

func (s *Service) reserve(registration reservedRegistration) {
	s.invalidateRegistration()
	s.RegistrationID, s.PublicURL = registration.id, registration.publicURL
	s.Target, s.Framework, s.TunnelID = "", "", ""
	s.RunNumber, s.ProvisioningStage, s.Failure = 0, "", ""
}

func (s *Service) bindListener(listener boundListener) error {
	if s.RegistrationID == "" {
		return ErrRegistrationStale
	}
	s.endPublication()
	s.Registered = true
	s.Target, s.Framework, s.Failure = listener.target, listener.framework, ""
	s.RunNumber = 0
	return nil
}

// invalidation fences callbacks before cancellation. keep identity and run facts
// until the old worker has joined; replacement and stale snapshots keep the stage.
func (s *Service) invalidateRegistration() {
	s.Registered, s.Routable = false, false
	s.invalidateReadiness()
}

// release follows invalidation and the worker join, never the other way around.
func (s *Service) releaseRegistration() {
	s.RegistrationID, s.Target, s.TunnelID = "", "", ""
	s.RunNumber, s.Framework = 0, ""
}

// a stopped or failed publication does not release the application's listener.
func (s *Service) endPublication() {
	s.Routable, s.ProvisioningStage = false, ""
	s.invalidateReadiness()
}

func (s *Service) publish(update PublicationUpdate) (becameRoutable bool, err error) {
	if !s.Registered || update.RunNumber == 0 || update.RunNumber < s.RunNumber ||
		update.TunnelID != s.TunnelID || update.Target != s.Target {
		return false, ErrRegistrationStale
	}
	newRun := update.RunNumber != s.RunNumber
	if newRun || !update.Routable {
		s.invalidateReadiness()
		if newRun {
			s.ProvisioningStage = ""
		}
	}
	becameRoutable = update.Routable && (!s.Routable || newRun)
	s.RunNumber, s.Routable = update.RunNumber, update.Routable
	if update.Routable {
		s.PublicURL = update.PublicURL
		s.Failure, s.ProvisioningStage = "", ""
	}
	return becameRoutable, nil
}

func (s *Service) invalidateReadiness() {
	s.Ready, s.Observation = false, nil
}

func (s *Service) acceptObservation(observation Observation) bool {
	if !s.Registered || !s.Routable || observation.RunNumber == 0 ||
		s.RegistrationID != observation.RegistrationID || s.RunNumber != observation.RunNumber ||
		s.Readiness != observation.Readiness || observation.Target == "" || s.Target != observation.Target {
		return false
	}
	if s.Observation != nil && observation.CheckedAt.Before(s.Observation.CheckedAt) {
		return false
	}
	s.Ready, s.Observation = observation.Ready, &observation
	return true
}

func (s *Service) invalidateTarget(at time.Time) bool {
	if !s.Registered || !s.Routable {
		return false
	}
	s.Ready = false
	s.Observation = &Observation{Target: s.Target, RegistrationID: s.RegistrationID, RunNumber: s.RunNumber, Readiness: s.Readiness, CheckedAt: at, Reason: "runtime.target_changed"}
	return true
}

package app

import (
	"errors"
	"reflect"
	"testing"
	"time"
)

func readyLifecycleService() Service {
	readiness := Readiness{Path: "/health"}
	return Service{
		Name: "web", Directory: "app", ServiceProtocol: "http", PublicURL: "https://web.example",
		RegistrationID: "reg_current", Target: "http://127.0.0.1:3000", Framework: "node", TunnelID: "tunnel_current",
		Registered: true, Routable: true, Ready: true, RunNumber: 7, Readiness: readiness,
		Observation: &Observation{RegistrationID: "reg_current", Target: "http://127.0.0.1:3000", RunNumber: 7, Readiness: readiness, Ready: true, CheckedAt: time.Unix(100, 0).UTC()},
	}
}

func TestServiceRegistrationTransitions(t *testing.T) {
	ready := readyLifecycleService()
	configured := Service{Name: ready.Name, Directory: ready.Directory, ServiceProtocol: ready.ServiceProtocol, Readiness: ready.Readiness}
	reserved := configured
	reserved.RegistrationID, reserved.PublicURL = "reg_next", ready.PublicURL
	bound := reserved
	bound.Registered, bound.Target, bound.Framework = true, ready.Target, ready.Framework
	invalidated := ready
	invalidated.Registered, invalidated.Routable, invalidated.Ready, invalidated.Observation = false, false, false, nil
	stopped := invalidated
	stopped.Registered = true
	released := configured
	released.PublicURL = ready.PublicURL
	provisioning := stopped
	provisioning.ProvisioningStage, provisioning.Failure = "certificate", "runtime.provisioning_stalled"
	invalidatedProvisioning := provisioning
	invalidatedProvisioning.Registered = false
	endedProvisioning := provisioning
	endedProvisioning.ProvisioningStage = ""

	for _, test := range []struct {
		name       string
		before     Service
		transition func(*Service) error
		want       Service
		wantErr    error
	}{
		{"reserve without claiming a listener", ready, func(s *Service) error {
			s.reserve(reservedRegistration{id: "reg_next", publicURL: ready.PublicURL})
			return nil
		}, reserved, nil},
		{"reserve clears old stage and warning", provisioning, func(s *Service) error {
			s.reserve(reservedRegistration{id: "reg_next", publicURL: ready.PublicURL})
			return nil
		}, reserved, nil},
		{"bind requires reservation", configured, func(s *Service) error {
			return s.bindListener(boundListener{target: ready.Target, framework: ready.Framework})
		}, configured, ErrRegistrationStale},
		{"bind before provisioning", reserved, func(s *Service) error {
			return s.bindListener(boundListener{target: ready.Target, framework: ready.Framework})
		}, bound, nil},
		{"publication stop retains listener and run", ready, func(s *Service) error {
			s.endPublication()
			return nil
		}, stopped, nil},
		{"invalidation retains identity until join", ready, func(s *Service) error {
			s.invalidateRegistration()
			return nil
		}, invalidated, nil},
		{"invalidation retains provisioning stage", provisioning, func(s *Service) error {
			s.invalidateRegistration()
			return nil
		}, invalidatedProvisioning, nil},
		{"publication end clears stage but keeps warning", provisioning, func(s *Service) error {
			s.endPublication()
			return nil
		}, endedProvisioning, nil},
		{"release retains saved public url", invalidated, func(s *Service) error {
			s.releaseRegistration()
			return nil
		}, released, nil},
	} {
		t.Run(test.name, func(t *testing.T) {
			service := test.before
			if err := test.transition(&service); !errors.Is(err, test.wantErr) {
				t.Fatalf("transition error = %v, want %v", err, test.wantErr)
			}
			if !reflect.DeepEqual(service, test.want) {
				t.Fatalf("transition = %+v, want %+v", service, test.want)
			}
		})
	}
}

func TestServicePublicationTransitions(t *testing.T) {
	ready := readyLifecycleService()
	provisioning := ready
	provisioning.Routable, provisioning.Ready, provisioning.Observation = false, false, nil
	provisioning.ProvisioningStage, provisioning.Failure = "certificate", "runtime.provisioning_stalled"
	reserved := provisioning
	reserved.Registered = false
	for _, test := range []struct {
		name     string
		before   Service
		update   publicationUpdate
		became   bool
		stale    bool
		run      uint64
		routable bool
		ready    bool
		stage    string
		failure  string
	}{
		{"reservation cannot publish", reserved, publicationUpdate{8, true}, false, true, 0, false, false, "", ""},
		{"zero run rejected", ready, publicationUpdate{0, true}, false, true, 0, false, false, "", ""},
		{"old run rejected", ready, publicationUpdate{6, true}, false, true, 0, false, false, "", ""},
		{"duplicate routable keeps readiness", ready, publicationUpdate{7, true}, false, false, 7, true, true, "", ""},
		{"drain invalidates readiness", ready, publicationUpdate{7, false}, false, false, 7, false, false, "", ""},
		{"same provisioning run keeps stage and warning", provisioning, publicationUpdate{7, false}, false, false, 7, false, false, "certificate", "runtime.provisioning_stalled"},
		{"new provisioning run clears stage but keeps warning", provisioning, publicationUpdate{8, false}, false, false, 8, false, false, "", "runtime.provisioning_stalled"},
		{"routable clears stage and warning", provisioning, publicationUpdate{7, true}, true, false, 7, true, false, "", ""},
		{"new routable run needs its own observation", ready, publicationUpdate{8, true}, true, false, 8, true, false, "", ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			service := test.before
			became, err := service.publish(test.update)
			if became != test.became || (test.stale && !errors.Is(err, ErrRegistrationStale)) || (!test.stale && err != nil) {
				t.Fatalf("publish = %v, %v", became, err)
			}
			want := test.before
			if !test.stale {
				want.RunNumber, want.Routable, want.Ready = test.run, test.routable, test.ready
				want.ProvisioningStage, want.Failure = test.stage, test.failure
				if !test.ready {
					want.Observation = nil
				}
			}
			if !reflect.DeepEqual(service, want) {
				t.Fatalf("publish = %+v, want %+v", service, want)
			}
		})
	}
}

func TestServiceReadinessTransitions(t *testing.T) {
	ready := readyLifecycleService()
	for _, test := range []struct {
		name   string
		change func(*Service, *Observation)
		accept bool
	}{
		{"success", func(*Service, *Observation) {}, true},
		{"readiness failure keeps routability", func(_ *Service, o *Observation) { o.Ready, o.Reason = false, "runtime.probe_failed" }, true},
		{"optional target remains compatible", func(_ *Service, o *Observation) { o.Target = "" }, true},
		{"unregistered", func(s *Service, _ *Observation) { s.Registered = false }, false},
		{"unroutable", func(s *Service, _ *Observation) { s.Routable = false }, false},
		{"zero run", func(s *Service, o *Observation) { s.RunNumber, o.RunNumber = 0, 0 }, false},
		{"old registration", func(_ *Service, o *Observation) { o.RegistrationID = "reg_old" }, false},
		{"old run", func(_ *Service, o *Observation) { o.RunNumber-- }, false},
		{"changed target", func(_ *Service, o *Observation) { o.Target = "http://127.0.0.1:3001" }, false},
		{"changed path", func(_ *Service, o *Observation) { o.Readiness.Path = "/old" }, false},
		{"older result", func(_ *Service, o *Observation) { o.CheckedAt = o.CheckedAt.Add(-time.Second) }, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			service, observation := ready, *ready.Observation
			test.change(&service, &observation)
			want := service
			if test.accept {
				want.Ready, want.Observation = observation.Ready, &observation
			}
			if got := service.acceptObservation(observation); got != test.accept {
				t.Fatalf("accepted = %v, want %v", got, test.accept)
			}
			if !reflect.DeepEqual(service, want) {
				t.Fatalf("observation changed other axes: %+v, want %+v", service, want)
			}
		})
	}
}

func TestServiceTargetInvalidationKeepsRunAndRejectsEarlierProbe(t *testing.T) {
	service := readyLifecycleService()
	oldProbe := *service.Observation
	at := oldProbe.CheckedAt.Add(time.Second)
	if !service.invalidateTarget(at) || service.Ready || !service.Registered || !service.Routable || service.RunNumber != 7 || service.Observation.Reason != "runtime.target_changed" || service.Observation.CheckedAt != at {
		t.Fatal("target invalidation changed publication or lost its observation", service)
	}
	if service.acceptObservation(oldProbe) {
		t.Fatal("probe started before target invalidation restored readiness")
	}
	for _, axis := range []string{"registration", "publication"} {
		t.Run(axis, func(t *testing.T) {
			service := readyLifecycleService()
			if axis == "registration" {
				service.Registered = false
			} else {
				service.Routable = false
			}
			before := service
			if service.invalidateTarget(at) || !reflect.DeepEqual(service, before) {
				t.Fatal("inactive target accepted invalidation", service)
			}
		})
	}
}

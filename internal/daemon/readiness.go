package daemon

import (
	"context"
	"errors"
	"fmt"
	"time"

	daemonconfig "github.com/tnldotdev/tnl/internal/daemon/config"
)

func (d *daemon) ready(ctx context.Context, role daemonconfig.Role, now time.Time) error {
	if d.draining.Load() {
		return errors.New("process is draining")
	}
	if role.RunsControl() {
		if d.database == nil {
			return errors.New("control database is not ready")
		}
		if err := d.database.Readiness(ctx); err != nil {
			return err
		}
		if err := d.readyControl(role, now); err != nil {
			return err
		}
		if err := d.checkRoute53Credentials(ctx); err != nil {
			return err
		}
	}
	if role.RunsIngress() {
		if err := d.readyIngress(now); err != nil {
			return err
		}
	}
	if role.RunsRelay() {
		if err := d.readyRelays(role, now); err != nil {
			return err
		}
	}
	return nil
}

func (d *daemon) readyControl(role daemonconfig.Role, now time.Time) error {
	if d.draining.Load() {
		return errors.New("control is draining")
	}
	if d.controlServer == nil || d.controlListener == nil {
		return errors.New("control listener is not ready")
	}
	if role == daemonconfig.RoleControl && (d.privateControlServer == nil || d.privateControlListener == nil) {
		return errors.New("private control listener is not ready")
	}
	return nil
}

func (d *daemon) readyIngress(now time.Time) error {
	if len(d.ingresses) < 1 || len(d.ingresses) > 2 {
		return errors.New("ingress runtime is not ready")
	}
	public := 0
	for _, runtime := range d.ingresses {
		if runtime.controller == nil || !runtime.controller.Ready(now) || !runtime.privateOnly && (runtime.server == nil || !runtime.server.Ready()) {
			return errors.New("ingress lease, routing table, certificate, or listener is not ready")
		}
		if runtime.serviceCertificate != nil && !runtime.serviceCertificate.ready(now) {
			return errors.New("private ingress transport certificate is not ready")
		}
		if !runtime.privateOnly {
			public++
		}
	}
	if public != 1 {
		return errors.New("public ingress listener is not ready")
	}
	return nil
}

func (d *daemon) readyRelays(role daemonconfig.Role, now time.Time) error {
	expected := 1
	if role == daemonconfig.RoleStandalone {
		expected = len(standaloneRelays)
	}
	if len(d.relays) != expected {
		return errors.New("relay runtimes are not ready")
	}
	for _, runtime := range d.relays {
		if runtime.controller == nil || !runtime.controller.Ready(now) || runtime.registry == nil || runtime.internalListener == nil {
			return errors.New("relay lease, certificate, or internal listener is not ready")
		}
	}
	physical := d.relays[0]
	if physical.tcpListener == nil || physical.udpListener == nil {
		return errors.New("relay publisher listeners are not ready")
	}
	return nil
}

func (d *daemon) checkRoute53Credentials(ctx context.Context) error {
	if d.route53Credentials == nil {
		return nil
	}
	checkCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	if _, err := d.route53Credentials.Retrieve(checkCtx); err != nil {
		return fmt.Errorf("retrieve Route 53 credentials: %w", err)
	}
	return nil
}

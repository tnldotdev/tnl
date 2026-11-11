package peer

import "time"

// CurrentBinding returns the revision and whether its packet delivery is active.
// a staged or suspended revision remains the high-water mark, not authority.
func (e *Endpoint) CurrentBinding() (BindingRevision, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.binding, e.bindingActive && e.ctx.Err() == nil
}

// InstallDirect transfers ownership even when the binding or slot rejects it.
// direct delivery belongs only to the exact active binding; replacement fences
// queued input and output without resetting the endpoint's replay history.
// a nil carrier may remove delivery for that same binding after suspension.
func (e *Endpoint) InstallDirect(binding BindingRevision, carrier Carrier) error {
	e.bindingMu.Lock()
	defer e.bindingMu.Unlock()
	e.mu.Lock()
	if e.ctx.Err() != nil || binding != e.binding || carrier != nil && !e.bindingActive || e.config.Direct == nil {
		e.mu.Unlock()
		if carrier != nil {
			_ = carrier.Close()
		}
		return ErrConfiguration
	}
	epoch := e.bindingEpoch
	e.paths[Direct].resetHealthLocked()
	e.chooseLocked()
	e.mu.Unlock()
	// carrier cleanup may join physical calls; it must not hold endpoint state.
	err := e.config.Direct.Install(carrier)
	e.mu.Lock()
	e.paths[Direct].refreshRevisionLocked()
	e.chooseLocked()
	// suspension must not wait for physical cleanup or this serialization lock.
	// if it won during installation, retire the attempt before returning.
	rejected := carrier != nil && (e.ctx.Err() != nil || !e.bindingActive || e.bindingEpoch != epoch)
	e.mu.Unlock()
	if rejected {
		_ = e.config.Direct.Install(nil)
		return ErrConfiguration
	}
	return err
}

func (e *Endpoint) directHealthyLocked(now time.Time) bool {
	p := e.paths[Direct]
	if p == nil || !e.bindingActive || e.ctx.Err() != nil {
		return false
	}
	p.refreshRevisionLocked()
	if p.failed || !p.alive || now.Sub(p.ack) > e.config.PathTimeout {
		return false
	}
	// check presence at selection, not just on the next probe tick. the slot
	// lock also covers removal that raced the revision refresh above.
	slot := e.config.Direct
	slot.mu.Lock()
	defer slot.mu.Unlock()
	if slot.closed || slot.current == nil || p.revision != (carrierRevision{slot: slot, revision: slot.revision}) {
		return false
	}
	if consent, ok := slot.current.carrier.(interface{ DirectConsent() bool }); ok {
		return consent.DirectConsent()
	}
	return true
}

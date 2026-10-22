package tnldruntime

import (
	"fmt"
)

func runtimeCapacity(name string, value int64) (int, error) {
	converted := int(value)
	if value <= 0 || int64(converted) != value {
		return 0, fmt.Errorf("%s capacity is out of range", name)
	}
	return converted, nil
}

// start supervises a component for the process lifetime. only its first exit
// determines the result of Serve; shutdown joins every component, including
// those that exit after the result has been selected.
func (d *daemon) start(name string, run func() error) {
	d.components.Go(func() {
		err := run()
		if err != nil {
			err = fmt.Errorf("%s: %w", name, err)
		}
		select {
		case d.componentDone <- err:
		default:
		}
	})
}

// background tracks work that can complete without ending the process, such
// as draining a relay after control updates its lease.
func (d *daemon) background(run func()) {
	d.components.Go(run)
}

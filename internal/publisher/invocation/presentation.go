package invocation

import (
	"github.com/tnldotdev/tnl/internal/clioutput"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/publisher/demo"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

// Progress carries semantic content; the command owns framing and its terminal.
type Progress struct {
	State   string
	Hint    string
	Details []clioutput.Block
}

type Presentation struct {
	Delegated           func()
	ConfigureBrowser    func(bool)
	Demo                func()
	GuestDemo           func()
	GuestShare          func(string)
	DemoPing            func(demo.State) error
	Logf                func(string, ...any)
	Starting            func(string, string) error
	Provisioning        func(string, uint64) error
	ProvisioningStalled func(uint64) error
	TransportFallback   func(uint64, string) error
	TargetUnavailable   func() error
	Draining            func() error
	Ready               func(string, uint64) error
	Resume              func(url, team, server string) error
	Stopped             func() error
	Progress            func(Progress) error
	Warning             func(string) error
}

func servicePresentation(output *ServicePresentation, saved controlv1.Service, target string) *Presentation {
	if output == nil {
		return &Presentation{}
	}
	emit := func(state string) error {
		if output.Event == nil {
			return nil
		}
		return output.Event(ServiceEvent{State: state, ServiceID: saved.Id, Name: saved.Name, Target: target,
			Hostname: saved.Endpoint.Hostname, Port: saved.Endpoint.Port, Protocol: string(saved.Protocol), Public: saved.Endpoint.Public})
	}
	return &Presentation{
		Starting: func(string, string) error {
			if output.Starting != nil {
				output.Starting()
			}
			return emit("starting")
		},
		Provisioning: func(string, uint64) error { return emit("provisioning") },
		Ready: func(string, uint64) error {
			if output.Ready != nil {
				output.Ready()
			}
			return emit("ready")
		},
		Stopped: func() error { return emit("stopped") },
	}
}

func (p *Presentation) configureBrowser(automated bool) {
	if p != nil && p.ConfigureBrowser != nil {
		p.ConfigureBrowser(automated)
	}
}
func (p *Presentation) setDemo() {
	if p != nil && p.Demo != nil {
		p.Demo()
	}
}
func (p *Presentation) setGuestDemo() {
	if p != nil && p.GuestDemo != nil {
		p.GuestDemo()
	}
}
func (p *Presentation) setGuestShare(secret string) {
	if p != nil && p.GuestShare != nil {
		p.GuestShare(secret)
	}
}
func (p *Presentation) starting(id, target string) error {
	if p == nil || p.Starting == nil {
		return nil
	}
	return p.Starting(id, target)
}
func (p *Presentation) provisioning(url string, run uint64) error {
	if p == nil || p.Provisioning == nil {
		return nil
	}
	return p.Provisioning(url, run)
}
func (p *Presentation) provisioningStalled(run uint64) error {
	if p == nil || p.ProvisioningStalled == nil {
		return nil
	}
	return p.ProvisioningStalled(run)
}
func (p *Presentation) transportFallback(run uint64, transport string) error {
	if p == nil || p.TransportFallback == nil {
		return nil
	}
	return p.TransportFallback(run, transport)
}
func (p *Presentation) targetUnavailable() error {
	if p == nil || p.TargetUnavailable == nil {
		return nil
	}
	return p.TargetUnavailable()
}
func (p *Presentation) draining() error {
	if p == nil || p.Draining == nil {
		return nil
	}
	return p.Draining()
}
func (p *Presentation) ready(url string, run uint64) error {
	if p == nil || p.Ready == nil {
		return nil
	}
	return p.Ready(url, run)
}
func (p *Presentation) stopped() error {
	if p == nil || p.Stopped == nil {
		return nil
	}
	return p.Stopped()
}

func (p *Presentation) integrationURLMessage(state, hint string, details ...clioutput.Block) error {
	if p == nil || p.Progress == nil {
		return nil
	}
	return p.Progress(Progress{State: state, Hint: hint, Details: details})
}

func failureMessage(err error) string {
	_, message, ok := failure.Describe(err)
	if ok {
		return message.Message
	}
	return err.Error()
}

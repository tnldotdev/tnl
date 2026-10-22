package state

import "crypto/subtle"

// these stages are internal views of the unchanged encrypted DeviceLogin DTO.
// an exchange can be consumed without changing the public pending status.
type deviceLoginStage interface{ deviceLoginStage() }
type deviceAwaitingBrowser struct{}
type deviceBrowserExchange struct {
	state, nonce, verifier string
	binding                []byte
}
type deviceVerifiedIdentity struct {
	identity OIDCIdentity
	binding  []byte
}
type deviceIssuedSession struct{ session ControlSession }
type deviceTerminal struct{}

func (deviceAwaitingBrowser) deviceLoginStage()  {}
func (deviceBrowserExchange) deviceLoginStage()  {}
func (deviceVerifiedIdentity) deviceLoginStage() {}
func (deviceIssuedSession) deviceLoginStage()    {}
func (deviceTerminal) deviceLoginStage()         {}

func (l DeviceLogin) stage() (deviceLoginStage, error) {
	clearExchange := l.State == "" && l.Nonce == "" && l.Verifier == ""
	switch l.Status {
	case DevicePending:
		if l.Session != nil {
			break
		}
		if l.Identity != nil {
			if clearExchange && len(l.Binding) == 32 {
				return deviceVerifiedIdentity{*l.Identity, l.Binding}, nil
			}
			break
		}
		if clearExchange && len(l.Binding) == 0 && l.CompanyIntent == nil {
			return deviceAwaitingBrowser{}, nil
		}
		if (l.State == "" || len(l.State) == 43) && len(l.Nonce) == 43 && len(l.Verifier) >= 43 && len(l.Binding) == 32 {
			return deviceBrowserExchange{l.State, l.Nonce, l.Verifier, l.Binding}, nil
		}
	case DeviceApproved:
		if l.Session != nil && l.Identity == nil && clearExchange && len(l.Binding) == 0 && l.CompanyIntent == nil {
			return deviceIssuedSession{*l.Session}, nil
		}
	case DeviceCancelled, DeviceDenied:
		if l.Session == nil && l.Identity == nil && clearExchange && len(l.Binding) == 0 && l.CompanyIntent == nil {
			return deviceTerminal{}, nil
		}
	}
	return nil, ErrDeviceLogin
}

func deviceBindingMatches(expected, submitted []byte) bool {
	return len(submitted) == 32 && subtle.ConstantTimeCompare(expected, submitted) == 1
}

func (l *DeviceLogin) beginBrowser(exchange deviceBrowserExchange, team string, intent *CompanyLoginIntent) error {
	stage, err := l.stage()
	if err != nil {
		return err
	}
	switch stage.(type) {
	case deviceAwaitingBrowser, deviceBrowserExchange:
	default:
		return ErrDeviceLogin
	}
	if l.TeamID != "" && l.TeamID != team {
		return ErrDeviceLogin
	}
	l.TeamID, l.CompanyIntent = team, intent
	l.State, l.Nonce, l.Verifier, l.Binding = exchange.state, exchange.nonce, exchange.verifier, exchange.binding
	return nil
}

func (l *DeviceLogin) consumeBrowser(binding []byte) error {
	stage, err := l.stage()
	exchange, ok := stage.(deviceBrowserExchange)
	if err != nil || !ok || exchange.state == "" || !deviceBindingMatches(exchange.binding, binding) {
		return ErrDeviceLogin
	}
	l.State = ""
	return nil
}

func (l *DeviceLogin) verifyBrowser(binding []byte, identity OIDCIdentity) error {
	stage, err := l.stage()
	exchange, ok := stage.(deviceBrowserExchange)
	if err != nil || !ok || exchange.state != "" || !deviceBindingMatches(exchange.binding, binding) {
		return ErrDeviceLogin
	}
	if l.CompanyIntent != nil {
		identity.CompanyIntent = &CompanyIntentBinding{ID: l.CompanyIntent.ID, BindingToken: l.CompanyIntent.BindingToken, RedirectURI: l.CompanyIntent.RedirectURI}
	}
	l.Identity, l.Nonce, l.Verifier = &identity, "", ""
	return nil
}

func (l *DeviceLogin) clearBrowser(status DeviceLoginStatus) {
	l.Status, l.Session, l.Identity = status, nil, nil
	l.State, l.Nonce, l.Verifier, l.Binding, l.CompanyIntent = "", "", "", nil, nil
}

func (l *DeviceLogin) issueSession(session ControlSession) {
	l.clearBrowser(DeviceApproved)
	l.Session = &session
}

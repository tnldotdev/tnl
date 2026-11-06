// package tlspolicy owns TLS key-agreement requirements shared by native
// transports and publisher visitor TLS. it depends only on crypto/tls, not on
// transport sessions, publisher lifetimes, or server composition.
package tlspolicy

import "crypto/tls"

// RequirePostQuantum returns an independent TLS 1.3 configuration that accepts
// only hybrid X25519 + ML-KEM-768 key agreement. dynamic server configurations
// receive the same requirement; neither caller settings nor Go debug defaults
// can silently enable a classical-only fallback.
func RequirePostQuantum(config *tls.Config) *tls.Config {
	result := config.Clone()
	result.MinVersion = tls.VersionTLS13
	result.CurvePreferences = []tls.CurveID{tls.X25519MLKEM768}
	if selectConfig := config.GetConfigForClient; selectConfig != nil {
		result.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			selected, err := selectConfig(hello)
			if selected == nil || err != nil {
				return nil, err
			}
			return RequirePostQuantum(selected), nil
		}
	}
	return result
}

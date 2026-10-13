package localpublisher

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/tnldotdev/tnl/internal/clientserver"
	"github.com/tnldotdev/tnl/internal/clientstate"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/internal/diagnostic"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/localproxy"
	"github.com/tnldotdev/tnl/internal/projectconfig"
	"github.com/tnldotdev/tnl/internal/tcptarget"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

type projectConfiguration struct{ projectconfig.Project }

type tunnelFlags struct {
	Domain, Name, PublicURL                                                      string
	AllowIP                                                                      []string
	AllowAllIPs, Ephemeral                                                       bool
	Requests, RateRequests, RateBurst, Concurrency                               *int
	RatePer                                                                      string
	TrafficConnections, TrafficRateCount, TrafficRateBurst                       *int
	TrafficRatePer, TrafficUpload, TrafficDownload                               string
	TargetCAFile                                                                 string
	InspectionMode                                                               config.InspectionMode
	InspectionRetention                                                          time.Duration
	InspectionMaxBytes                                                           string
	allowAllIPsFromCLI, ephemeralFromCLI                                         bool
	inspectionModeFromCLI, inspectionRetentionFromCLI, inspectionMaxBytesFromCLI bool
}

type dockerPublishTarget struct {
	selection    config.DockerSelection
	projectLabel string
}

const defaultServerURL = clientserver.DefaultURL

func clientStateRoot(root string) (string, error) {
	if root != "" {
		return root, nil
	}
	return clientstate.DefaultDir()
}

func pathInside(path, root string) bool {
	relative, err := filepath.Rel(root, path)
	return err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}

func parseLoginInput(data []byte) (credentials.LoginToken, error) {
	token := credentials.LoginToken(strings.TrimSpace(string(data)))
	if _, err := credentials.ParseLoginToken(token); err != nil {
		return "", failure.Wrap("validate login token", failure.LoginTokenInvalid, err)
	}
	return token, nil
}

func targetOptionsForCA(path, projectRoot string) (localproxy.TargetOptions, error) {
	return TargetOptionsForCA(path, projectRoot)
}

func TargetOptionsForCA(path, projectRoot string) (localproxy.TargetOptions, error) {
	if path == "" {
		return localproxy.TargetOptions{}, nil
	}
	if !filepath.IsAbs(path) {
		path = filepath.Join(projectRoot, path)
	}
	roots, err := localproxy.LoadTargetRootCAs(path)
	if err != nil {
		return localproxy.TargetOptions{}, err
	}
	return localproxy.TargetOptions{RootCAs: roots}, nil
}

func normalizePublishTarget(target string, protocol controlv1.PublicURLServiceProtocol) (string, error) {
	if protocol == controlv1.Http {
		return localproxy.NormalizeTarget(target)
	}
	canonical, err := tcptarget.Normalize(target)
	if err != nil {
		return "", diagnostic.Wrap(diagnostic.TargetInvalid, err)
	}
	return canonical, nil
}

func savedPublicAddress(route controlv1.PublicURL) (string, error) {
	return SavedPublicAddress(route)
}

func applyTunnelConfiguration(flags *tunnelFlags, tunnel *config.Tunnel, protocol ...string) {
	if tunnel == nil {
		return
	}
	applyTunnelLimits(flags, tunnel.Limits, protocol...)
	if flags.Domain == "" && tunnel.Domain != nil {
		flags.Domain = *tunnel.Domain
	}
	if flags.PublicURL == "" && flags.Name == "" {
		if tunnel.PublicURL != nil {
			flags.PublicURL = *tunnel.PublicURL
		}
		if tunnel.Name != nil {
			flags.Name = *tunnel.Name
		}
	}
	_, ephemeralFromEnvironment := os.LookupEnv("TNL_EPHEMERAL")
	if tunnel.Ephemeral != nil && !flags.ephemeralFromCLI && !ephemeralFromEnvironment {
		flags.Ephemeral = *tunnel.Ephemeral
	}
	_, allowAllIPsFromEnvironment := os.LookupEnv("TNL_ALLOW_ALL_IPS")
	if !flags.allowAllIPsFromCLI && !allowAllIPsFromEnvironment {
		if flags.AllowIP == nil {
			flags.AllowIP = slices.Clone(tunnel.AllowIP)
		}
		if tunnel.AllowAllIPs != nil && flags.AllowIP == nil {
			flags.AllowAllIPs = *tunnel.AllowAllIPs
		}
	}
}

func applyTunnelLimits(flags *tunnelFlags, limits *config.Limits, protocol ...string) {
	if limits == nil {
		return
	}
	if traffic := limits.Traffic; traffic != nil {
		if flags.TrafficConnections == nil {
			flags.TrafficConnections = traffic.Connections
		}
		if traffic.Rate != nil {
			if flags.TrafficRateCount == nil {
				flags.TrafficRateCount = traffic.Rate.Count
			}
			if flags.TrafficRatePer == "" && traffic.Rate.Per != nil {
				flags.TrafficRatePer = traffic.Rate.Per.Value().String()
			}
			if flags.TrafficRateBurst == nil {
				flags.TrafficRateBurst = traffic.Rate.Burst
			}
		}
		if traffic.Bandwidth != nil {
			if flags.TrafficUpload == "" && traffic.Bandwidth.Upload != nil {
				flags.TrafficUpload = string(*traffic.Bandwidth.Upload)
			}
			if flags.TrafficDownload == "" && traffic.Bandwidth.Download != nil {
				flags.TrafficDownload = string(*traffic.Bandwidth.Download)
			}
		}
	}
	selected := limits.HTTP
	if len(protocol) != 0 && protocol[0] != "" && protocol[0] != "http" {
		selected = limits.TCP
	}
	if selected == nil {
		return
	}
	if flags.Requests == nil {
		flags.Requests = selected.Total
	}
	if flags.Concurrency == nil {
		flags.Concurrency = selected.Concurrency
	}
	if selected.Rate != nil {
		if flags.RateRequests == nil {
			flags.RateRequests = selected.Rate.Count
		}
		if flags.RatePer == "" && selected.Rate.Per != nil {
			flags.RatePer = selected.Rate.Per.Value().String()
		}
		if flags.RateBurst == nil {
			flags.RateBurst = selected.Rate.Burst
		}
	}
}

func applyInspection(flags *tunnelFlags, effective config.TNL) {
	if effective.Inspection != nil {
		if !flags.inspectionModeFromCLI && effective.Inspection.Mode != nil {
			flags.InspectionMode = *effective.Inspection.Mode
		}
		if !flags.inspectionRetentionFromCLI && flags.InspectionRetention == 0 && effective.Inspection.Retention != nil {
			flags.InspectionRetention = effective.Inspection.Retention.Value()
		}
		if !flags.inspectionMaxBytesFromCLI && flags.InspectionMaxBytes == "" && effective.Inspection.MaxBytes != nil {
			flags.InspectionMaxBytes = fmt.Sprintf("%dKiB", effective.Inspection.MaxBytes.Value()/(1<<10))
		}
	}
	if flags.InspectionMode == "" {
		flags.InspectionMode = config.InspectionSummary
	}
}

type presentedFailure struct {
	reason  failure.Reason
	message string
}

func presentFailure(err error) presentedFailure {
	if code, ok := diagnostic.CodeOf(err); ok {
		return presentedFailure{failure.Reason(code), diagnostic.Summary(code)}
	}
	if reason, definition, ok := failure.Describe(err); ok {
		return presentedFailure{reason, definition.Message}
	}
	definition, _ := failure.DefinitionFor(failure.Unexpected)
	return presentedFailure{failure.Unexpected, definition.Message}
}

func tcpVisitorTLSPassthrough(project projectConfiguration, name string) bool {
	service := project.Config.Services[name]
	return service.TCP != nil && service.TCP.VisitorTLS != nil && *service.TCP.VisitorTLS == "passthrough"
}

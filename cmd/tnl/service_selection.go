package main

import (
	"errors"
	"slices"
	"strings"

	"github.com/spf13/cobra"
	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func requireWholeServiceArgument(cmd *cobra.Command, where int, reason failure.Reason) {
	bind := cmd.Args
	cmd.Args = func(cmd *cobra.Command, args []string) error {
		if err := bind(cmd, args); err != nil {
			return err
		}
		if where >= len(args) {
			return nil
		}
		input, err := parseWholeService(args[where], reason)
		if err == nil && input.Kind == naming.SelectorOmitted {
			return serviceInputError(reason, "The service selector cannot be empty.")
		}
		return err
	}
}

func parseWholeService(raw string, reason failure.Reason) (naming.ServiceSelector, error) {
	input, err := naming.ParseServiceSelector(raw)
	if err != nil {
		return input, serviceInputError(reason, "Use a service name, service ID, hostname, host:port, or service URL.")
	}
	if input.Resource {
		return input, serviceInputError(reason, "Select the whole service with "+input.WholeAddress()+" or its service ID. Remove the path and query.")
	}
	return input, nil
}

func serviceInputError(reason failure.Reason, message string) error {
	return &commandGuidance{error: failure.Wrap("select service", reason, errors.New(message)), message: message}
}

// matchInventory compares already-authorized facts. it neither chooses an
// inventory nor broadens an explicit selector when there is no match.
func matchInventory(input naming.ServiceSelector, items []controlv1.ServiceSummary, reason failure.Reason) (controlv1.ServiceSummary, error) {
	if input.Kind == naming.SelectorOmitted && len(items) != 1 {
		return controlv1.ServiceSummary{}, serviceInputError(reason, "Select the public URL by hostname or exact service ID.")
	}
	matches := map[string]controlv1.ServiceSummary{}
	for _, item := range items {
		matched := false
		switch input.Kind {
		case naming.SelectorOmitted:
			matched = true
		case naming.SelectorID:
			matched = item.Id == input.ID
		case naming.SelectorName:
			matched = item.Name == input.Name || item.Endpoint != nil && item.Endpoint.Hostname == input.Name
		case naming.SelectorAddress:
			matched = item.Endpoint != nil && input.MatchesEndpoint(string(item.Protocol), item.Endpoint.Hostname, item.Endpoint.Port)
		}
		if matched {
			if !opaqueid.Valid(item.Id, opaqueid.ServicePrefix) {
				return controlv1.ServiceSummary{}, serviceShareResponse()
			}
			matches[item.Id] = item
		}
	}
	if len(matches) > 1 {
		ids := make([]string, 0, len(matches))
		for id := range matches {
			ids = append(ids, id)
		}
		slices.Sort(ids)
		message := "More than one service matches. Select an exact service ID."
		if len(ids) > 8 {
			ids = ids[:8]
			message += " First matches: "
		} else {
			message += " Matches: "
		}
		return controlv1.ServiceSummary{}, serviceInputError(reason, message+strings.Join(ids, ", "))
	}
	for _, item := range matches {
		return item, nil
	}
	return controlv1.ServiceSummary{}, clientcontrol.ErrNotFound
}

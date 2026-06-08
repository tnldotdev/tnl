package routes_test

import (
	"github.com/tnldotdev/tnl/internal/api"
	"github.com/tnldotdev/tnl/internal/routes"
)

var _ api.RouteService = (*routes.Coordinator)(nil)

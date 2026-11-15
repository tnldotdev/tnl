package public

import (
	"net/http"

	"github.com/tnldotdev/tnl/internal/security/credentials"
)

func requestBearerToken(request *http.Request) (string, bool) {
	token, err := credentials.Bearer(request.Header)
	return token, err == nil
}

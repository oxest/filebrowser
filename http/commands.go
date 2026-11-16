package fbhttp

import "net/http"

// Command execution is deliberately unavailable. The upstream implementation
// has multiple known security issues and is not safe to re-enable by config.
var commandsHandler = withUser(func(_ http.ResponseWriter, _ *http.Request, _ *data) (int, error) {
	return http.StatusForbidden, nil
})

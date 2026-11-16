package runner

import (
	"github.com/filebrowser/filebrowser/v2/settings"
	"github.com/filebrowser/filebrowser/v2/users"
)

// Runner is a commands runner.
type Runner struct {
	Enabled bool
	*settings.Settings
}

// RunHook executes the file operation. External hooks are disabled.
func (r *Runner) RunHook(fn func() error, _, _, _ string, _ *users.User) error {
	return fn()
}

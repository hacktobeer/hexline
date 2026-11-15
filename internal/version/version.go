// Package version exposes build metadata set via -ldflags.
package version

import "runtime"

// Values are overridden at build time.
var (
	Version   = "dev"
	Commit    = "none"
	BuildDate = "unknown"
)

// String returns a one-line build description.
func String() string {
	return Version + " (" + Commit + ", " + BuildDate + ", " + runtime.Version() + ")"
}

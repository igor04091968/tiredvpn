// Package godebug provides the tiny subset of internal/godebug needed by the
// standalone TLS fork. It intentionally reads GODEBUG dynamically, matching
// the standard package's observable Value behavior.
package godebug

import (
	"os"
	"strings"
)

type Setting struct {
	name string
}

func New(name string) *Setting {
	return &Setting{name: name}
}

func (s *Setting) Value() string {
	var value string
	for _, field := range strings.Split(os.Getenv("GODEBUG"), ",") {
		name, v, ok := strings.Cut(strings.TrimSpace(field), "=")
		if ok && name == s.name {
			value = v
		}
	}
	return value
}

// IncNonDefault is a telemetry hook in the standard library. A standalone
// package has no runtime telemetry counter, so it is deliberately a no-op.
func (s *Setting) IncNonDefault() {}

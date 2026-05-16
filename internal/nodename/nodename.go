// Package nodename validates and expands tinc-compatible node names.
//
// Tinc rules (tinc.conf(5)):
//   - Names may only contain alphanumeric characters and underscores.
//   - Case-sensitive.
//   - A name starting with `$` refers to the named environment variable.
//     If the variable is unset and the prefix is `$HOST`, the system hostname is used.
//     Invalid characters in the resolved value are converted to underscores.
package nodename

import (
	"fmt"
	"os"
	"strings"
)

func Validate(name string) error {
	if name == "" {
		return fmt.Errorf("node name must not be empty")
	}
	for i, r := range name {
		if !isNameRune(r) {
			return fmt.Errorf("node name %q: invalid character %q at position %d", name, r, i)
		}
	}
	return nil
}

func Expand(spec string) (string, error) {
	if !strings.HasPrefix(spec, "$") {
		return spec, nil
	}
	envName := spec[1:]
	val, ok := os.LookupEnv(envName)
	if !ok {
		h, err := os.Hostname()
		if err != nil {
			return "", fmt.Errorf("lookup %s and hostname: %w", spec, err)
		}
		val = h
	}
	return sanitize(val), nil
}

func sanitize(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if isNameRune(r) {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
	}
	return b.String()
}

func isNameRune(r rune) bool {
	return (r >= 'a' && r <= 'z') ||
		(r >= 'A' && r <= 'Z') ||
		(r >= '0' && r <= '9') ||
		r == '_'
}

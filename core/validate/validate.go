// cordova/core/validate/validate.go
//
// Package validate provides shared input validation rules for token names and
// key names. It is intentionally outside internal/ so both cordova-vault and
// cordova-admin can import it without violating Go's visibility rules.
// It has no external dependencies — only the standard library.
package validate

import (
	"fmt"
	"strings"
)

// ValidateTokenName returns an error if name is not a valid token slug.
//
// Rules:
//   - Lowercase ASCII letters, digits, and hyphens only
//   - Must start and end with a letter or digit (no leading/trailing hyphens)
//   - No consecutive hyphens
//   - Between 1 and 64 characters long
func ValidateTokenName(name string) error {
	if len(name) == 0 {
		return fmt.Errorf("token name cannot be empty")
	}
	if len(name) > 64 {
		return fmt.Errorf("token name must be 64 characters or fewer, got %d", len(name))
	}
	for i, r := range name {
		switch {
		case r >= 'a' && r <= 'z':
			// ok
		case r >= '0' && r <= '9':
			// ok
		case r == '-':
			if i == 0 {
				return fmt.Errorf("token name must not start with a hyphen: %q", name)
			}
			if i == len(name)-1 {
				return fmt.Errorf("token name must not end with a hyphen: %q", name)
			}
			if name[i-1] == '-' {
				return fmt.Errorf("token name must not contain consecutive hyphens: %q", name)
			}
		default:
			return fmt.Errorf("token name contains invalid character %q (only lowercase letters, digits, and hyphens are allowed): %q", r, name)
		}
	}
	return nil
}

// ValidateKeyName returns an error if name is not in "namespace/name" format.
//
// Rules:
//   - Exactly one forward slash separating two non-empty parts
//   - No whitespace anywhere in the name
//   - No sub-namespaces (only one slash allowed)
func ValidateKeyName(name string) error {
	if strings.ContainsAny(name, " \t\n\r") {
		return fmt.Errorf("key name must not contain whitespace: %q", name)
	}
	parts := strings.SplitN(name, "/", 3)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return fmt.Errorf("key name must be namespace/name with exactly one slash (e.g. prod/db-pass): %q", name)
	}
	return nil
}

// cordova/core/validate/validate.go

package validate

import (
	"fmt"
	"strings"
)

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

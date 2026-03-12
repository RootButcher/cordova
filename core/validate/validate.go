// cordova/core/validate/validate.go

package validate

import (
	"fmt"
	"strings"
)

// TokenName validates a token slug name: 1–64 chars, lowercase letters,
// digits, and hyphens; no leading, trailing, or consecutive hyphens.
func TokenName(name string) error {
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

// KeyName validates a key name in namespace/name format.
func KeyName(name string) error {
	if strings.ContainsAny(name, " \t\n\r") {
		return fmt.Errorf("key name must not contain whitespace: %q", name)
	}
	parts := strings.SplitN(name, "/", 3)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return fmt.Errorf("key name must be namespace/name with exactly one slash (e.g. prod/db-pass): %q", name)
	}
	return nil
}

// Username validates a user slug name using the same rules as token names.
func Username(name string) error {
	if len(name) == 0 {
		return fmt.Errorf("username cannot be empty")
	}
	if len(name) > 64 {
		return fmt.Errorf("username must be 64 characters or fewer, got %d", len(name))
	}
	for i, r := range name {
		switch {
		case r >= 'a' && r <= 'z':
			// ok
		case r >= '0' && r <= '9':
			// ok
		case r == '-':
			if i == 0 {
				return fmt.Errorf("username must not start with a hyphen: %q", name)
			}
			if i == len(name)-1 {
				return fmt.Errorf("username must not end with a hyphen: %q", name)
			}
			if name[i-1] == '-' {
				return fmt.Errorf("username must not contain consecutive hyphens: %q", name)
			}
		default:
			return fmt.Errorf("username contains invalid character %q (only lowercase letters, digits, and hyphens are allowed): %q", r, name)
		}
	}
	return nil
}

// SocketName validates a socket entry name using the same slug rules.
func SocketName(name string) error {
	if len(name) == 0 {
		return fmt.Errorf("socket name cannot be empty")
	}
	if len(name) > 64 {
		return fmt.Errorf("socket name must be 64 characters or fewer, got %d", len(name))
	}
	for i, r := range name {
		switch {
		case r >= 'a' && r <= 'z':
			// ok
		case r >= '0' && r <= '9':
			// ok
		case r == '-':
			if i == 0 {
				return fmt.Errorf("socket name must not start with a hyphen: %q", name)
			}
			if i == len(name)-1 {
				return fmt.Errorf("socket name must not end with a hyphen: %q", name)
			}
			if name[i-1] == '-' {
				return fmt.Errorf("socket name must not contain consecutive hyphens: %q", name)
			}
		default:
			return fmt.Errorf("socket name contains invalid character %q (only lowercase letters, digits, and hyphens are allowed): %q", r, name)
		}
	}
	return nil
}

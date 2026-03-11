// cordova/admin/tui/views.go
//
// View renders the current Model state as a string. Each screen has its own
// helper function. Styling is done with lipgloss.

package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
)

// ── Styles ────────────────────────────────────────────────────────────────────

var (
	// bannerStyle renders the full-width CORDOVA header in white on red.
	// No vertical padding — we want a single solid red bar, not multiple rows.
	// Width is applied dynamically in View() to fill the terminal width.
	bannerStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#FFFFFF")).
			Background(lipgloss.Color("1")).
			Padding(0, 2).
			Align(lipgloss.Center).
			Height(5)

	// borderStyle wraps the entire TUI in a red rounded border.
	// No padding here — the banner needs to fill edge-to-edge. Screen content
	// gets its own horizontal padding applied separately in View().
	borderStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("1"))

	// contentPadStyle adds horizontal margins to screen content so text does
	// not sit directly against the border characters.
	contentPadStyle = lipgloss.NewStyle().Padding(0, 2)

	// titleStyle renders the screen heading.
	titleStyle = lipgloss.NewStyle().Bold(true).Underline(true)

	// selectedStyle highlights the cursor row in a list.
	selectedStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("12")).Bold(true)

	// dimStyle renders secondary information in a muted colour.
	dimStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("8"))

	// errStyle renders transient error messages in red.
	errStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("9"))

	// hintStyle renders the keyboard hint bar at the bottom of each screen.
	hintStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("8"))

	// tokenStyle renders a newly generated token value in green so it stands
	// out from the surrounding text.
	tokenStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("10")).Bold(true)

	// valueStyle renders a revealed secret value in yellow.
	valueStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("11")).Bold(true)
)

// ── View ──────────────────────────────────────────────────────────────────────

// View returns the complete rendered string for the current model state.
// bubbletea calls this after every Update.
func (m Model) View() string {
	// innerWidth is the content area width inside the border characters only —
	// no border padding so the banner background fills edge-to-edge.
	// Border takes 2 chars (left + right). Fall back to 78 before the first
	// WindowSizeMsg arrives.
	innerWidth := m.width - 2
	if innerWidth < 40 {
		innerWidth = 78
	}

	// Build screen content separately so it can receive its own horizontal
	// padding without affecting the banner.
	var screen strings.Builder
	screen.WriteString("\n")
	switch m.screen {
	case screenAuth:
		screen.WriteString(viewAuth(m))
	case screenMenu:
		screen.WriteString(viewMenu(m))
	case screenKeys:
		screen.WriteString(viewKeys(m))
	case screenTokens:
		screen.WriteString(viewTokens(m))
	case screenStatus:
		screen.WriteString(viewStatus(m))
	}
	if m.err != "" {
		screen.WriteString("\n" + errStyle.Render("error: "+m.err))
	}
	screen.WriteString("\n")

	var b strings.Builder
	// terminal emulators cannot change font size.
	b.WriteString(bannerStyle.Width(innerWidth).Render("\n"+"CORDOVA") + "\n")
	b.WriteString(contentPadStyle.Width(innerWidth).Render(screen.String()))

	return borderStyle.Width(innerWidth).Render(b.String())
}

// viewAuth renders the token entry screen shown when no token was pre-supplied.
func viewAuth(m Model) string {
	var b strings.Builder
	b.WriteString(titleStyle.Render("Authentication") + "\n\n")
	if m.loading {
		b.WriteString(dimStyle.Render("connecting..."))
		return b.String()
	}
	b.WriteString("Enter your token to continue.\n\n")
	b.WriteString(m.input.View() + "\n")
	b.WriteString("\n" + hintStyle.Render("enter confirm  ctrl+c quit"))
	return b.String()
}

// viewMenu renders the main navigation menu.
func viewMenu(m Model) string {
	var b strings.Builder

	b.WriteString(titleStyle.Render("Cordova Admin") + "\n\n")

	items := []string{"Keys", "Tokens", "Admin"}
	for i, item := range items {
		if i == m.menuCursor {
			b.WriteString(selectedStyle.Render("> " + item))
		} else {
			b.WriteString("  " + item)
		}
		b.WriteString("\n")
	}

	b.WriteString("\n" + hintStyle.Render("↑/↓ navigate  enter select  q quit"))
	return b.String()
}

// viewKeys renders the key list and any active form.
func viewKeys(m Model) string {
	var b strings.Builder

	b.WriteString(titleStyle.Render("Keys") + "\n\n")

	// Active form takes priority over the list.
	switch m.step {
	case stepKeyName:
		b.WriteString("key name (namespace/name)\n")
		b.WriteString(m.input.View() + "\n")
		b.WriteString(hintStyle.Render("enter confirm  esc cancel"))
		return b.String()

	case stepKeyValue:
		b.WriteString(fmt.Sprintf("value for %q\n", m.inputBuffer["name"]))
		b.WriteString(m.input.View() + "\n")
		b.WriteString(hintStyle.Render("enter confirm  esc cancel"))
		return b.String()

	case stepRotateValue:
		b.WriteString(fmt.Sprintf("new value for %q\n", m.inputBuffer["name"]))
		b.WriteString(m.input.View() + "\n")
		b.WriteString(hintStyle.Render("enter confirm  esc cancel"))
		return b.String()

	case stepConfirm:
		b.WriteString(fmt.Sprintf("delete %q?  ", m.confirmTarget))
		b.WriteString(hintStyle.Render("y confirm  any other key cancel"))
		return b.String()

	case stepKeyView:
		name := m.keys[m.keyCursor]
		b.WriteString(fmt.Sprintf("key:   %s\n", name))
		b.WriteString(fmt.Sprintf("value: %s\n\n", valueStyle.Render(m.selectedKeyValue)))
		b.WriteString(hintStyle.Render("any key to dismiss"))
		return b.String()
	}

	if m.loading {
		b.WriteString(dimStyle.Render("loading..."))
		return b.String()
	}

	if len(m.keys) == 0 {
		b.WriteString(dimStyle.Render("no keys stored"))
	} else {
		for i, k := range m.keys {
			if i == m.keyCursor {
				b.WriteString(selectedStyle.Render("> " + k))
			} else {
				b.WriteString("  " + k)
			}
			b.WriteString("\n")
		}
	}

	b.WriteString("\n" + hintStyle.Render("↑/↓ navigate  enter view  a add  r rotate  d delete  esc back"))
	return b.String()
}

// viewTokens renders the token list and any active form.
func viewTokens(m Model) string {
	var b strings.Builder

	b.WriteString(titleStyle.Render("Tokens") + "\n\n")

	switch m.step {
	case stepTokenName:
		b.WriteString("token name (slug: lowercase letters, digits, hyphens)\n")
		b.WriteString(m.input.View() + "\n")
		b.WriteString(hintStyle.Render("enter confirm  esc cancel"))
		return b.String()

	case stepTokenDesc:
		b.WriteString(fmt.Sprintf("description for %q\n", m.inputBuffer["name"]))
		b.WriteString(m.input.View() + "\n")
		b.WriteString(hintStyle.Render("enter confirm  esc cancel"))
		return b.String()

	case stepConfirm:
		b.WriteString(fmt.Sprintf("revoke %q?  ", m.confirmTarget))
		b.WriteString(hintStyle.Render("y confirm  any other key cancel"))
		return b.String()

	case stepTokenCreated:
		b.WriteString("token created\n\n")
		b.WriteString(tokenStyle.Render(m.newToken) + "\n\n")
		b.WriteString("copy this secret now — it will not be shown again\n")
		b.WriteString("\n" + hintStyle.Render("any key to continue"))
		return b.String()
	}

	if m.loading {
		b.WriteString(dimStyle.Render("loading..."))
		return b.String()
	}

	if len(m.tokens) == 0 {
		b.WriteString(dimStyle.Render("no tokens stored"))
	} else {
		for i, t := range m.tokens {
			line := fmt.Sprintf("%-20s  %-8s  %s", t.Name, t.Role, t.Description)
			if i == m.tokenCursor {
				b.WriteString(selectedStyle.Render("> " + line))
			} else {
				b.WriteString("  " + line)
			}
			b.WriteString("\n")
		}
	}

	b.WriteString("\n" + hintStyle.Render("↑/↓ navigate  a add admin token  d revoke  esc back"))
	return b.String()
}

// viewStatus renders the vault status screen.
func viewStatus(m Model) string {
	var b strings.Builder

	b.WriteString(titleStyle.Render("Admin") + "\n\n")

	if m.loading {
		b.WriteString(dimStyle.Render("loading..."))
		return b.String()
	}

	if m.status != nil {
		state := "unsealed"
		if m.status.Sealed {
			state = "sealed"
		}
		b.WriteString(fmt.Sprintf("status:  %s\n", state))
		b.WriteString(fmt.Sprintf("version: %s\n", m.status.Version))
	}

	b.WriteString("\n" + hintStyle.Render("s seal vault  esc back  q quit"))
	return b.String()
}

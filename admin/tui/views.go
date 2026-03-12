// cordova/admin/tui/views.go

package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
)

// ── Styles ────────────────────────────────────────────────────────────────────

var (
	bannerStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#FFFFFF")).
			Background(lipgloss.Color("1")).
			Padding(0, 2).
			Align(lipgloss.Center).
			Height(5)

	borderStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("1"))

	contentPadStyle = lipgloss.NewStyle().Padding(0, 2)
	titleStyle      = lipgloss.NewStyle().Bold(true).Underline(true)
	selectedStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("12")).Bold(true)
	dimStyle        = lipgloss.NewStyle().Foreground(lipgloss.Color("8"))
	errStyle        = lipgloss.NewStyle().Foreground(lipgloss.Color("9"))
	hintStyle       = lipgloss.NewStyle().Foreground(lipgloss.Color("8"))
	tokenStyle      = lipgloss.NewStyle().Foreground(lipgloss.Color("10")).Bold(true)
	valueStyle      = lipgloss.NewStyle().Foreground(lipgloss.Color("11")).Bold(true)
)

// viewPermListScreen renders a cursor-navigable permission toggle list.
func viewPermListScreen(title string, items []permItem, cursor int, hint string) string {
	var b strings.Builder
	b.WriteString(titleStyle.Render(title) + "\n\n")
	for i, item := range items {
		selected := i == cursor
		var line string
		switch item.kind {
		case permBoolToggle:
			check := "[ ]"
			if item.on {
				check = "[x]"
			}
			line = check + " " + item.key
		case permListEntry:
			line = "x  " + item.value
			if item.dim && !selected {
				b.WriteString("  " + dimStyle.Render(line) + "\n")
				continue
			}
		case permAddAction:
			line = "+ " + item.value
			if item.dim || !selected {
				b.WriteString("  " + dimStyle.Render(line) + "\n")
				continue
			}
		case permDone:
			line = "✓ done"
		}
		if selected {
			b.WriteString(selectedStyle.Render("> "+line) + "\n")
		} else {
			b.WriteString("  " + line + "\n")
		}
	}
	b.WriteString("\n" + hintStyle.Render(hint))
	return b.String()
}

// ── View ──────────────────────────────────────────────────────────────────────

func (m Model) View() string {
	innerWidth := m.width - 2
	if innerWidth < 40 {
		innerWidth = 78
	}
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
	case screenUsers:
		screen.WriteString(viewUsers(m))
	case screenSockets:
		screen.WriteString(viewSockets(m))
	}
	if m.err != "" {
		screen.WriteString("\n" + errStyle.Render("error: "+m.err))
	}
	screen.WriteString("\n")

	var b strings.Builder
	b.WriteString(bannerStyle.Width(innerWidth).Render("\n"+"CORDOVA") + "\n")
	b.WriteString(contentPadStyle.Width(innerWidth).Render(screen.String()))

	return borderStyle.Width(innerWidth).Render(b.String())
}

func viewAuth(m Model) string {
	var b strings.Builder
	b.WriteString(titleStyle.Render("Authentication") + "\n\n")
	if m.loading {
		b.WriteString(dimStyle.Render("connecting..."))
		return b.String()
	}
	if m.step == stepAuthUser {
		b.WriteString("Enter your username.\n\n")
		b.WriteString(m.input.View() + "\n")
		b.WriteString("\n" + hintStyle.Render("enter confirm  ctrl+c quit"))
		return b.String()
	}
	if m.inputBuffer["awaitingToken"] == "1" {
		b.WriteString(fmt.Sprintf("User: %s\n\n", m.authUsername))
		b.WriteString("Enter your token.\n\n")
		b.WriteString(m.input.View() + "\n")
		b.WriteString("\n" + hintStyle.Render("enter confirm  ctrl+c quit"))
		return b.String()
	}
	b.WriteString("Enter your username to continue.\n\n")
	b.WriteString(m.input.View() + "\n")
	b.WriteString("\n" + hintStyle.Render("enter confirm  ctrl+c quit"))
	return b.String()
}

func viewMenu(m Model) string {
	var b strings.Builder
	b.WriteString(titleStyle.Render("Cordova Admin") + "\n\n")
	items := []string{"Keys", "Tokens", "Users", "Admin"}
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

func viewKeys(m Model) string {
	var b strings.Builder
	b.WriteString(titleStyle.Render("Keys") + "\n\n")
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
	case stepNone, stepTokenUser, stepTokenName, stepTokenDesc, stepTokenCreated, stepAuthUser,
		stepUserName, stepUserParent, stepSocketName, stepSocketPath,
		stepUserPerms, stepSocketScope, stepPermInput:
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

func viewTokens(m Model) string {
	var b strings.Builder
	b.WriteString(titleStyle.Render("Tokens") + "\n\n")

	switch m.step {
	case stepTokenUser:
		b.WriteString("username for new token\n")
		b.WriteString(m.input.View() + "\n")
		b.WriteString(hintStyle.Render("enter confirm  esc cancel"))
		return b.String()
	case stepTokenName:
		b.WriteString(fmt.Sprintf("token name for user %q\n", m.inputBuffer["username"]))
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
		b.WriteString(fmt.Sprintf("token created for user %q\n\n", m.newTokenUsername))
		b.WriteString(tokenStyle.Render(m.newToken) + "\n\n")
		b.WriteString("copy this secret now — it will not be shown again\n")
		b.WriteString("\n" + hintStyle.Render("any key to continue"))
		return b.String()
	case stepNone, stepKeyName, stepKeyValue, stepRotateValue, stepKeyView, stepAuthUser,
		stepUserName, stepUserParent, stepSocketName, stepSocketPath,
		stepUserPerms, stepSocketScope, stepPermInput:
	}

	if m.loading {
		b.WriteString(dimStyle.Render("loading..."))
		return b.String()
	}

	if len(m.tokens) == 0 {
		b.WriteString(dimStyle.Render("no tokens stored"))
	} else {
		for i, t := range m.tokens {
			line := fmt.Sprintf("%-12s  %-20s  %s", t.Username, t.Name, t.Description)
			if i == m.tokenCursor {
				b.WriteString(selectedStyle.Render("> " + line))
			} else {
				b.WriteString("  " + line)
			}
			b.WriteString("\n")
		}
	}

	b.WriteString("\n" + hintStyle.Render("↑/↓ navigate  a add token  d revoke  esc back"))
	return b.String()
}

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

	b.WriteString("\n" + hintStyle.Render("s seal vault  m sockets  esc back  q quit"))
	return b.String()
}

// viewUsers renders the user tree list and management screen.
func viewUsers(m Model) string {
	var b strings.Builder
	b.WriteString(titleStyle.Render("Users") + "\n\n")

	switch m.step {
	case stepUserName:
		b.WriteString("username (slug)\n")
		b.WriteString(m.input.View() + "\n")
		b.WriteString(hintStyle.Render("enter confirm  esc cancel"))
		return b.String()
	case stepUserParent:
		b.WriteString(fmt.Sprintf("parent user for %q\n", m.inputBuffer["name"]))
		b.WriteString(m.input.View() + "\n")
		b.WriteString(hintStyle.Render("enter confirm  esc cancel"))
		return b.String()
	case stepConfirm:
		b.WriteString(fmt.Sprintf("delete %q?  ", m.confirmTarget))
		b.WriteString(hintStyle.Render("y confirm  any other key cancel"))
		return b.String()
	case stepUserPerms:
		return viewPermListScreen("User Permissions", buildUserPermItems(m), m.permCursor,
			"↑/↓ navigate  space toggle/remove  enter add/confirm  esc cancel")
	case stepPermInput:
		if m.inputBuffer["permScreen"] != "socket" {
			b.WriteString(fmt.Sprintf("add %s value\n", m.inputBuffer["permField"]))
			b.WriteString(m.input.View() + "\n")
			b.WriteString(hintStyle.Render("enter confirm  esc back"))
			return b.String()
		}
	case stepNone, stepKeyName, stepKeyValue, stepRotateValue, stepKeyView,
		stepTokenUser, stepTokenName, stepTokenDesc, stepTokenCreated, stepAuthUser,
		stepSocketName, stepSocketPath, stepSocketScope:
	}

	if m.loading {
		b.WriteString(dimStyle.Render("loading..."))
		return b.String()
	}

	if len(m.users) == 0 {
		b.WriteString(dimStyle.Render("no users"))
	} else {
		for i, u := range m.users {
			admin := ""
			if u.Admin {
				admin = "  [admin]"
			}
			parent := u.Parent
			if parent == "" {
				parent = "—"
			}
			line := fmt.Sprintf("%-16s  (parent: %-12s)%s  %d tokens",
				u.Name, parent, admin, u.TokenCount)
			if i == m.userCursor {
				b.WriteString(selectedStyle.Render("> " + line))
			} else {
				b.WriteString("  " + line)
			}
			b.WriteString("\n")
		}
	}

	b.WriteString("\n" + hintStyle.Render("↑/↓ navigate  a add user  t add token  d delete  esc back"))
	return b.String()
}

// viewSockets renders the socket list and management screen.
func viewSockets(m Model) string {
	var b strings.Builder
	b.WriteString(titleStyle.Render("Sockets") + "\n\n")

	switch m.step {
	case stepSocketName:
		b.WriteString("socket name (slug)\n")
		b.WriteString(m.input.View() + "\n")
		b.WriteString(hintStyle.Render("enter confirm  esc cancel"))
		return b.String()
	case stepSocketPath:
		b.WriteString(fmt.Sprintf("path for socket %q\n", m.inputBuffer["name"]))
		b.WriteString(m.input.View() + "\n")
		b.WriteString(hintStyle.Render("enter confirm  esc cancel"))
		return b.String()
	case stepConfirm:
		b.WriteString(fmt.Sprintf("delete %q?  ", m.confirmTarget))
		b.WriteString(hintStyle.Render("y confirm  any other key cancel"))
		return b.String()
	case stepSocketScope:
		return viewPermListScreen("Socket Scope", buildSocketScopeItems(m), m.permCursor,
			"↑/↓ navigate  space toggle/remove  enter add/confirm  esc cancel")
	case stepPermInput:
		if m.inputBuffer["permScreen"] == "socket" {
			b.WriteString(fmt.Sprintf("add %s value\n", m.inputBuffer["permField"]))
			b.WriteString(m.input.View() + "\n")
			b.WriteString(hintStyle.Render("enter confirm  esc back"))
			return b.String()
		}
	case stepNone, stepKeyName, stepKeyValue, stepRotateValue, stepKeyView,
		stepTokenUser, stepTokenName, stepTokenDesc, stepTokenCreated, stepAuthUser,
		stepUserName, stepUserParent, stepUserPerms:
	}

	if m.loading {
		b.WriteString(dimStyle.Render("loading..."))
		return b.String()
	}

	if len(m.sockets) == 0 {
		b.WriteString(dimStyle.Render("no sockets configured"))
	} else {
		for i, s := range m.sockets {
			scope := "scoped"
			if s.Scope.Unrestricted {
				scope = "unrestricted"
			}
			live := ""
			if s.Live {
				live = "  [live]"
			}
			line := fmt.Sprintf("%-16s  %-40s  [%s]%s", s.Name, s.Path, scope, live)
			if i == m.socketCursor {
				b.WriteString(selectedStyle.Render("> " + line))
			} else {
				b.WriteString("  " + line)
			}
			b.WriteString("\n")
		}
	}

	b.WriteString("\n" + hintStyle.Render("↑/↓ navigate  a add  d delete  esc back"))
	return b.String()
}

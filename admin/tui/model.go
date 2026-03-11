// cordova/admin/tui/model.go

package tui

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"cordova/admin/client"
	"cordova/core/ipc"
	"cordova/core/validate"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
)

type screen int

const (
	screenAuth   screen = iota // token entry — shown when no token is pre-supplied
	screenMenu                 // main navigation menu
	screenKeys                 // key list and management
	screenTokens               // token list and management
	screenStatus               // vault status and seal
)

type inputStep int

const (
	stepNone         inputStep = iota // no form active
	stepKeyName                       // entering namespace/name for a new key
	stepKeyValue                      // entering value for a new key (hidden)
	stepRotateValue                   // entering new value for key rotation (hidden)
	stepConfirm                       // y/n confirmation prompt
	stepTokenName                     // entering the slug name for a new token
	stepTokenDesc                     // entering description for a new token
	stepTokenCreated                  // displaying the newly created token secret
	stepKeyView                       // displaying a fetched key value
)

// ── Messages ──────────────────────────────────────────────────────────────────

type authDoneMsg struct {
	client *client.Client
	err    error
}

type keysLoadedMsg struct {
	keys []string
	err  error
}

type tokensLoadedMsg struct {
	tokens []ipc.TokenSummary
	err    error
}

type statusLoadedMsg struct {
	data ipc.StatusData
	err  error
}

type keyValueMsg struct {
	name  string
	value string
	err   error
}

type actionDoneMsg struct {
	err error
}

type tokenCreatedMsg struct {
	name   string
	secret string
	role   string
	err    error
}

// ── Commands (async IPC calls) ─────────────────────────────────────────────────

func probeClient(socketPath, token string) tea.Cmd {
	return func() tea.Msg {
		c := client.New(socketPath, token)
		if err := c.Probe(); err != nil {
			return authDoneMsg{err: err}
		}
		return authDoneMsg{client: c}
	}
}

// loadKeys fetches all key names from the daemon.
func loadKeys(c *client.Client) tea.Cmd {
	return func() tea.Msg {
		resp, err := c.Send(ipc.CmdKeyList, nil)
		if err != nil {
			return keysLoadedMsg{err: err}
		}
		if !resp.OK {
			return keysLoadedMsg{err: fmt.Errorf("%s", resp.Error)}
		}
		var d ipc.KeyListData
		if err := json.Unmarshal(resp.Data, &d); err != nil {
			return keysLoadedMsg{err: err}
		}
		sort.Strings(d.Keys)
		return keysLoadedMsg{keys: d.Keys}
	}
}

// loadTokens fetches all persistent tokens from the daemon.
func loadTokens(c *client.Client) tea.Cmd {
	return func() tea.Msg {
		resp, err := c.Send(ipc.CmdTokenList, nil)
		if err != nil {
			return tokensLoadedMsg{err: err}
		}
		if !resp.OK {
			return tokensLoadedMsg{err: fmt.Errorf("%s", resp.Error)}
		}
		var d ipc.TokenListData
		if err := json.Unmarshal(resp.Data, &d); err != nil {
			return tokensLoadedMsg{err: err}
		}
		return tokensLoadedMsg{tokens: d.Tokens}
	}
}

// loadStatus fetches the daemon's current sealed state and version.
func loadStatus(c *client.Client) tea.Cmd {
	return func() tea.Msg {
		resp, err := c.Send(ipc.CmdStatus, nil)
		if err != nil {
			return statusLoadedMsg{err: err}
		}
		if !resp.OK {
			return statusLoadedMsg{err: fmt.Errorf("%s", resp.Error)}
		}
		var d ipc.StatusData
		if err := json.Unmarshal(resp.Data, &d); err != nil {
			return statusLoadedMsg{err: err}
		}
		return statusLoadedMsg{data: d}
	}
}

// loadKeyValue fetches the plaintext value of a single key from the daemon.
func loadKeyValue(c *client.Client, name string) tea.Cmd {
	return func() tea.Msg {
		resp, err := c.Send(ipc.CmdKeyGet, ipc.KeyGetParams{Name: name})
		if err != nil {
			return keyValueMsg{err: err}
		}
		if !resp.OK {
			return keyValueMsg{err: fmt.Errorf("%s", resp.Error)}
		}
		var d ipc.KeyGetData
		if err := json.Unmarshal(resp.Data, &d); err != nil {
			return keyValueMsg{err: err}
		}
		return keyValueMsg{name: d.Name, value: d.Value}
	}
}

// deleteKey removes a key from the vault.
func deleteKey(c *client.Client, name string) tea.Cmd {
	return func() tea.Msg {
		resp, err := c.Send(ipc.CmdKeyDelete, ipc.KeyDeleteParams{Name: name})
		if err != nil {
			return actionDoneMsg{err: err}
		}
		if !resp.OK {
			return actionDoneMsg{err: fmt.Errorf("%s", resp.Error)}
		}
		return actionDoneMsg{}
	}
}

// setKey adds or rotates a key value.
func setKey(c *client.Client, name, value string) tea.Cmd {
	return func() tea.Msg {
		resp, err := c.Send(ipc.CmdKeySet, ipc.KeySetParams{Name: name, Value: value})
		if err != nil {
			return actionDoneMsg{err: err}
		}
		if !resp.OK {
			return actionDoneMsg{err: fmt.Errorf("%s", resp.Error)}
		}
		return actionDoneMsg{}
	}
}

// createAdminToken creates a new persistent admin-role token with the given
// name and description. ExpiresAt is left empty (persistent). Ephemeral and
// TTL tokens can be created via the CLI with --ephemeral or --ttl.
func createAdminToken(c *client.Client, name, description string) tea.Cmd {
	return func() tea.Msg {
		resp, err := c.Send(ipc.CmdTokenAdd, ipc.TokenAddParams{
			Name:        name,
			Description: description,
			Role:        "admin",
			ExpiresAt:   "", // persistent
		})
		if err != nil {
			return tokenCreatedMsg{err: err}
		}
		if !resp.OK {
			return tokenCreatedMsg{err: fmt.Errorf("%s", resp.Error)}
		}
		var d ipc.TokenAddData
		if err := json.Unmarshal(resp.Data, &d); err != nil {
			return tokenCreatedMsg{err: err}
		}
		return tokenCreatedMsg{name: d.Name, secret: d.Secret, role: d.Role}
	}
}

// revokeToken removes a single token by name.
func revokeToken(c *client.Client, name string) tea.Cmd {
	return func() tea.Msg {
		resp, err := c.Send(ipc.CmdTokenRevoke, ipc.TokenRevokeParams{Name: name})
		if err != nil {
			return actionDoneMsg{err: err}
		}
		if !resp.OK {
			return actionDoneMsg{err: fmt.Errorf("%s", resp.Error)}
		}
		return actionDoneMsg{}
	}
}

// sealVault tells the daemon to seal and exit.
func sealVault(c *client.Client) tea.Cmd {
	return func() tea.Msg {
		resp, err := c.Send(ipc.CmdSeal, nil)
		if err != nil {
			return actionDoneMsg{err: err}
		}
		if !resp.OK {
			return actionDoneMsg{err: fmt.Errorf("%s", resp.Error)}
		}
		return actionDoneMsg{}
	}
}

// ── Model ─────────────────────────────────────────────────────────────────────

// Model is the single source of truth for all TUI state. bubbletea passes it
// by value through Update, so every field is a value type or pointer.
type Model struct {
	// socketPath is the filesystem path of the cordova-vault Unix socket.
	// Stored here so the auth screen can create the client after token entry.
	socketPath string

	// client is the shared IPC connection used by all async commands.
	// It is nil until the user authenticates on screenAuth.
	client *client.Client

	// width is the current terminal width, updated on tea.WindowSizeMsg.
	// Used to scale the banner and border to fill the terminal.
	width int

	// screen is the currently displayed view.
	screen screen

	// menuCursor is the selected item index on the main menu.
	menuCursor int

	// keys is the list of key names displayed on the keys screen.
	keys []string

	// keyCursor is the selected key index on the keys screen.
	keyCursor int

	// tokens is the list of token summaries on the tokens screen.
	tokens []ipc.TokenSummary

	// tokenCursor is the selected token index on the tokens screen.
	tokenCursor int

	// status holds the latest daemon status response.
	status *ipc.StatusData

	// loading is true while an async IPC call is in flight.
	loading bool

	// step tracks the current field being collected in a multi-step form.
	step inputStep

	// input is the active text input widget (name, value, description, etc.).
	input textinput.Model

	// inputBuffer stores values collected in earlier form steps, keyed by
	// field name (e.g. "name", "value").
	inputBuffer map[string]string

	// confirmTarget is the item name or ID targeted by a pending confirmation.
	confirmTarget string

	// confirmAction is the IPC command to execute if the user confirms.
	confirmAction tea.Cmd

	// newToken holds the one-time secret of a just-created token for display.
	// Cleared when the user dismisses the stepTokenCreated screen.
	newToken string

	// selectedKeyValue holds the plaintext value of the key currently being
	// viewed. Cleared when the user dismisses the stepKeyView screen.
	selectedKeyValue string

	// err is a transient error message shown at the bottom of the screen.
	// Cleared on the next keypress.
	err string
}

// initialModel builds the starting Model. If token is non-empty a client is
// created immediately and the menu is shown. If token is empty the auth screen
// is shown so the user can supply one interactively.
func initialModel(socketPath, token string) Model {
	ti := textinput.New()
	ti.CharLimit = 256

	m := Model{
		socketPath:  socketPath,
		screen:      screenAuth,
		input:       ti,
		inputBuffer: make(map[string]string),
	}

	if token != "" {
		m.client = client.New(socketPath, token)
		m.screen = screenMenu
	} else {
		// Auth screen: configure the input for hidden token entry and focus it
		// immediately so the user can start typing without an extra keypress.
		m.input.Placeholder = "token"
		m.input.EchoMode = textinput.EchoPassword
		m.input.Focus()
	}

	return m
}

// ── bubbletea interface ────────────────────────────────────────────────────────

// Init is called once at startup. On the auth screen we just blink the cursor;
// on the menu we immediately fetch vault status.
func (m Model) Init() tea.Cmd {
	if m.screen == screenAuth {
		return textinput.Blink
	}
	return loadStatus(m.client)
}

// Update receives a message and returns the next model and an optional command.
// It dispatches on the current screen and input step.
func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	// Clear transient error on any keypress.
	if _, ok := msg.(tea.KeyMsg); ok {
		m.err = ""
	}

	switch msg := msg.(type) {

	// ── Window resize ─────────────────────────────────────────────────────────

	case tea.WindowSizeMsg:
		m.width = msg.Width
		return m, nil

	// ── Auth ──────────────────────────────────────────────────────────────────

	case authDoneMsg:
		m.loading = false
		if msg.err != nil {
			m.err = msg.err.Error()
			m.input.Focus()
			return m, textinput.Blink
		}
		m.client = msg.client
		m.screen = screenMenu
		m.loading = true
		return m, loadStatus(m.client)

	// ── IPC responses ────────────────────────────────────────────────────────

	case keysLoadedMsg:
		m.loading = false
		if msg.err != nil {
			m.err = msg.err.Error()
		} else {
			m.keys = msg.keys
			m.keyCursor = 0
		}
		return m, nil

	case tokensLoadedMsg:
		m.loading = false
		if msg.err != nil {
			m.err = msg.err.Error()
		} else {
			m.tokens = msg.tokens
			m.tokenCursor = 0
		}
		return m, nil

	case statusLoadedMsg:
		m.loading = false
		if msg.err != nil {
			m.err = msg.err.Error()
		} else {
			m.status = &msg.data
		}
		return m, nil

	case actionDoneMsg:
		m.loading = false
		if msg.err != nil {
			m.err = msg.err.Error()
			return m, nil
		}
		// Refresh the current list after a successful mutation.
		switch m.screen {
		case screenKeys:
			m.loading = true
			return m, loadKeys(m.client)
		case screenTokens:
			m.loading = true
			return m, loadTokens(m.client)
		case screenStatus:
			return m, tea.Quit
		}
		return m, nil

	case keyValueMsg:
		m.loading = false
		if msg.err != nil {
			m.err = msg.err.Error()
			return m, nil
		}
		m.selectedKeyValue = msg.value
		m.step = stepKeyView
		return m, nil

	case tokenCreatedMsg:
		m.loading = false
		if msg.err != nil {
			m.err = msg.err.Error()
			m.step = stepNone
			return m, nil
		}
		m.newToken = msg.secret
		m.step = stepTokenCreated
		return m, nil

	// ── Keyboard ─────────────────────────────────────────────────────────────

	case tea.KeyMsg:
		// If a form is active, route to the form handler.
		if m.step != stepNone {
			return m.updateForm(msg)
		}
		// Otherwise route to the screen handler.
		switch m.screen {
		case screenAuth:
			return m.updateAuth(msg)
		case screenMenu:
			return m.updateMenu(msg)
		case screenKeys:
			return m.updateKeys(msg)
		case screenTokens:
			return m.updateTokens(msg)
		case screenStatus:
			return m.updateStatus(msg)
		}
	}

	return m, nil
}

// ── Screen update handlers ────────────────────────────────────────────────────

// updateAuth handles keypresses on the token entry screen. The textinput
// widget receives every keystroke except Enter (submit) and ctrl+c (quit).
func (m Model) updateAuth(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "ctrl+c":
		return m, tea.Quit
	case "enter":
		val := strings.TrimSpace(m.input.Value())
		if val == "" {
			m.err = "token cannot be empty"
			return m, nil
		}
		// Clear the token from the widget immediately — it is sensitive.
		m.input.SetValue("")
		m.input.Blur()
		m.loading = true
		return m, probeClient(m.socketPath, val)
	}
	var cmd tea.Cmd
	m.input, cmd = m.input.Update(msg)
	return m, cmd
}

// updateMenu handles keypresses on the main menu screen.
func (m Model) updateMenu(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	const items = 3 // Keys, Tokens, Status
	switch msg.String() {
	case "q", "ctrl+c":
		return m, tea.Quit
	case "up", "k":
		if m.menuCursor > 0 {
			m.menuCursor--
		}
	case "down", "j":
		if m.menuCursor < items-1 {
			m.menuCursor++
		}
	case "enter", " ":
		switch m.menuCursor {
		case 0:
			m.screen = screenKeys
			m.loading = true
			return m, loadKeys(m.client)
		case 1:
			m.screen = screenTokens
			m.loading = true
			return m, loadTokens(m.client)
		case 2:
			m.screen = screenStatus
			m.loading = true
			return m, loadStatus(m.client)
		}
	}
	return m, nil
}

// updateKeys handles keypresses on the keys list screen.
func (m Model) updateKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "q", "esc":
		m.screen = screenMenu
	case "up", "k":
		if m.keyCursor > 0 {
			m.keyCursor--
		}
	case "down", "j":
		if m.keyCursor < len(m.keys)-1 {
			m.keyCursor++
		}
	case "enter":
		if len(m.keys) == 0 {
			return m, nil
		}
		m.loading = true
		return m, loadKeyValue(m.client, m.keys[m.keyCursor])
	case "a":
		// Add key: collect namespace/name then value.
		m.step = stepKeyName
		m.input.Placeholder = "namespace/name"
		m.input.EchoMode = textinput.EchoNormal
		m.input.SetValue("")
		m.input.Focus()
		return m, textinput.Blink
	case "r":
		// Rotate selected key: collect new value.
		if len(m.keys) == 0 {
			return m, nil
		}
		m.inputBuffer["name"] = m.keys[m.keyCursor]
		m.step = stepRotateValue
		m.input.Placeholder = "new value"
		m.input.EchoMode = textinput.EchoPassword
		m.input.SetValue("")
		m.input.Focus()
		return m, textinput.Blink
	case "d":
		// Delete selected key: confirm first.
		if len(m.keys) == 0 {
			return m, nil
		}
		name := m.keys[m.keyCursor]
		m.confirmTarget = name
		m.confirmAction = deleteKey(m.client, name)
		m.step = stepConfirm
	}
	return m, nil
}

// updateTokens handles keypresses on the tokens list screen.
func (m Model) updateTokens(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "q", "esc":
		m.screen = screenMenu
	case "up", "k":
		if m.tokenCursor > 0 {
			m.tokenCursor--
		}
	case "down", "j":
		if m.tokenCursor < len(m.tokens)-1 {
			m.tokenCursor++
		}
	case "a":
		// Create admin token: collect name first, then description.
		m.step = stepTokenName
		m.input.Placeholder = "name (e.g. ops-box)"
		m.input.EchoMode = textinput.EchoNormal
		m.input.SetValue("")
		m.input.Focus()
		return m, textinput.Blink
	case "d", "r":
		// Revoke selected token: confirm first.
		if len(m.tokens) == 0 {
			return m, nil
		}
		tok := m.tokens[m.tokenCursor]
		m.confirmTarget = tok.Name
		m.confirmAction = revokeToken(m.client, tok.Name)
		m.step = stepConfirm
	}
	return m, nil
}

// updateStatus handles keypresses on the status screen.
func (m Model) updateStatus(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "q", "esc":
		m.screen = screenMenu
	case "s":
		// Seal the vault; the actionDoneMsg handler will quit the TUI.
		m.loading = true
		return m, sealVault(m.client)
	}
	return m, nil
}

// updateForm handles keypresses while a multi-step form is active.
func (m Model) updateForm(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch m.step {

	case stepConfirm:
		// Single-keypress confirmation: y confirms, anything else cancels.
		switch strings.ToLower(msg.String()) {
		case "y":
			m.step = stepNone
			m.loading = true
			return m, m.confirmAction
		default:
			m.step = stepNone
		}
		return m, nil

	case stepKeyView:
		// Any key dismisses the value display.
		m.selectedKeyValue = ""
		m.step = stepNone
		return m, nil

	case stepTokenCreated:
		// Any key dismisses the new-token display and refreshes the list.
		m.newToken = ""
		m.step = stepNone
		m.loading = true
		return m, loadTokens(m.client)

	default:
		// Text input steps: delegate to the textinput widget then check Enter/Esc.
		switch msg.String() {
		case "esc":
			m.step = stepNone
			m.inputBuffer = make(map[string]string)
			m.input.Blur()
			return m, nil

		case "enter":
			val := strings.TrimSpace(m.input.Value())
			return m.advanceForm(val)
		}

		var cmd tea.Cmd
		m.input, cmd = m.input.Update(msg)
		return m, cmd
	}
}

// advanceForm is called when Enter is pressed during a text-input form step.
// It validates the current field value and either advances to the next step or
// fires the IPC command.
func (m Model) advanceForm(val string) (tea.Model, tea.Cmd) {
	switch m.step {

	case stepKeyName:
		if val == "" {
			m.err = "name cannot be empty"
			return m, nil
		}
		m.inputBuffer["name"] = val
		m.step = stepKeyValue
		m.input.Placeholder = "value"
		m.input.EchoMode = textinput.EchoPassword
		m.input.SetValue("")
		return m, textinput.Blink

	case stepKeyValue:
		if val == "" {
			m.err = "value cannot be empty"
			return m, nil
		}
		name := m.inputBuffer["name"]
		m.step = stepNone
		m.inputBuffer = make(map[string]string)
		m.input.Blur()
		m.loading = true
		return m, setKey(m.client, name, val)

	case stepRotateValue:
		if val == "" {
			m.err = "value cannot be empty"
			return m, nil
		}
		name := m.inputBuffer["name"]
		m.step = stepNone
		m.inputBuffer = make(map[string]string)
		m.input.Blur()
		m.loading = true
		return m, setKey(m.client, name, val)

	case stepTokenName:
		if err := validate.ValidateTokenName(val); err != nil {
			m.err = err.Error()
			return m, nil
		}
		m.inputBuffer["name"] = val
		m.step = stepTokenDesc
		m.input.Placeholder = "description"
		m.input.EchoMode = textinput.EchoNormal
		m.input.SetValue("")
		return m, textinput.Blink

	case stepTokenDesc:
		if val == "" {
			m.err = "description cannot be empty"
			return m, nil
		}
		name := m.inputBuffer["name"]
		m.step = stepNone
		m.inputBuffer = make(map[string]string)
		m.input.Blur()
		m.loading = true
		return m, createAdminToken(m.client, name, val)
	}

	return m, nil
}

// ── Entry point ───────────────────────────────────────────────────────────────

// Run starts the bubbletea program in alt-screen mode. If token is non-empty
// the client is created immediately and the menu is shown. If token is empty
// the auth screen is shown so the user can supply one interactively.
// Run blocks until the user quits.
func Run(socketPath, token string) error {
	p := tea.NewProgram(initialModel(socketPath, token), tea.WithAltScreen())
	_, err := p.Run()
	return err
}

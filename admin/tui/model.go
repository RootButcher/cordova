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
	screenAuth   screen = iota // username + token entry
	screenMenu                 // main navigation menu
	screenKeys                 // key list and management
	screenTokens               // token list and management
	screenStatus               // vault status and seal
)

type inputStep int

const (
	stepNone         inputStep = iota // no form active
	stepAuthUser                      // entering username on auth screen
	stepKeyName                       // entering namespace/name for a new key
	stepKeyValue                      // entering value for a new key (hidden)
	stepRotateValue                   // entering new value for key rotation (hidden)
	stepConfirm                       // y/n confirmation prompt
	stepTokenUser                     // entering username for a new token
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
	username string
	name     string
	secret   string
	err      error
}

// ── Commands (async IPC calls) ─────────────────────────────────────────────────

func probeClient(socketPath, username, token string) tea.Cmd {
	return func() tea.Msg {
		c := client.New(socketPath, username, token)
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

// loadTokens fetches all tokens from the daemon.
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

// createToken creates a new persistent token for the given user.
func createToken(c *client.Client, username, name, description string) tea.Cmd {
	return func() tea.Msg {
		resp, err := c.Send(ipc.CmdTokenAdd, ipc.TokenAddParams{
			Username:    username,
			Name:        name,
			Description: description,
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
		return tokenCreatedMsg{username: d.Username, name: d.Name, secret: d.Secret}
	}
}

// revokeToken removes a single token by username and name.
func revokeToken(c *client.Client, username, name string) tea.Cmd {
	return func() tea.Msg {
		resp, err := c.Send(ipc.CmdTokenRevoke, ipc.TokenRevokeParams{
			Username: username,
			Name:     name,
		})
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

// Model is the single source of truth for all TUI state.
type Model struct {
	socketPath string
	client     *client.Client
	width      int
	screen     screen
	menuCursor int

	keys      []string
	keyCursor int

	tokens      []ipc.TokenSummary
	tokenCursor int

	status  *ipc.StatusData
	loading bool

	step        inputStep
	input       textinput.Model
	inputBuffer map[string]string

	confirmTarget  string
	confirmAction  tea.Cmd

	newToken         string
	newTokenUsername string
	selectedKeyValue string

	err string

	// authUsername holds the username entered on the auth screen before the
	// token step begins.
	authUsername string
}

// initialModel builds the starting Model. If both username and token are
// non-empty a client is created immediately and the menu is shown.
func initialModel(socketPath, username, token string) Model {
	ti := textinput.New()
	ti.CharLimit = 256

	m := Model{
		socketPath:  socketPath,
		screen:      screenAuth,
		input:       ti,
		inputBuffer: make(map[string]string),
	}

	if username != "" && token != "" {
		m.client = client.New(socketPath, username, token)
		m.authUsername = username
		m.screen = screenMenu
	} else {
		// Show username input first.
		m.step = stepAuthUser
		m.input.Placeholder = "username"
		m.input.EchoMode = textinput.EchoNormal
		m.input.Focus()
	}

	return m
}

// ── bubbletea interface ────────────────────────────────────────────────────────

// Init is called once at startup.
func (m Model) Init() tea.Cmd {
	if m.screen == screenAuth {
		return textinput.Blink
	}
	return loadStatus(m.client)
}

// Update receives a message and returns the next model and an optional command.
func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	if _, ok := msg.(tea.KeyMsg); ok {
		m.err = ""
	}

	switch msg := msg.(type) {

	case tea.WindowSizeMsg:
		m.width = msg.Width
		return m, nil

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
		switch m.screen {
		case screenKeys:
			m.loading = true
			return m, loadKeys(m.client)
		case screenTokens:
			m.loading = true
			return m, loadTokens(m.client)
		case screenStatus:
			return m, tea.Quit
		case screenAuth, screenMenu:
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
		m.newTokenUsername = msg.username
		m.step = stepTokenCreated
		return m, nil

	case tea.KeyMsg:
		if m.step != stepNone {
			return m.updateForm(msg)
		}
		// Special case: username was entered, now awaiting token input.
		if m.inputBuffer["awaitingToken"] == "1" {
			return m.updateAuthToken(msg)
		}
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

func (m Model) updateAuth(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "ctrl+c":
		return m, tea.Quit
	}
	var cmd tea.Cmd
	m.input, cmd = m.input.Update(msg)
	return m, cmd
}

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
		m.step = stepKeyName
		m.input.Placeholder = "namespace/name"
		m.input.EchoMode = textinput.EchoNormal
		m.input.SetValue("")
		m.input.Focus()
		return m, textinput.Blink
	case "r":
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
		// Start token creation: first collect username.
		m.step = stepTokenUser
		m.input.Placeholder = "username (e.g. root)"
		m.input.EchoMode = textinput.EchoNormal
		m.input.SetValue("")
		m.input.Focus()
		return m, textinput.Blink
	case "d", "r":
		if len(m.tokens) == 0 {
			return m, nil
		}
		tok := m.tokens[m.tokenCursor]
		m.confirmTarget = tok.Username + "/" + tok.Name
		m.confirmAction = revokeToken(m.client, tok.Username, tok.Name)
		m.step = stepConfirm
	}
	return m, nil
}

func (m Model) updateStatus(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "q", "esc":
		m.screen = screenMenu
	case "s":
		m.loading = true
		return m, sealVault(m.client)
	}
	return m, nil
}

// updateForm handles keypresses while a multi-step form is active.
func (m Model) updateForm(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch m.step {

	case stepAuthUser:
		// Username entry on auth screen.
		switch msg.String() {
		case "ctrl+c":
			return m, tea.Quit
		case "enter":
			val := strings.TrimSpace(m.input.Value())
			if val == "" {
				m.err = "username cannot be empty"
				return m, nil
			}
			m.authUsername = val
			m.input.SetValue("")
			// Switch to token (password) entry.
			m.input.Placeholder = "token"
			m.input.EchoMode = textinput.EchoPassword
			m.input.Focus()
			m.step = stepNone // handled by updateAuth via token entry below
			// Reuse stepNone + a flag — actually just use a different approach:
			// Clear step and set a pending-token flag via inputBuffer.
			m.inputBuffer["awaitingToken"] = "1"
			return m, textinput.Blink
		}
		var cmd tea.Cmd
		m.input, cmd = m.input.Update(msg)
		return m, cmd

	case stepConfirm:
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
		m.selectedKeyValue = ""
		m.step = stepNone
		return m, nil

	case stepTokenCreated:
		m.newToken = ""
		m.newTokenUsername = ""
		m.step = stepNone
		m.loading = true
		return m, loadTokens(m.client)

	default:
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

// advanceForm validates the current field and moves to the next step or fires.
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

	case stepTokenUser:
		if err := validate.ValidateUsername(val); err != nil {
			m.err = err.Error()
			return m, nil
		}
		m.inputBuffer["username"] = val
		m.step = stepTokenName
		m.input.Placeholder = "name (e.g. ops-box)"
		m.input.EchoMode = textinput.EchoNormal
		m.input.SetValue("")
		return m, textinput.Blink

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
		username := m.inputBuffer["username"]
		name := m.inputBuffer["name"]
		m.step = stepNone
		m.inputBuffer = make(map[string]string)
		m.input.Blur()
		m.loading = true
		return m, createToken(m.client, username, name, val)

	case stepNone, stepConfirm, stepTokenCreated, stepKeyView, stepAuthUser:
	}

	return m, nil
}

// ── Auth screen token entry ───────────────────────────────────────────────────

// updateAuthToken is called from updateAuth when awaiting a token after
// username has been entered.
func (m Model) updateAuthToken(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "ctrl+c":
		return m, tea.Quit
	case "enter":
		val := strings.TrimSpace(m.input.Value())
		if val == "" {
			m.err = "token cannot be empty"
			return m, nil
		}
		m.input.SetValue("")
		m.input.Blur()
		delete(m.inputBuffer, "awaitingToken")
		m.loading = true
		return m, probeClient(m.socketPath, m.authUsername, val)
	}
	var cmd tea.Cmd
	m.input, cmd = m.input.Update(msg)
	return m, cmd
}

// ── Entry point ───────────────────────────────────────────────────────────────

// Run starts the bubbletea program in alt-screen mode.
func Run(socketPath, username, token string) error {
	p := tea.NewProgram(initialModel(socketPath, username, token), tea.WithAltScreen())
	_, err := p.Run()
	return err
}
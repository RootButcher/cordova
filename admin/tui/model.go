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
	screenAuth    screen = iota // username + token entry
	screenMenu                  // main navigation menu
	screenKeys                  // key list and management
	screenTokens                // token list and management
	screenStatus                // vault status and seal
	screenUsers                 // user tree list and management
	screenSockets               // socket list and management (entered from screenStatus)
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
	stepUserName                      // entering slug name for a new user
	stepUserParent                    // entering parent username for a new user
	stepSocketName                    // entering slug name for a new socket
	stepSocketPath                    // entering filesystem path for a new socket
	stepUserPerms                     // cursor-navigable permission toggle list for user creation
	stepSocketScope                   // cursor-navigable scope toggle list for socket creation
	stepPermInput                     // text input for adding a single namespace / key / socket value
)

// permItemKind classifies one row in a permission toggle list.
type permItemKind int

const (
	permBoolToggle permItemKind = iota // space or enter flips the bool
	permListEntry                      // existing string value; space/d removes it
	permAddAction                      // "+ add …"; enter opens stepPermInput
	permDone                           // "✓ done"; enter fires the IPC command
)

// permItem is one row in the permission toggle list.
type permItem struct {
	kind  permItemKind
	key   string // "admin","writable","unrestricted" for bool; "ns","key","sock" for lists
	value string // listEntry: the value; addAction: display label
	on    bool   // boolToggle: current state
	dim   bool   // render dimmed (e.g. ns/key rows when unrestricted overrides)
}

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

// usersLoadedMsg carries the result of a user.list IPC call.
type usersLoadedMsg struct {
	users []ipc.UserSummary
	err   error
}

// socketsLoadedMsg carries the result of a socket.list IPC call.
type socketsLoadedMsg struct {
	sockets []ipc.SocketSummary
	err     error
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

// loadUsers fetches all users from the daemon.
func loadUsers(c *client.Client) tea.Cmd {
	return func() tea.Msg {
		resp, err := c.Send(ipc.CmdUserList, nil)
		if err != nil {
			return usersLoadedMsg{err: err}
		}
		if !resp.OK {
			return usersLoadedMsg{err: fmt.Errorf("%s", resp.Error)}
		}
		var d ipc.UserListData
		if err := json.Unmarshal(resp.Data, &d); err != nil {
			return usersLoadedMsg{err: err}
		}
		return usersLoadedMsg{users: d.Users}
	}
}

// createUser adds a new child user under the given parent with the given permissions.
func createUser(c *client.Client, name, parent string, admin, writable bool, ns, keys, socks []string) tea.Cmd {
	return func() tea.Msg {
		resp, err := c.Send(ipc.CmdUserAdd, ipc.UserAddParams{
			Name:       name,
			Parent:     parent,
			Admin:      admin,
			Writable:   writable,
			Namespaces: ns,
			Keys:       keys,
			Sockets:    socks,
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

// deleteUser removes a user from the daemon.
func deleteUser(c *client.Client, name string) tea.Cmd {
	return func() tea.Msg {
		resp, err := c.Send(ipc.CmdUserDelete, ipc.UserDeleteParams{Name: name})
		if err != nil {
			return actionDoneMsg{err: err}
		}
		if !resp.OK {
			return actionDoneMsg{err: fmt.Errorf("%s", resp.Error)}
		}
		return actionDoneMsg{}
	}
}

// loadSockets fetches all sockets from the daemon.
func loadSockets(c *client.Client) tea.Cmd {
	return func() tea.Msg {
		resp, err := c.Send(ipc.CmdSocketList, nil)
		if err != nil {
			return socketsLoadedMsg{err: err}
		}
		if !resp.OK {
			return socketsLoadedMsg{err: fmt.Errorf("%s", resp.Error)}
		}
		var d ipc.SocketListData
		if err := json.Unmarshal(resp.Data, &d); err != nil {
			return socketsLoadedMsg{err: err}
		}
		return socketsLoadedMsg{sockets: d.Sockets}
	}
}

// addSocket registers a socket with the daemon using the given scope settings.
func addSocket(c *client.Client, name, path string, unrestricted, writable bool, ns, keys []string) tea.Cmd {
	return func() tea.Msg {
		resp, err := c.Send(ipc.CmdSocketAdd, ipc.SocketAddParams{
			Name: name,
			Path: path,
			Scope: ipc.SocketScope{
				Unrestricted: unrestricted,
				Writable:     writable,
				Namespaces:   ns,
				Keys:         keys,
			},
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

// deleteSocket removes a socket from the daemon.
func deleteSocket(c *client.Client, name string) tea.Cmd {
	return func() tea.Msg {
		resp, err := c.Send(ipc.CmdSocketDelete, ipc.SocketDeleteParams{Name: name})
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

	users      []ipc.UserSummary
	userCursor int

	sockets      []ipc.SocketSummary
	socketCursor int

	status  *ipc.StatusData
	loading bool

	step        inputStep
	input       textinput.Model
	inputBuffer map[string]string

	confirmTarget string
	confirmAction tea.Cmd

	newToken         string
	newTokenUsername string
	selectedKeyValue string

	err string

	// authUsername holds the username entered on the auth screen before the
	// token step begins.
	authUsername string

	// perm state for user/socket creation forms.
	permCursor int
	permAdmin  bool     // user: admin flag; socket: unrestricted flag
	permWrite  bool     // writable flag (both)
	permNS     []string // allowed namespaces
	permKeys   []string // allowed keys
	permSocks  []string // user only: allowed socket names
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

	case usersLoadedMsg:
		m.loading = false
		if msg.err != nil {
			m.err = msg.err.Error()
		} else {
			m.users = msg.users
			m.userCursor = 0
		}
		return m, nil

	case socketsLoadedMsg:
		m.loading = false
		if msg.err != nil {
			m.err = msg.err.Error()
		} else {
			m.sockets = msg.sockets
			m.socketCursor = 0
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
		case screenUsers:
			m.loading = true
			return m, loadUsers(m.client)
		case screenSockets:
			m.loading = true
			return m, loadSockets(m.client)
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
		case screenUsers:
			return m.updateUsers(msg)
		case screenSockets:
			return m.updateSockets(msg)
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
	const items = 4 // Keys, Tokens, Users, Admin
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
			m.screen = screenUsers
			m.loading = true
			return m, loadUsers(m.client)
		case 3:
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
	case "m":
		m.screen = screenSockets
		m.loading = true
		return m, loadSockets(m.client)
	}
	return m, nil
}

func (m Model) updateUsers(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "q", "esc":
		m.screen = screenMenu
	case "up", "k":
		if m.userCursor > 0 {
			m.userCursor--
		}
	case "down", "j":
		if m.userCursor < len(m.users)-1 {
			m.userCursor++
		}
	case "a":
		m.step = stepUserName
		m.input.Placeholder = "username (slug)"
		m.input.EchoMode = textinput.EchoNormal
		m.input.SetValue("")
		m.input.Focus()
		return m, textinput.Blink
	case "t":
		if len(m.users) == 0 {
			return m, nil
		}
		u := m.users[m.userCursor]
		m.inputBuffer["username"] = u.Name
		m.step = stepTokenName
		m.input.Placeholder = "name (e.g. ops-box)"
		m.input.EchoMode = textinput.EchoNormal
		m.input.SetValue("")
		m.input.Focus()
		m.screen = screenTokens
		return m, textinput.Blink
	case "d":
		if len(m.users) == 0 {
			return m, nil
		}
		name := m.users[m.userCursor].Name
		m.confirmTarget = name
		m.confirmAction = deleteUser(m.client, name)
		m.step = stepConfirm
	}
	return m, nil
}

func (m Model) updateSockets(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "q", "esc":
		m.screen = screenStatus
	case "up", "k":
		if m.socketCursor > 0 {
			m.socketCursor--
		}
	case "down", "j":
		if m.socketCursor < len(m.sockets)-1 {
			m.socketCursor++
		}
	case "a":
		m.step = stepSocketName
		m.input.Placeholder = "socket name (slug)"
		m.input.EchoMode = textinput.EchoNormal
		m.input.SetValue("")
		m.input.Focus()
		return m, textinput.Blink
	case "d":
		if len(m.sockets) == 0 {
			return m, nil
		}
		name := m.sockets[m.socketCursor].Name
		m.confirmTarget = name
		m.confirmAction = deleteSocket(m.client, name)
		m.step = stepConfirm
	}
	return m, nil
}

// removeString removes the first occurrence of val from slice.
func removeString(slice []string, val string) []string {
	for i, s := range slice {
		if s == val {
			return append(slice[:i], slice[i+1:]...)
		}
	}
	return slice
}

// buildUserPermItems builds the flat permission toggle list for user creation.
func buildUserPermItems(m Model) []permItem {
	items := []permItem{
		{kind: permBoolToggle, key: "admin", on: m.permAdmin},
		{kind: permBoolToggle, key: "writable", on: m.permWrite},
	}
	for _, ns := range m.permNS {
		items = append(items, permItem{kind: permListEntry, key: "ns", value: ns})
	}
	items = append(items, permItem{kind: permAddAction, key: "ns", value: "add namespace"})
	for _, k := range m.permKeys {
		items = append(items, permItem{kind: permListEntry, key: "key", value: k})
	}
	items = append(items, permItem{kind: permAddAction, key: "key", value: "add key"})
	for _, s := range m.permSocks {
		items = append(items, permItem{kind: permListEntry, key: "sock", value: s})
	}
	items = append(items, permItem{kind: permAddAction, key: "sock", value: "add socket"})
	items = append(items, permItem{kind: permDone, value: "done"})
	return items
}

// buildSocketScopeItems builds the flat scope toggle list for socket creation.
// Namespace/key entries are dimmed when unrestricted is on.
func buildSocketScopeItems(m Model) []permItem {
	unrestricted := m.permAdmin
	items := []permItem{
		{kind: permBoolToggle, key: "unrestricted", on: unrestricted},
		{kind: permBoolToggle, key: "writable", on: m.permWrite},
	}
	for _, ns := range m.permNS {
		items = append(items, permItem{kind: permListEntry, key: "ns", value: ns, dim: unrestricted})
	}
	items = append(items, permItem{kind: permAddAction, key: "ns", value: "add namespace", dim: unrestricted})
	for _, k := range m.permKeys {
		items = append(items, permItem{kind: permListEntry, key: "key", value: k, dim: unrestricted})
	}
	items = append(items, permItem{kind: permAddAction, key: "key", value: "add key", dim: unrestricted})
	items = append(items, permItem{kind: permDone, value: "done"})
	return items
}

// updateUserPerms handles key-presses on the user permission toggle screen.
func (m Model) updateUserPerms(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	items := buildUserPermItems(m)
	switch msg.String() {
	case "up", "k":
		if m.permCursor > 0 {
			m.permCursor--
		}
	case "down", "j":
		if m.permCursor < len(items)-1 {
			m.permCursor++
		}
	case " ":
		if m.permCursor >= len(items) {
			break
		}
		item := items[m.permCursor]
		switch item.kind {
		case permBoolToggle:
			switch item.key {
			case "admin":
				m.permAdmin = !m.permAdmin
			case "writable":
				m.permWrite = !m.permWrite
			}
		case permListEntry:
			switch item.key {
			case "ns":
				m.permNS = removeString(m.permNS, item.value)
			case "key":
				m.permKeys = removeString(m.permKeys, item.value)
			case "sock":
				m.permSocks = removeString(m.permSocks, item.value)
			}
			newItems := buildUserPermItems(m)
			if m.permCursor >= len(newItems) {
				m.permCursor = len(newItems) - 1
			}
		case permAddAction:
		case permDone:
		}
	case "enter":
		if m.permCursor >= len(items) {
			break
		}
		item := items[m.permCursor]
		switch item.kind {
		case permBoolToggle:
			switch item.key {
			case "admin":
				m.permAdmin = !m.permAdmin
			case "writable":
				m.permWrite = !m.permWrite
			}
		case permAddAction:
			m.inputBuffer["permField"] = item.key
			m.inputBuffer["permScreen"] = "user"
			m.step = stepPermInput
			m.input.Placeholder = "value"
			m.input.EchoMode = textinput.EchoNormal
			m.input.SetValue("")
			m.input.Focus()
			return m, textinput.Blink
		case permDone:
			name := m.inputBuffer["name"]
			parent := m.inputBuffer["parent"]
			admin, writable := m.permAdmin, m.permWrite
			ns, keys, socks := m.permNS, m.permKeys, m.permSocks
			m.step = stepNone
			m.inputBuffer = make(map[string]string)
			m.permAdmin, m.permWrite = false, false
			m.permNS, m.permKeys, m.permSocks = nil, nil, nil
			m.permCursor = 0
			m.loading = true
			return m, createUser(m.client, name, parent, admin, writable, ns, keys, socks)
		case permListEntry:
		}
	case "d":
		if m.permCursor >= len(items) {
			break
		}
		item := items[m.permCursor]
		if item.kind == permListEntry {
			switch item.key {
			case "ns":
				m.permNS = removeString(m.permNS, item.value)
			case "key":
				m.permKeys = removeString(m.permKeys, item.value)
			case "sock":
				m.permSocks = removeString(m.permSocks, item.value)
			}
			newItems := buildUserPermItems(m)
			if m.permCursor >= len(newItems) {
				m.permCursor = len(newItems) - 1
			}
		}
	case "esc":
		m.step = stepNone
		m.inputBuffer = make(map[string]string)
		m.permAdmin, m.permWrite = false, false
		m.permNS, m.permKeys, m.permSocks = nil, nil, nil
		m.permCursor = 0
	}
	return m, nil
}

// updateSocketScope handles key-presses on the socket scope toggle screen.
func (m Model) updateSocketScope(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	items := buildSocketScopeItems(m)
	switch msg.String() {
	case "up", "k":
		if m.permCursor > 0 {
			m.permCursor--
		}
	case "down", "j":
		if m.permCursor < len(items)-1 {
			m.permCursor++
		}
	case " ":
		if m.permCursor >= len(items) {
			break
		}
		item := items[m.permCursor]
		switch item.kind {
		case permBoolToggle:
			switch item.key {
			case "unrestricted":
				m.permAdmin = !m.permAdmin
			case "writable":
				m.permWrite = !m.permWrite
			}
		case permListEntry:
			switch item.key {
			case "ns":
				m.permNS = removeString(m.permNS, item.value)
			case "key":
				m.permKeys = removeString(m.permKeys, item.value)
			}
			newItems := buildSocketScopeItems(m)
			if m.permCursor >= len(newItems) {
				m.permCursor = len(newItems) - 1
			}
		case permAddAction:
		case permDone:
		}
	case "enter":
		if m.permCursor >= len(items) {
			break
		}
		item := items[m.permCursor]
		switch item.kind {
		case permBoolToggle:
			switch item.key {
			case "unrestricted":
				m.permAdmin = !m.permAdmin
			case "writable":
				m.permWrite = !m.permWrite
			}
		case permAddAction:
			m.inputBuffer["permField"] = item.key
			m.inputBuffer["permScreen"] = "socket"
			m.step = stepPermInput
			m.input.Placeholder = "value"
			m.input.EchoMode = textinput.EchoNormal
			m.input.SetValue("")
			m.input.Focus()
			return m, textinput.Blink
		case permDone:
			name := m.inputBuffer["name"]
			path := m.inputBuffer["path"]
			unrestricted, writable := m.permAdmin, m.permWrite
			ns, keys := m.permNS, m.permKeys
			m.step = stepNone
			m.inputBuffer = make(map[string]string)
			m.permAdmin, m.permWrite = false, false
			m.permNS, m.permKeys = nil, nil
			m.permCursor = 0
			m.loading = true
			return m, addSocket(m.client, name, path, unrestricted, writable, ns, keys)
		case permListEntry:
		}
	case "d":
		if m.permCursor >= len(items) {
			break
		}
		item := items[m.permCursor]
		if item.kind == permListEntry {
			switch item.key {
			case "ns":
				m.permNS = removeString(m.permNS, item.value)
			case "key":
				m.permKeys = removeString(m.permKeys, item.value)
			}
			newItems := buildSocketScopeItems(m)
			if m.permCursor >= len(newItems) {
				m.permCursor = len(newItems) - 1
			}
		}
	case "esc":
		m.step = stepNone
		m.inputBuffer = make(map[string]string)
		m.permAdmin, m.permWrite = false, false
		m.permNS, m.permKeys = nil, nil
		m.permCursor = 0
	}
	return m, nil
}

// updateForm handles key-presses while a multistep form is active.
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

	case stepUserPerms:
		return m.updateUserPerms(msg)

	case stepSocketScope:
		return m.updateSocketScope(msg)

	case stepPermInput:
		switch msg.String() {
		case "esc":
			if m.inputBuffer["permScreen"] == "socket" {
				m.step = stepSocketScope
			} else {
				m.step = stepUserPerms
			}
			m.input.Blur()
			m.input.SetValue("")
			return m, nil
		case "enter":
			val := strings.TrimSpace(m.input.Value())
			return m.advanceForm(val)
		}
		var cmd tea.Cmd
		m.input, cmd = m.input.Update(msg)
		return m, cmd

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
		if err := validate.Username(val); err != nil {
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
		if err := validate.TokenName(val); err != nil {
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

	case stepUserName:
		if err := validate.Username(val); err != nil {
			m.err = err.Error()
			return m, nil
		}
		m.inputBuffer["name"] = val
		m.step = stepUserParent
		m.input.Placeholder = "parent username"
		m.input.EchoMode = textinput.EchoNormal
		m.input.SetValue("")
		return m, textinput.Blink

	case stepUserParent:
		if err := validate.Username(val); err != nil {
			m.err = err.Error()
			return m, nil
		}
		m.inputBuffer["parent"] = val
		m.permAdmin = false
		m.permWrite = false
		m.permNS = nil
		m.permKeys = nil
		m.permSocks = nil
		m.permCursor = 0
		m.step = stepUserPerms
		m.input.Blur()
		return m, textinput.Blink

	case stepSocketName:
		if err := validate.SocketName(val); err != nil {
			m.err = err.Error()
			return m, nil
		}
		m.inputBuffer["name"] = val
		m.step = stepSocketPath
		m.input.Placeholder = "socket path"
		m.input.EchoMode = textinput.EchoNormal
		m.input.SetValue("")
		return m, textinput.Blink

	case stepSocketPath:
		if val == "" {
			m.err = "path cannot be empty"
			return m, nil
		}
		m.inputBuffer["path"] = val
		m.permAdmin = false
		m.permWrite = false
		m.permNS = nil
		m.permKeys = nil
		m.permCursor = 0
		m.step = stepSocketScope
		m.input.Blur()
		return m, nil

	case stepPermInput:
		if val == "" {
			m.err = "value cannot be empty"
			return m, nil
		}
		field := m.inputBuffer["permField"]
		switch field {
		case "ns":
			m.permNS = append(m.permNS, val)
		case "key":
			m.permKeys = append(m.permKeys, val)
		case "sock":
			m.permSocks = append(m.permSocks, val)
		}
		if m.inputBuffer["permScreen"] == "socket" {
			m.step = stepSocketScope
		} else {
			m.step = stepUserPerms
		}
		m.input.Blur()
		m.input.SetValue("")
		return m, nil

	case stepNone, stepConfirm, stepTokenCreated, stepKeyView, stepAuthUser,
		stepUserPerms, stepSocketScope:
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

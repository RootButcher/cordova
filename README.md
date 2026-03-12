# Cordova

A lightweight secrets appliance targeting Raspberry Pi Zero 2W. Secrets are encrypted at rest
and served over a Unix socket. The decrypted state lives in memory only while the daemon is running.

---

## Modules

Cordova is a Go workspace containing independent modules.

```
cordova/
├── go.work
├── core/   - module cordova/core   (daemon, no TUI dependencies)
├── admin/  - module cordova/admin  (TUI + CLI client)
├── http/   - [Future] serves secretes over http
└── ssh|scp?- [Future] serves secretes to ssh clients, needs planning.
```

### `cordova/core`

The daemon and all its internals. Has no UI dependencies.

| Package              | Role                                                                  |
|----------------------|-----------------------------------------------------------------------|
| `ipc/`               | Shared wire protocol — importable by other mods                       |
| `validate/`          | Shared validation rules — importable by other mods                    |
| `internal/vault/`    | AES-256-GCM encryption, vault file format, token store                |
| `internal/auth/`     | All authentication logic — single entry point for every auth decision |
| `internal/store/`    | Thread-safe in-memory vault state                                     |
| `internal/socket/`   | Transport layer — reads request, calls auth, writes response          |
| `internal/audit/`    | Structured JSON audit logging                                         |
| `internal/config/`   | `config.yaml` parsing and socket config                               |
| `cmd/cordova-vault/` | Daemon binary                                                         |

### `cordova/admin`

The admin client. Imports `cordova/core/ipc` for wire types; and `cordova/core/validate` to prevalidate format cannot access any
`cordova/core/internal/` package (enforced by Go's `internal/` visibility rule).

| Package              | Role                                                  |
|----------------------|-------------------------------------------------------|
| `client/`            | IPC client — dials the socket and sends JSON requests |
| `cli/`               | Cobra subcommands (`key`, `token`, `status`)          |
| `tui/`               | Bubbletea interactive terminal UI                     |
| `cmd/cordova-admin/` | Admin binary                                          |

Direct dependencies: `cordova/core`, `charmbracelet/bubbletea`, `charmbracelet/bubbles`,
`charmbracelet/lipgloss`, `cobra`, `golang.org/x/term`

---

## Binaries

| Binary          | Module          | Role                                            |
|-----------------|-----------------|-------------------------------------------------|
| `cordova-vault` | `cordova/core`  | Daemon — encrypts vault, serves Unix socket     |
| `cordova-admin` | `cordova/admin` | Admin client — TUI (default) or CLI subcommands |

`cordova-http` and `cordova-ssh` are planned. They will be separate modules that reference
`cordova/core/ipc` for the wire protocol, following the same pattern as `cordova/admin`.

---


### Auth flow

Every connection on the socket passes through `auth.Authenticator.Authenticate(token, socket, command)`.
Auth owns the full decision: token lookup, expiry cleanup (revoke + persist), role check, and
audit logging. The socket layer only reads the result — it never inspects tokens or makes
policy decisions itself.

---

## Token model

---

## Build

```bash
task build:all        # build both binaries for local macOS
task build:pi:all     # cross-compile both for Raspberry Pi (arm64, CGO_ENABLED=0)
task deploy:pi        # cross-compile + SCP to Pi, restart service
task test             # run all tests across both modules
task tidy             # go mod tidy for both modules
task clean            # remove build/ artifacts
```
---

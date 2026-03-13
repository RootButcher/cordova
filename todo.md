# TODO

## TUI

- [ ] Socket config scope screen: "add namespace" and "add key" action rows are not highlighted when selected (`admin/tui/`)

## Auth

- [ ] Refactor authentication so users have a set of auth methods (currently token-only); add support for password-based auth and certificate-based auth as additional method types

## Audit Log

- [ ] Audit log access: live feed via TUI (gRPC server-streaming); last-N entries served as JSON over HTTP (`admin/tui/`, `http/`)

## Docs

- [ ] `http/`: write `README.md` demonstrating basic curl usage — get, set, and other common commands; include a sample shell script showing how to fetch a secret in a real workflow

## Build

- [ ] `task clean` — make it selective: remove `build/` binaries only, preserve `config.yaml` and artifact files (`Taskfile.yml:126`)

## IPC

- [ ] Replace Unix socket JSON protocol with gRPC over Unix socket (`core/ipc/`, `core/internal/socket/`, `core/client/`, `admin/tui/`, `admin/cli/`, `http/`): define `.proto` replacing `protocol.go`, server-streaming RPC for audit log feed (TUI only); HTTP gateway stays JSON
  - Resolve `replace cordova/core => ../core` directive in `admin/go.mod` and `http/go.mod` — decide whether workspace `use` directives alone are sufficient or if a published module version is needed (`admin/go.mod:38`)
  - **HTTP gateway design**: `http/` stays JSON in/out — translation is explicit field-mapping inside each handler. Three key changes vs today:
    1. **Auth**: HTTP Basic Auth (`username:token`) maps to outgoing gRPC metadata headers (not proto message fields). A server-side unary interceptor reads metadata and calls `auth.Authenticate()` — same logic, new entry point.
    2. **Errors**: Replace fragile `ipcStatus()` string-matching with typed gRPC status codes (`codes.NotFound` → 404, `codes.PermissionDenied` → 403, etc.). Daemon handlers return `status.Error(codes.X, "...")` instead of plain strings.
    3. **Connection**: Single long-lived `grpc.ClientConn` per HTTP server instance (dial `unix:///path/to/cordova.sock` at startup, shared across handlers) replaces the current per-request socket connection.
    - Each HTTP handler: parse JSON body → construct proto request → call gRPC stub with metadata ctx → map proto response fields → write JSON response. HTTP API shape (URLs, JSON field names, Basic Auth) is unchanged from the caller's perspective.
    - Streaming audit log RPC is TUI-only. HTTP exposes a non-live `GET /audit/log?limit=N` endpoint returning the last N entries as a JSON array — no SSE.
    - No `grpc-gateway` — it forces HTTP shape to mirror proto shape and doesn't map cleanly to Basic Auth.

## Unit Test Coverage

Overall: **7 / 186 functions tested (~4%)**

| Package | Functions | Tested | % |
|---|---|---|---|
| `http/server` | 12 | 7 | 58% |
| `core/internal/vault` | 20 | 0 | 0% |
| `core/internal/auth` | 4 | 0 | 0% |
| `core/internal/store` | 24 | 0 | 0% |
| `core/internal/socket` | 32 | 0 | 0% |
| `core/internal/config` | 6 | 0 | 0% |
| `core/internal/audit` | 3 | 0 | 0% |
| `core/client` | 4 | 0 | 0% |
| `admin/tui` | 44 | 0 | 0% |
| `admin/cli` | 2 | 0 | 0% |

### `http/server` — 58% (7/12)

- [x] `handleKeyGet` — OK + NotFound
- [x] `handleKeySet` — OK
- [x] `handleKeyDelete` — OK
- [x] `handleKeyList` — OK
- [x] `handleStatus` — OK
- [x] `authClient` — missing credentials → 401
- [x] `ipcStatus` — error string → HTTP status mapping
- [ ] `handleKeyGet` — wrong method, malformed body edge cases
- [ ] `handleKey` — direct routing test (PUT/DELETE/GET dispatch)
- [ ] `Handler` — route wiring (unknown paths → 404)
- [ ] `writeJSON` / `writeError` — direct unit tests
- [ ] `Run` — TLS startup, listener binding

### `core/internal/vault` — 0% (0/20)

- [ ] `EphemeralExpiry` — returns sentinel zero time
- [ ] `(Token).IsPersistent` / `IsEphemeral` / `IsExpired` — all TTL states
- [ ] `(SecretsState).Zero` — memory is overwritten
- [ ] `(SecretsVault).Init` + `Exists` + `Path`
- [ ] `(SecretsVault).Seal` + `Unseal` — round-trip; wrong passphrase; corrupt file
- [ ] `(UsersVault).Init` + `Seal` + `Unseal` — same as above; root user seeded
- [ ] `unsealFile` / `sealFile` — magic bytes, version byte, nonce freshness
- [ ] `zeroBytes` — bytes are all zero after call

### `core/internal/auth` — 0% (0/4)

- [ ] `Authenticate` — valid token; expired token; wrong scope; ephemeral token; nonexistent user
- [ ] `intersectScope` — all combinations (empty, disjoint, subset, equal)
- [ ] `intersectSlice` — empty inputs, no overlap, partial overlap

### `core/internal/store` — 0% (0/24)

- [ ] `SecretsStore`: Load, IsSealed, Zero, Snapshot, GetKey, ListKeys, SetKey, DeleteKey
- [ ] `UserStore`: Load, IsSealed, Zero, Snapshot, GetUser, ListUsers, Children
- [ ] `UserStore`: AddUser — child permissions subset enforced; duplicate name rejected
- [ ] `UserStore`: DeleteUser — user with children rejected; tokens removed
- [ ] `UserStore`: AddToken / FindToken / RevokeToken / RevokeAllTokens / TouchToken / ListAllTokens
- [ ] `checkSubset` — valid subset; invalid superset

### `core/internal/socket` — 0% (0/32)

- [ ] `handleKeyGet` / `handleKeySet` / `handleKeyDelete` / `handleKeyList` — via fake in-process store
- [ ] `handleTokenAdd` / `handleTokenList` / `handleTokenRevoke` / `handleTokenRevokeAll`
- [ ] `handleUserAdd` / `handleUserList` / `handleUserGet` / `handleUserDelete`
- [ ] `handleSocketList` / `handleSocketAdd` / `handleSocketDelete`
- [ ] `handleSeal` / `handleStatus`
- [ ] `dispatch` — unknown command returns error; auth failure returns error
- [ ] `okResp` / `errResp` / `writeResp` — response serialisation

### `core/internal/config` — 0% (0/6)

- [ ] `Load` — valid YAML; missing file; invalid YAML; defaults applied
- [ ] `(Config).Validate` — missing required fields
- [ ] `(Config).Save` — atomic write; file readable back as valid config
- [ ] `LoadSockets` / `SaveSockets` — round-trip

### `core/internal/audit` — 0% (0/3)

- [ ] `(Logger).Log` — entry written as valid JSON line
- [ ] `(Logger).Close` — file handle released; subsequent Log returns error

### `core/client` — 0% (0/4)

- [ ] `(Client).Probe` — daemon up → nil; daemon down → error
- [ ] `(Client).Send` — valid request/response round-trip; daemon error propagated
- [ ] `(Client).Username` — returns configured value

### `admin/cli` — 0% (0/2)

- [ ] `splitTrim` — separators, whitespace, empty entries dropped

## Code Quality

### P1 — Correctness bugs

- [ ] TOCTOU race in `handleSocketAdd`: check-unlock-start-relock pattern allows duplicate socket registration under concurrent calls (`core/internal/socket/socket.go:628–643`)
- [ ] Silent unmarshal failure in `handleTokenRevokeAll`: `_ = json.Unmarshal(raw, &p)` treats malformed params as zero-value; `p.Username == ""` may match unintended users in `RevokeAllTokens` (`core/internal/socket/socket.go:460`)

### P2 — Ignored errors that should be logged

- [ ] `okResp`: `b, _ := json.Marshal(data)` — marshal failure sends nil body silently (`core/internal/socket/socket.go` — `okResp` helper)
- [ ] `writeJSON`: `_ = json.NewEncoder(w).Encode(v)` — encode errors silently swallowed (`http/server/server.go:50`)
- [ ] `writeResp`: `_ = json.NewEncoder(conn).Encode(resp)` — same pattern on IPC socket path (`core/internal/socket/socket.go` — `writeResp` helper)

### P3 — Low priority / style

- [ ] `Execute()` calls `os.Exit(1)` inside the `cli` package — prevents callers from running deferred cleanup and makes CLI entry untestable; return error from `Execute()` and let `main()` call `os.Exit` (`admin/cli/root.go:52`)
- [ ] Cleanup-path ignores (`_ = conn.Close()`, `_ = os.Remove()`, `_ = f.Close()`) pervasive in `socket.go`, `config.go`, `sockets.go`, `client.go` — low risk but worth `slog.Warn` for file/socket removes in production paths

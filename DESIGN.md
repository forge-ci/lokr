# lokr design

lokr tells an AI agent which credentials exist on a machine and where, and lets
a host ask the user for a missing one. It never hands a value to the agent.

## Hard constraints

1. **One public crate.** `lokr` is the only crate published to crates.io.
   If the code is ever split into a workspace, internal crates stay
   `publish = false` and are amalgamated into the single `lokr` crate at release,
   following zccache's `ci/publish_amalgamate.py`. Until a split earns its cost,
   modules in one crate are the simplest way to meet this.
2. **`kernal-api` is the only dependency.** No other crate may appear in
   `[dependencies]`, including optional or target-specific entries. Pin it
   exactly (`=x.y.z`), as kernal-api requires below 1.0. Capabilities come from
   kernal-api features or `std`; if kernal-api lacks one, add it there. A guard
   test enforces this.
3. **No route returns a value.** There is no `get_secret`. Scans read values only
   to skip empty ones, and the catalog stores names and locations.

## Scenario

lokr exists so a credential can be written into a known location in a way that
never reaches the agent's context. The agent names the credential and where it
belongs, then sees only the outcome and the location. The value itself must not
appear in tool arguments, tool results, logs or prompts.

## Parts

- **Scanner** (`scan`): environment, same-user processes (Linux), `.env` files,
  credential files and known keyring entries.
- **Daemon** (`run_daemon`): rescans on a background thread every 60 seconds,
  writes `~/.lokr/catalog.json` (mode 0600), and exits after 10 minutes without an
  MCP heartbeat.
- **MCP server** (`serve_stdio`): newline-delimited JSON-RPC on stdio, with routes
  `list_secrets`, `secret_status`, and `request_secret` when a prompt is configured.
- **Library**: hosts embed all of this. `ServerOptions` names the daemon command
  and the masked prompt.

## Asking for secrets

`request_secret` runs the host's prompt and returns only `stored`, `failed` or
`cancelled`. The prompt delivers the value straight to its sink, so the value
never passes through lokr or the model. clud supplies its cross-platform
`clud secret` window today. Moving that prompt into lokr, built on kernal-api's
windowing features, is the planned path to one shared library.

## Host integration

`clud --allow-secrets` opts in. It adds lokr's MCP server to the session and
appends a system prompt naming the routes. Without the flag, nothing runs.

## Known limits

- An agent with shell access under the same account can read these locations
  itself. lokr prevents accidental exposure; it is not a sandbox.
- Process scanning is Linux-only so far. macOS and Windows see the other sources.
- Keyring entries cannot be enumerated, so only known entries are probed.
- Process spawning still uses `std::process`. It should move to kernal-api's
  `spawn_sync` once the kernal-api boundary Dylint is adopted here.

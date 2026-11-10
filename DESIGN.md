# lokr design

lokr tells an AI agent which credentials exist on a machine and where, and lets
a host ask the user for a missing one. It never hands a value to the agent.

## Hard constraints

1. **One public crate.** `lokr` is the only crate published to crates.io.
   If the code is ever split into a workspace, internal crates stay
   `publish = false` and are amalgamated into the single `lokr` crate at release,
   following zccache's `ci/publish_amalgamate.py`. Until a split earns its cost,
   modules in one crate are the simplest way to meet this.
2. **Keep dependencies focused.** `kernal-api` remains exactly pinned for JSON.
   The built-in request bar adds eframe/egui (OpenGL only, without persistence),
   regex, zeroize, rpassword, tempfile and keyring for native input and safe
   delivery. This replaces the original catalog-only single-dependency rule:
   the request bar needs explicit control over masked input, undo state,
   zeroization, validation and native credential stores. Keep it in one crate;
   do not pull in a browser runtime or WebGPU for this window.
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

`request_secret(title, message, sink, hint?, pattern?)` validates specific
context, runs a separate `lokr request` process, discards its output, and returns
only `stored`, `failed` or `cancelled` from the exit code. The request process
collects masked input and delivers it directly to a private file, native keyring,
or command stdin. Only metadata is recorded. The model never receives a value.
The CLI enables this tool automatically; library hosts may configure another
compatible command prefix or disable it with an empty prefix.

The native window shows the large title, explanation, hint, actual requesting
process identity and permanent warning: "This is NOT your computer or login
password." A custom bullet-only editor avoids plaintext undo snapshots. The
same validation supports a masked controlling-terminal fallback. `Prompt` is
injected for tests, with no real dialogs, terminals or keyring prompts allowed.
`LOKR_TEST_MODE` and test executable detection fail closed at real UI, keyring
and prompt-subprocess boundaries. Regexes match fully; three invalid submissions
fail. Credential buffers are zeroized after delivery, cancellation or rejection.

## Host integration

`clud --allow-secrets` opts in. It adds lokr's MCP server to the session and
appends a system prompt naming the routes. Without the flag, nothing runs.

## Known limits

- An agent with shell access under the same account can read these locations
  itself. lokr prevents accidental exposure; it is not a sandbox.
- Process scanning is Linux-only so far. macOS and Windows see the other sources.
- Legacy Python keyring probing can trigger an unlock dialog, so it is disabled
  by default and always in tests. `LOKR_SCAN_KEYRING=1` explicitly opts in to
  probing known entries; new request registrations need no keyring reads.
- Process spawning still uses `std::process`. It should move to kernal-api's
  `spawn_sync` once the kernal-api boundary Dylint is adopted here.

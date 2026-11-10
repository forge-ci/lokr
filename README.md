# lokr

A local secrets catalog for AI agents. It answers "is there an OpenRouter key on
this machine, and where?" without ever returning the key.

    lokr scan            # one scan, prints the catalog as JSON
    lokr list [query]    # names and sources
    lokr mcp             # stdio MCP server; starts the background scanner
    lokr daemon          # background scanner (normally started by `lokr mcp`)

MCP tools: `list_secrets(query?)`, `secret_status(name)`, and `request_secret(title, message, sink, hint?, pattern?)`.

**No tool returns a value.** The scanner reads values only to skip empty ones.
The catalog (`~/.lokr/catalog.json`, mode 0600) holds names and locations.

Sources: this process's environment, other same-user processes (Linux), `.env`
files in well-known directories, common credential files, and known OS keyring
entries (legacy keyring CLI probing is opt-in via `LOKR_SCAN_KEYRING=1`;
it can trigger an OS unlock dialog and is always disabled in tests).

An agent with shell access and the same user account can still read these
locations itself. lokr narrows what is exposed by accident; it is not a sandbox.


## Request a credential safely

`lokr request` opens a native masked window. The large title, explanation,
expected-format hint and requesting process identify what the human is entering.
The window permanently displays **This is NOT your computer or login password.**
On Linux without a display it uses the controlling terminal with echo disabled;
it never reads the agent's stdin. Empty terminal input cancels; for multiline
input an empty line finishes the entry. No display and no terminal fails closed.

```text
lokr request --title TITLE --message MESSAGE [--hint HINT] [--pattern REGEX] [--multiline]
             (--to-file PATH | --to-keyring SERVICE USER | --to-command CMD [ARG...])
```

Title and message are mandatory, specific context. Empty, whitespace-only and
generic prompts such as "password", "secret", "credential", and "enter the
requested credential" are refused before opening a UI. Name the actual service
and credential in the title; explain why it is needed and where to find it in
the message. For example:

```sh
lokr request --title 'GitHub OAuth Client ID' \
  --message 'Needed to configure GitHub sign-in. Find the Client ID in GitHub Settings > Developer settings > OAuth Apps > your application.' \
  --hint 'The Client ID, not the client secret or your login password' \
  --to-file ./github-client-id
```

A regex must match the entire value. At most three submissions are allowed;
each mismatch shows a format error. Invalid regexes fail before opening a UI.
All input is masked, including multiline text. The GUI has no reveal, copy or
undo operation; only bullets enter its widget state. Secret buffers are zeroized
after delivery or cancellation. Do not put credential values in arguments,
messages, hints or regexes.

Exactly one sink is required. File delivery atomically replaces the target from
a temporary file in the same directory, mode 0600 on Unix and an owner-only ACL
on Windows set before writing. Parent directories must exist. Keyring delivery
uses the native OS store (Secret Service on Linux, Keychain on macOS, Credential
Manager on Windows). Command delivery invokes the program directly, without a
shell, sends the exact value to stdin without adding a newline, and discards
both stdout and stderr. Put `--to-command` last; every following argument belongs
to the command. The selected command is trusted to handle the credential safely.

Only `stored`, `cancelled` or `failed` is printed, with exit code 0, 3 or 1.
Successful delivery registers only the title and sink location in
`~/.lokr/requests/`; catalog scans and MCP listings include that metadata. No API
returns the credential. A failed catalog update reports `failed` even if delivery
already succeeded; inspect the destination before retrying.

### MCP

```text
request_secret(title: string, message: string, sink: Sink,
               hint?: string, pattern?: string) -> "stored" | "cancelled" | "failed"
Sink = {type: "file", path: string}
     | {type: "keyring", service: string, user: string}
     | {type: "command", argv: [program, ...args]}
```

The `lokr mcp` server enables this tool automatically. It starts a separate
`lokr request` process, discards its output, and returns only the exit-code
status. Embedders may configure `ServerOptions.ask_command` as the command prefix;
validated request flags are appended. An empty prefix disables the tool. The old
name-only request API is rejected.

### UI and tests

The native window uses `kernal_api::gfx` with its `gfx-egui` backend (wgpu).
The facade owns the window and secure masked input; lokr has no direct GUI
backend dependency.
Release builds use size optimization, thin LTO and stripped symbols. The facade
masked editor avoids plaintext undo snapshots. The public
`Prompt` trait lets tests provide fake input without starting an event loop.

Tests must never open dialogs, read a terminal or unlock a keyring. Real UI and
keyring delivery are refused in unit tests, integration-test executables, or
whenever `LOKR_TEST_MODE` is set. MCP prompt subprocesses are also disabled then.
Run tests headlessly:

```sh
env -u DISPLAY -u WAYLAND_DISPLAY LOKR_TEST_MODE=1 soldr cargo test --all-targets
```

Never manually invoke a real credential request as a test. The test suite uses
fake input, temporary files and harmless command sinks, and covers context
validation, full regex matching, retry limits, cancellation, permissions,
command stdin delivery, and metadata-only registration.

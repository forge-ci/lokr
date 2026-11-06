# lokr

A local secrets catalog for AI agents. It answers "is there an OpenRouter key on
this machine, and where?" without ever returning the key.

    lokr scan            # one scan, prints the catalog as JSON
    lokr list [query]    # names and sources
    lokr mcp             # stdio MCP server; starts the background scanner
    lokr daemon          # background scanner (normally started by `lokr mcp`)

MCP tools: `list_secrets(query?)` and `secret_status(name)`.

**No tool returns a value.** The scanner reads values only to skip empty ones.
The catalog (`~/.lokr/catalog.json`, mode 0600) holds names and locations.

Sources: this process's environment, other same-user processes (Linux), `.env`
files in well-known directories, common credential files, and known OS keyring
entries.

An agent with shell access and the same user account can still read these
locations itself. lokr narrows what is exposed by accident; it is not a sandbox.

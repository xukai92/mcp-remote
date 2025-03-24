# `mcp-remote`

Connect an MCP Client that only supports local (stdio) servers to a Remote MCP Server, with auth support:

**Note: this is a working proof-of-concept** but should be considered **experimental**.

## Why is this necessary?

So far, the majority of MCP servers in the wild are installed locally, using the stdio transport. This has some benefits: both the client and the server can implicitly trust each other as the user has granted them both permission to run. Adding secrets like API keys can be done using environment variables and never leave your machine. And building on `npx` and `uvx` has allowed users to avoid explicit install steps, too.

But there's a reason most software that _could_ be moved to the web _did_ get moved to the web: it's so much easier to find and fix bugs & iterate on new features when you can push updates to all your users with a single deploy.

With the MCP [Authorization specification](https://spec.modelcontextprotocol.io/specification/draft/basic/authorization/) nearing completion, we now have a secure way of sharing our MCP servers with the world _without_ running code on user's laptops. Or at least, you would, if all the popular MCP _clients_ supported it yet. Most are stdio-only, and those that _do_ support HTTP+SSE don't yet support the OAuth flows required.

That's where `mcp-remote` comes in. As soon as your chosen MCP client supports remote, authorized servers, you can remove it. Until that time, drop in this one liner and dress for the MCP clients you want!

## Configuration

E.g: Claude Desktop or Windsurf

```json
{
  "mcpServers": {
    "remote-example": {
      "command": "npx",
      "args": ["mcp-remote", "https://remote.mcp.server/sse"]
    }
  }
}
```

Cursor:

![image](https://github.com/user-attachments/assets/14338bfa-a779-4e8a-a477-71f72cc5d99d)

## Debugging

### Check your Node version

Make sure that the version of Node you have installed is [16 or higher](https://modelcontextprotocol.io/quickstart/server).

### Restart Claude

When modifying `claude_desktop_config.json` it can helpful to completely restart Claude

### VPN Certs

You may run into issues if you are behind a VPN, you can try setting the `NODE_EXTRA_CA_CERTS`
environment variable to point to the CA certificate file. If using `claude_desktop_config.json`,
this might look like:

```json
{
 "mcpServers": {
    "remote-example": {
      "command": "npx",
      "args": [
        "mcp-remote",
        "https://remote.mcp.server/sse"
      ],
      "env": {
        "NODE_EXTRA_CA_CERTS": "{your CA certificate file path}.pem"
      }
    }
  }
}
```

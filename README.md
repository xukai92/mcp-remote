# `mcp-remote`

Connect an MCP Client that only supports local (stdio) servers to a Remote MCP Server, with auth support:

**Note: this is a working proof-of-concept** but should be considered **experimental**

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

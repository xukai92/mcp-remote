# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

`mcp-remote` is a TypeScript proxy tool that enables local MCP (Model Context Protocol) clients to connect to remote MCP servers with OAuth authentication. It acts as a bridge between stdio-only MCP clients (like Claude Desktop, Cursor, Windsurf) and remote HTTP/SSE servers.

## Development Commands

- **Build**: `pnpm run build` - Compiles TypeScript to `dist/` using tsup
- **Build (watch)**: `pnpm run build:watch` - Continuous compilation during development
- **Type check and format**: `pnpm run check` - Runs prettier check and TypeScript compilation
- **Format code**: `pnpm run lint-fix` - Auto-fixes code formatting with prettier

## Architecture

The codebase has two main entry points:

### Core Components

- **`src/proxy.ts`**: Main proxy executable that creates a bidirectional bridge between local stdio transport and remote server transport with OAuth
- **`src/client.ts`**: Standalone test client for debugging remote server connections
- **`src/lib/coordination.ts`**: Handles process coordination using lockfiles to prevent multiple auth flows for the same server
- **`src/lib/node-oauth-client-provider.ts`**: OAuth client implementation with dynamic registration and token management
- **`src/lib/utils.ts`**: Transport creation, command-line parsing, and connection utilities
- **`src/lib/mcp-auth-config.ts`**: Configuration file management for storing OAuth credentials in `~/.mcp-auth/`

### Transport Strategy

The system supports multiple transport strategies (`sse-only`, `http-only`, `sse-first`, `http-first`) and automatically falls back between Server-Sent Events and HTTP transports based on server capabilities.

### Authentication Flow

1. Creates a local Express server for OAuth callbacks
2. Uses process coordination via lockfiles to handle multiple simultaneous auth attempts
3. Supports both dynamic OAuth client registration and static client configurations
4. Stores credentials securely in user's home directory under `.mcp-auth/`

## Key Implementation Details

- Uses ES modules (`"type": "module"`)
- Built with tsup for fast TypeScript compilation
- Supports both `mcp-remote` (proxy) and `mcp-remote-client` (debug client) binaries
- Implements proper cleanup handlers for graceful shutdown
- Debug logging available via `--debug` flag, writes to `~/.mcp-auth/{server_hash}_debug.log`

## New Features

### Tool Renaming and Filtering

Two new command-line options have been added to help manage multiple MCP servers:

- **`--tool-prefix <prefix>`**: Adds a prefix to all tool names from the remote server (e.g., "list_issues" becomes "linear_list_issues" with prefix "linear")
- **`--tool-filter <tool1,tool2>`**: Only exposes specified tools from the remote server using their **original names** (comma-separated list)

Example usage:
```bash
npx mcp-remote https://remote.server/sse --tool-prefix linear --tool-filter list_issues,create_issue
```

### Implementation Details

- Tool transformations happen in the `mcpProxy` function in `src/lib/utils.ts`
- `tools/list` responses are transformed to apply prefixes and filtering
- `tools/call` requests are reverse-transformed to remove prefixes before forwarding to the remote server
- Filtering is applied based on original tool names before prefix transformation (so you specify tools using their original names from the remote server)

## Testing

Use the standalone client for testing server connections:

```bash
npx tsx src/client.ts https://example.remote/server
```

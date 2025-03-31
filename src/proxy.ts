#!/usr/bin/env node

/**
 * MCP Proxy with OAuth support
 * A bidirectional proxy between a local STDIO MCP server and a remote SSE server with OAuth authentication.
 *
 * Run with: npx tsx proxy.ts [--clean] https://example.remote/server [callback-port]
 *
 * Options:
 * --clean: Deletes stored configuration before reading, ensuring a fresh session
 *
 * If callback-port is not specified, an available port will be automatically selected.
 */

import { EventEmitter } from 'events'
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js'
import { connectToRemoteServer, log, mcpProxy, parseCommandLineArgs, setupOAuthCallbackServer, setupSignalHandlers } from './lib/utils'
import { NodeOAuthClientProvider } from './lib/node-oauth-client-provider'

/**
 * Main function to run the proxy
 */
async function runProxy(serverUrl: string, callbackPort: number, clean: boolean = false) {
  // Set up event emitter for auth flow
  const events = new EventEmitter()

  // Create the OAuth client provider
  const authProvider = new NodeOAuthClientProvider({
    serverUrl,
    callbackPort,
    clientName: 'MCP CLI Proxy',
    clean,
  })

  // Create the STDIO transport for local connections
  const localTransport = new StdioServerTransport()

  // Set up an HTTP server to handle OAuth callback
  const { server, waitForAuthCode } = setupOAuthCallbackServer({
    port: callbackPort,
    path: '/oauth/callback',
    events,
  })

  try {
    // Connect to remote server with authentication
    const remoteTransport = await connectToRemoteServer(serverUrl, authProvider, waitForAuthCode)

    // Set up bidirectional proxy between local and remote transports
    mcpProxy({
      transportToClient: localTransport,
      transportToServer: remoteTransport,
    })

    // Start the local STDIO server
    await localTransport.start()
    log('Local STDIO server running')
    log('Proxy established successfully between local STDIO and remote SSE')
    log('Press Ctrl+C to exit')

    // Setup cleanup handler
    const cleanup = async () => {
      await remoteTransport.close()
      await localTransport.close()
      server.close()
    }
    setupSignalHandlers(cleanup)
  } catch (error) {
    log('Fatal error:', error)
    if (error instanceof Error && error.message.includes('self-signed certificate in certificate chain')) {
      log(`You may be behind a VPN!

If you are behind a VPN, you can try setting the NODE_EXTRA_CA_CERTS environment variable to point
to the CA certificate file. If using claude_desktop_config.json, this might look like:

{
  "mcpServers": {
    "\${mcpServerName}": {
      "command": "npx",
      "args": [
        "mcp-remote",
        "https://remote.mcp.server/sse"
      ],
      "env": {
        "NODE_EXTRA_CA_CERTS": "\${your CA certificate file path}.pem"
      }
    }
  }
}
        `)
    }
    server.close()
    process.exit(1)
  }
}

// Parse command-line arguments and run the proxy
parseCommandLineArgs(process.argv.slice(2), 3334, 'Usage: npx tsx proxy.ts [--clean] <https://server-url> [callback-port]')
  .then(({ serverUrl, callbackPort, clean }) => {
    return runProxy(serverUrl, callbackPort, clean)
  })
  .catch((error) => {
    log('Fatal error:', error)
    process.exit(1)
  })

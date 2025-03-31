import { OAuthClientProvider, UnauthorizedError } from '@modelcontextprotocol/sdk/client/auth.js'
import { SSEClientTransport } from '@modelcontextprotocol/sdk/client/sse.js'
import { Transport } from '@modelcontextprotocol/sdk/shared/transport.js'
import { OAuthCallbackServerOptions } from './types'
import express from 'express'
import net from 'net'

const pid = process.pid

/**
 * Creates a bidirectional proxy between two transports
 * @param params The transport connections to proxy between
 */
export function mcpProxy({ transportToClient, transportToServer }: { transportToClient: Transport; transportToServer: Transport }) {
  let transportToClientClosed = false
  let transportToServerClosed = false

  transportToClient.onmessage = (message) => {
    // @ts-expect-error TODO
    console.error('[Local→Remote]', message.method || message.id)
    transportToServer.send(message).catch(onServerError)
  }

  transportToServer.onmessage = (message) => {
    // @ts-expect-error TODO: fix this type
    console.error('[Remote→Local]', message.method || message.id)
    transportToClient.send(message).catch(onClientError)
  }

  transportToClient.onclose = () => {
    if (transportToServerClosed) {
      return
    }

    transportToClientClosed = true
    transportToServer.close().catch(onServerError)
  }

  transportToServer.onclose = () => {
    if (transportToClientClosed) {
      return
    }
    transportToServerClosed = true
    transportToClient.close().catch(onClientError)
  }

  transportToClient.onerror = onClientError
  transportToServer.onerror = onServerError

  function onClientError(error: Error) {
    console.error('Error from local client:', error)
  }

  function onServerError(error: Error) {
    console.error('Error from remote server:', error)
  }
}

/**
 * Creates and connects to a remote SSE server with OAuth authentication
 * @param serverUrl The URL of the remote server
 * @param authProvider The OAuth client provider
 * @param waitForAuthCode Function to wait for the auth code
 * @returns The connected SSE client transport
 */
export async function connectToRemoteServer(
  serverUrl: string,
  authProvider: OAuthClientProvider,
  waitForAuthCode: () => Promise<string>,
): Promise<SSEClientTransport> {
  console.error(`[${pid}] Connecting to remote server: ${serverUrl}`)
  const url = new URL(serverUrl)
  const transport = new SSEClientTransport(url, { authProvider })

  try {
    await transport.start()
    console.error('Connected to remote server')
    return transport
  } catch (error) {
    if (error instanceof UnauthorizedError || (error instanceof Error && error.message.includes('Unauthorized'))) {
      console.error('Authentication required. Waiting for authorization...')

      // Wait for the authorization code from the callback
      const code = await waitForAuthCode()

      try {
        console.error('Completing authorization...')
        await transport.finishAuth(code)

        // Create a new transport after auth
        const newTransport = new SSEClientTransport(url, { authProvider })
        await newTransport.start()
        console.error('Connected to remote server after authentication')
        return newTransport
      } catch (authError) {
        console.error('Authorization error:', authError)
        throw authError
      }
    } else {
      console.error('Connection error:', error)
      throw error
    }
  }
}

/**
 * Sets up an Express server to handle OAuth callbacks
 * @param options The server options
 * @returns An object with the server, authCode, and waitForAuthCode function
 */
export function setupOAuthCallbackServer(options: OAuthCallbackServerOptions) {
  let authCode: string | null = null
  const app = express()

  app.get(options.path, (req, res) => {
    const code = req.query.code as string | undefined
    if (!code) {
      res.status(400).send('Error: No authorization code received')
      return
    }

    authCode = code
    res.send('Authorization successful! You may close this window and return to the CLI.')

    // Notify main flow that auth code is available
    options.events.emit('auth-code-received', code)
  })

  const server = app.listen(options.port, () => {
    console.error(`OAuth callback server running at http://127.0.0.1:${options.port}`)
  })

  /**
   * Waits for the OAuth authorization code
   * @returns A promise that resolves with the authorization code
   */
  const waitForAuthCode = (): Promise<string> => {
    return new Promise((resolve) => {
      if (authCode) {
        resolve(authCode)
        return
      }

      options.events.once('auth-code-received', (code) => {
        resolve(code)
      })
    })
  }

  return { server, authCode, waitForAuthCode }
}

/**
 * Finds an available port on the local machine
 * @param preferredPort Optional preferred port to try first
 * @returns A promise that resolves to an available port number
 */
export async function findAvailablePort(preferredPort?: number): Promise<number> {
  return new Promise((resolve, reject) => {
    const server = net.createServer()

    server.on('error', (err: NodeJS.ErrnoException) => {
      if (err.code === 'EADDRINUSE') {
        // If preferred port is in use, get a random port
        server.listen(0)
      } else {
        reject(err)
      }
    })

    server.on('listening', () => {
      const { port } = server.address() as net.AddressInfo
      server.close(() => {
        resolve(port)
      })
    })

    // Try preferred port first, or get a random port
    server.listen(preferredPort || 0)
  })
}

/**
 * Parses command line arguments for MCP clients and proxies
 * @param args Command line arguments
 * @param defaultPort Default port for the callback server if specified port is unavailable
 * @param usage Usage message to show on error
 * @returns A promise that resolves to an object with parsed serverUrl, callbackPort, and clean flag
 */
export async function parseCommandLineArgs(args: string[], defaultPort: number, usage: string) {
  // Check for --clean flag
  const cleanIndex = args.indexOf('--clean')
  const clean = cleanIndex !== -1

  // Remove the flag from args if it exists
  if (clean) {
    args.splice(cleanIndex, 1)
  }

  const serverUrl = args[0]
  const specifiedPort = args[1] ? parseInt(args[1]) : undefined

  if (!serverUrl) {
    console.error(usage)
    process.exit(1)
  }

  const url = new URL(serverUrl)
  const isLocalhost = (url.hostname === 'localhost' || url.hostname === '127.0.0.1') && url.protocol === 'http:'

  if (!(url.protocol == 'https:' || isLocalhost)) {
    console.error(usage)
    process.exit(1)
  }

  // Use the specified port, or find an available one
  const callbackPort = specifiedPort || (await findAvailablePort(defaultPort))

  if (specifiedPort) {
    console.error(`Using specified callback port: ${callbackPort}`)
  } else {
    console.error(`Using automatically selected callback port: ${callbackPort}`)
  }

  if (clean) {
    console.error('Clean mode enabled: config files will be reset before reading')
  }

  return { serverUrl, callbackPort, clean }
}

/**
 * Sets up signal handlers for graceful shutdown
 * @param cleanup Cleanup function to run on shutdown
 */
export function setupSignalHandlers(cleanup: () => Promise<void>) {
  process.on('SIGINT', async () => {
    console.error('\nShutting down...')
    await cleanup()
    process.exit(0)
  })

  // Keep the process alive
  process.stdin.resume()
}

export const MCP_REMOTE_VERSION = require('../../package.json').version

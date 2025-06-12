import { OAuthClientProvider, UnauthorizedError } from '@modelcontextprotocol/sdk/client/auth.js'
import { Client } from '@modelcontextprotocol/sdk/client/index.js'
import { SSEClientTransport } from '@modelcontextprotocol/sdk/client/sse.js'
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js'
import { Transport } from '@modelcontextprotocol/sdk/shared/transport.js'
import { OAuthError } from '@modelcontextprotocol/sdk/server/auth/errors.js'
import { OAuthClientInformationFull, OAuthClientInformationFullSchema } from '@modelcontextprotocol/sdk/shared/auth.js'
import { OAuthCallbackServerOptions, StaticOAuthClientInformationFull, StaticOAuthClientMetadata } from './types'
import { getConfigDir, getConfigFilePath, readJsonFile } from './mcp-auth-config'
import express from 'express'
import net from 'net'
import crypto from 'crypto'
import fs from 'fs'
import { readFile, rm } from 'fs/promises'
import path from 'path'
import { version as MCP_REMOTE_VERSION } from '../../package.json'

// Global type declaration for typescript
declare global {
  var currentServerUrlHash: string | undefined
}

// Connection constants
export const REASON_AUTH_NEEDED = 'authentication-needed'
export const REASON_TRANSPORT_FALLBACK = 'falling-back-to-alternate-transport'

// Transport strategy types
export type TransportStrategy = 'sse-only' | 'http-only' | 'sse-first' | 'http-first'
export { MCP_REMOTE_VERSION }

const pid = process.pid
// Global debug flag
export let DEBUG = false

// Helper function for timestamp formatting
function getTimestamp(): string {
  const now = new Date()
  return now.toISOString()
}

// Debug logging function
export function debugLog(message: string, ...args: any[]) {
  if (!DEBUG) return

  const serverUrlHash = global.currentServerUrlHash
  if (!serverUrlHash) {
    console.error('[DEBUG LOG ERROR] global.currentServerUrlHash is not set. Cannot write debug log.')
    return
  }

  try {
    // Format with timestamp and PID
    const formattedMessage = `[${getTimestamp()}][${pid}] ${message}`

    // Log to console
    console.error(formattedMessage, ...args)

    // Ensure config directory exists
    const configDir = getConfigDir()
    fs.mkdirSync(configDir, { recursive: true })

    // Append to log file
    const logPath = path.join(configDir, `${serverUrlHash}_debug.log`)
    const logMessage = `${formattedMessage} ${args.map((arg) => (typeof arg === 'object' ? JSON.stringify(arg) : String(arg))).join(' ')}\n`

    fs.appendFileSync(logPath, logMessage, { encoding: 'utf8' })
  } catch (error) {
    // Fallback to console if file logging fails
    console.error(`[DEBUG LOG ERROR] ${error}`)
  }
}

export function log(str: string, ...rest: unknown[]) {
  // Using stderr so that it doesn't interfere with stdout
  console.error(`[${pid}] ${str}`, ...rest)

  // If debug mode is on, also log to debug file
  if (DEBUG && global.currentServerUrlHash) {
    debugLog(str, ...rest)
  }
}

/**
 * Creates a bidirectional proxy between two transports
 * @param params The transport connections to proxy between
 */
/**
 * Transform tool names by adding a prefix
 */
function transformToolName(toolName: string, prefix?: string): string {
  if (!prefix) return toolName
  return `${prefix}_${toolName}`
}

/**
 * Reverse transform tool names by removing a prefix
 */
function reverseTransformToolName(toolName: string, prefix?: string): string {
  if (!prefix) return toolName
  if (toolName.startsWith(`${prefix}_`)) {
    return toolName.substring(prefix.length + 1)
  }
  return toolName
}

/**
 * Filter tools based on allowed list
 */
function filterTools(tools: any[], allowedTools?: string[]): any[] {
  if (!allowedTools) return tools
  return tools.filter((tool) => allowedTools.includes(tool.name))
}

/**
 * Transform tools/list response to apply prefix and filtering
 */
function transformToolsListResponse(result: any, toolPrefix?: string, toolFilter?: string[]): any {
  if (!result || !result.tools) return result

  let transformedTools = [...result.tools]

  // Apply filtering first (based on original names)
  if (toolFilter) {
    transformedTools = filterTools(transformedTools, toolFilter)
  }

  // Apply prefix transformation
  if (toolPrefix) {
    transformedTools = transformedTools.map((tool) => ({
      ...tool,
      name: transformToolName(tool.name, toolPrefix),
    }))
  }

  return {
    ...result,
    tools: transformedTools,
  }
}

/**
 * Transform tools/call request to remove prefix
 */
function transformToolCallRequest(params: any, toolPrefix?: string): any {
  if (!params || !params.name || !toolPrefix) return params

  return {
    ...params,
    name: reverseTransformToolName(params.name, toolPrefix),
  }
}

export function mcpProxy({
  transportToClient,
  transportToServer,
  toolPrefix,
  toolFilter,
}: {
  transportToClient: Transport
  transportToServer: Transport
  toolPrefix?: string
  toolFilter?: string[]
}) {
  let transportToClientClosed = false
  let transportToServerClosed = false

  transportToClient.onmessage = (_message) => {
    // TODO: fix types
    const message = _message as any
    log('[Local→Remote]', message.method || message.id)

    if (DEBUG) {
      debugLog('Local → Remote message', {
        method: message.method,
        id: message.id,
        params: message.params ? JSON.stringify(message.params).substring(0, 500) : undefined,
      })
    }

    // Handle initialize message
    if (message.method === 'initialize') {
      const { clientInfo } = message.params
      if (clientInfo) clientInfo.name = `${clientInfo.name} (via mcp-remote ${MCP_REMOTE_VERSION})`
      log(JSON.stringify(message, null, 2))

      if (DEBUG) {
        debugLog('Initialize message with modified client info', { clientInfo })
      }
    }

    // Handle tools/call message - transform tool name to remove prefix
    if (message.method === 'tools/call' && toolPrefix) {
      const originalParams = message.params
      message.params = transformToolCallRequest(message.params, toolPrefix)
      if (DEBUG) {
        debugLog('Transformed tools/call request', { originalParams, transformedParams: message.params })
      }
    }

    transportToServer.send(message).catch(onServerError)
  }

  transportToServer.onmessage = (_message) => {
    // TODO: fix types
    const message = _message as any
    log('[Remote→Local]', message.method || message.id)

    if (DEBUG) {
      debugLog('Remote → Local message', {
        method: message.method,
        id: message.id,
        result: message.result ? 'result-present' : undefined,
        error: message.error,
      })
    }

    // Handle tools/list response - transform tool names and apply filtering
    if (message.result && message.result.tools && (toolPrefix || toolFilter)) {
      const originalResult = { ...message.result }
      message.result = transformToolsListResponse(message.result, toolPrefix, toolFilter)
      if (DEBUG) {
        debugLog('Transformed tools/list response', {
          originalCount: originalResult.tools?.length || 0,
          transformedCount: message.result.tools?.length || 0,
          toolPrefix,
          toolFilter,
        })
      }
    }

    transportToClient.send(message).catch(onClientError)
  }

  transportToClient.onclose = () => {
    if (transportToServerClosed) {
      return
    }

    transportToClientClosed = true
    if (DEBUG) debugLog('Local transport closed, closing remote transport')
    transportToServer.close().catch(onServerError)
  }

  transportToServer.onclose = () => {
    if (transportToClientClosed) {
      return
    }
    transportToServerClosed = true
    if (DEBUG) debugLog('Remote transport closed, closing local transport')
    transportToClient.close().catch(onClientError)
  }

  transportToClient.onerror = onClientError
  transportToServer.onerror = onServerError

  function onClientError(error: Error) {
    log('Error from local client:', error)
    if (DEBUG) debugLog('Error from local client', { stack: error.stack })
  }

  function onServerError(error: Error) {
    log('Error from remote server:', error)
    if (DEBUG) debugLog('Error from remote server', { stack: error.stack })
  }
}

/**
 * Type for the auth initialization function
 */
export type AuthInitializer = () => Promise<{
  waitForAuthCode: () => Promise<string>
  skipBrowserAuth: boolean
}>

/**
 * Creates and connects to a remote server with OAuth authentication
 * @param client The client to connect with
 * @param serverUrl The URL of the remote server
 * @param authProvider The OAuth client provider
 * @param headers Additional headers to send with the request
 * @param authInitializer Function to initialize authentication when needed
 * @param transportStrategy Strategy for selecting transport type ('sse-only', 'http-only', 'sse-first', 'http-first')
 * @param recursionReasons Set of reasons for recursive calls (internal use)
 * @returns The connected transport
 */
export async function connectToRemoteServer(
  client: Client | null,
  serverUrl: string,
  authProvider: OAuthClientProvider,
  headers: Record<string, string>,
  authInitializer: AuthInitializer,
  transportStrategy: TransportStrategy = 'http-first',
  recursionReasons: Set<string> = new Set(),
): Promise<Transport> {
  log(`[${pid}] Connecting to remote server: ${serverUrl}`)
  const url = new URL(serverUrl)

  // Create transport with eventSourceInit to pass Authorization header if present
  const eventSourceInit = {
    fetch: (url: string | URL, init?: RequestInit) => {
      return Promise.resolve(authProvider?.tokens?.()).then((tokens) =>
        fetch(url, {
          ...init,
          headers: {
            ...(init?.headers as Record<string, string> | undefined),
            ...headers,
            ...(tokens?.access_token ? { Authorization: `Bearer ${tokens.access_token}` } : {}),
            Accept: 'text/event-stream',
          } as Record<string, string>,
        }),
      )
    },
  }

  log(`Using transport strategy: ${transportStrategy}`)
  // Determine if we should attempt to fallback on error
  // Choose transport based on user strategy and recursion history
  const shouldAttemptFallback = transportStrategy === 'http-first' || transportStrategy === 'sse-first'

  // Create transport instance based on the strategy
  const sseTransport = transportStrategy === 'sse-only' || transportStrategy === 'sse-first'
  const transport = sseTransport
    ? new SSEClientTransport(url, {
        authProvider,
        requestInit: { headers },
        eventSourceInit,
      })
    : new StreamableHTTPClientTransport(url, {
        authProvider,
        requestInit: { headers },
      })

  try {
    if (DEBUG) debugLog('Attempting to connect to remote server', { sseTransport })

    if (client) {
      if (DEBUG) debugLog('Connecting client to transport')
      await client.connect(transport)
    } else {
      if (DEBUG) debugLog('Starting transport directly')
      await transport.start()
      if (!sseTransport) {
        // Extremely hacky, but we didn't actually send a request when calling transport.start() above, so we don't
        // know if we're even talking to an HTTP server. But if we forced that now we'd get an error later saying that
        // the client is already connected. So let's just create a one-off client to make a single request and figure
        // out if we're actually talking to an HTTP server or not.
        if (DEBUG) debugLog('Creating test transport for HTTP-only connection test')
        const testTransport = new StreamableHTTPClientTransport(url, { authProvider, requestInit: { headers } })
        const testClient = new Client({ name: 'mcp-remote-fallback-test', version: '0.0.0' }, { capabilities: {} })
        await testClient.connect(testTransport)
      }
    }
    log(`Connected to remote server using ${transport.constructor.name}`)

    return transport
  } catch (error: any) {
    // Check if it's a protocol error and we should attempt fallback
    if (
      error instanceof Error &&
      shouldAttemptFallback &&
      (error.message.includes('405') ||
        error.message.includes('Method Not Allowed') ||
        error.message.includes('404') ||
        error.message.includes('Not Found'))
    ) {
      log(`Received error: ${error.message}`)

      // If we've already tried falling back once, throw an error
      if (recursionReasons.has(REASON_TRANSPORT_FALLBACK)) {
        const errorMessage = `Already attempted transport fallback. Giving up.`
        log(errorMessage)
        throw new Error(errorMessage)
      }

      log(`Recursively reconnecting for reason: ${REASON_TRANSPORT_FALLBACK}`)

      // Add to recursion reasons set
      recursionReasons.add(REASON_TRANSPORT_FALLBACK)

      // Recursively call connectToRemoteServer with the updated recursion tracking
      return connectToRemoteServer(
        client,
        serverUrl,
        authProvider,
        headers,
        authInitializer,
        sseTransport ? 'http-only' : 'sse-only',
        recursionReasons,
      )
    } else if (error instanceof UnauthorizedError || (error instanceof Error && error.message.includes('Unauthorized'))) {
      log('Authentication required. Initializing auth...')
      if (DEBUG) {
        debugLog('Authentication error detected', {
          errorCode: error instanceof OAuthError ? error.errorCode : undefined,
          errorMessage: error.message,
          stack: error.stack,
        })
      }

      // Initialize authentication on-demand
      if (DEBUG) debugLog('Calling authInitializer to start auth flow')
      const { waitForAuthCode, skipBrowserAuth } = await authInitializer()

      if (skipBrowserAuth) {
        log('Authentication required but skipping browser auth - using shared auth')
      } else {
        log('Authentication required. Waiting for authorization...')
      }

      // Wait for the authorization code from the callback
      if (DEBUG) debugLog('Waiting for auth code from callback server')
      const code = await waitForAuthCode()
      if (DEBUG) debugLog('Received auth code from callback server')

      try {
        log('Completing authorization...')
        await transport.finishAuth(code)
        if (DEBUG) debugLog('Authorization completed successfully')

        if (recursionReasons.has(REASON_AUTH_NEEDED)) {
          const errorMessage = `Already attempted reconnection for reason: ${REASON_AUTH_NEEDED}. Giving up.`
          log(errorMessage)
          if (DEBUG)
            debugLog('Already attempted auth reconnection, giving up', {
              recursionReasons: Array.from(recursionReasons),
            })
          throw new Error(errorMessage)
        }

        // Track this reason for recursion
        recursionReasons.add(REASON_AUTH_NEEDED)
        log(`Recursively reconnecting for reason: ${REASON_AUTH_NEEDED}`)
        if (DEBUG) debugLog('Recursively reconnecting after auth', { recursionReasons: Array.from(recursionReasons) })

        // Recursively call connectToRemoteServer with the updated recursion tracking
        return connectToRemoteServer(client, serverUrl, authProvider, headers, authInitializer, transportStrategy, recursionReasons)
      } catch (authError: any) {
        log('Authorization error:', authError)
        if (DEBUG)
          debugLog('Authorization error during finishAuth', {
            errorMessage: authError.message,
            stack: authError.stack,
          })
        throw authError
      }
    } else {
      log('Connection error:', error)
      if (DEBUG)
        debugLog('Connection error', {
          errorMessage: error.message,
          stack: error.stack,
          transportType: transport.constructor.name,
        })
      throw error
    }
  }
}

/**
 * Sets up an Express server to handle OAuth callbacks
 * @param options The server options
 * @returns An object with the server, authCode, and waitForAuthCode function
 */
export function setupOAuthCallbackServerWithLongPoll(options: OAuthCallbackServerOptions) {
  let authCode: string | null = null
  const app = express()

  // Create a promise to track when auth is completed
  let authCompletedResolve: (code: string) => void
  const authCompletedPromise = new Promise<string>((resolve) => {
    authCompletedResolve = resolve
  })

  // Long-polling endpoint
  app.get('/wait-for-auth', (req, res) => {
    if (authCode) {
      // Auth already completed - just return 200 without the actual code
      // Secondary instances will read tokens from disk
      log('Auth already completed, returning 200')
      res.status(200).send('Authentication completed')
      return
    }

    if (req.query.poll === 'false') {
      log('Client requested no long poll, responding with 202')
      res.status(202).send('Authentication in progress')
      return
    }

    // Long poll - wait for up to 30 seconds
    const longPollTimeout = setTimeout(() => {
      log('Long poll timeout reached, responding with 202')
      res.status(202).send('Authentication in progress')
    }, 30000)

    // If auth completes while we're waiting, send the response immediately
    authCompletedPromise
      .then(() => {
        clearTimeout(longPollTimeout)
        if (!res.headersSent) {
          log('Auth completed during long poll, responding with 200')
          res.status(200).send('Authentication completed')
        }
      })
      .catch(() => {
        clearTimeout(longPollTimeout)
        if (!res.headersSent) {
          log('Auth failed during long poll, responding with 500')
          res.status(500).send('Authentication failed')
        }
      })
  })

  // OAuth callback endpoint
  app.get(options.path, (req, res) => {
    const code = req.query.code as string | undefined
    if (!code) {
      res.status(400).send('Error: No authorization code received')
      return
    }

    authCode = code
    log('Auth code received, resolving promise')
    authCompletedResolve(code)

    res.send(`
      Authorization successful!
      You may close this window and return to the CLI.
      <script>
        // If this is a non-interactive session (no manual approval step was required) then
        // this should automatically close the window. If not, this will have no effect and
        // the user will see the message above.
        window.close();
      </script>
    `)

    // Notify main flow that auth code is available
    options.events.emit('auth-code-received', code)
  })

  const server = app.listen(options.port, () => {
    log(`OAuth callback server running at http://127.0.0.1:${options.port}`)
  })

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

  return { server, authCode, waitForAuthCode, authCompletedPromise }
}

/**
 * Sets up an Express server to handle OAuth callbacks
 * @param options The server options
 * @returns An object with the server, authCode, and waitForAuthCode function
 */
export function setupOAuthCallbackServer(options: OAuthCallbackServerOptions) {
  const { server, authCode, waitForAuthCode } = setupOAuthCallbackServerWithLongPoll(options)
  return { server, authCode, waitForAuthCode }
}

async function findExistingClientPort(serverUrlHash: string): Promise<number | undefined> {
  const clientInfo = await readJsonFile<OAuthClientInformationFull>(serverUrlHash, 'client_info.json', OAuthClientInformationFullSchema)
  if (!clientInfo) {
    return undefined
  }

  const localhostRedirectUri = clientInfo.redirect_uris
    .map((uri) => new URL(uri))
    .find(({ hostname }) => hostname === 'localhost' || hostname === '127.0.0.1')
  if (!localhostRedirectUri) {
    throw new Error('Cannot find localhost callback URI from existing client information')
  }

  return parseInt(localhostRedirectUri.port)
}

function calculateDefaultPort(serverUrlHash: string): number {
  // Convert the first 4 bytes of the serverUrlHash into a port offset
  const offset = parseInt(serverUrlHash.substring(0, 4), 16)
  // Pick a consistent but random-seeming port from 3335 to 49151
  return 3335 + (offset % 45816)
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
 * @param usage Usage message to show on error
 * @returns A promise that resolves to an object with parsed serverUrl, callbackPort and headers
 */
export async function parseCommandLineArgs(args: string[], usage: string) {
  // Process headers
  const headers: Record<string, string> = {}
  let i = 0
  while (i < args.length) {
    if (args[i] === '--header' && i < args.length - 1) {
      const value = args[i + 1]
      const match = value.match(/^([A-Za-z0-9_-]+):(.*)$/)
      if (match) {
        headers[match[1]] = match[2]
      } else {
        log(`Warning: ignoring invalid header argument: ${value}`)
      }
      args.splice(i, 2)
      // Do not increment i, as the array has shifted
      continue
    }
    i++
  }

  const serverUrl = args[0]
  const specifiedPort = args[1] ? parseInt(args[1]) : undefined
  const allowHttp = args.includes('--allow-http')

  // Check for debug flag
  const debug = args.includes('--debug')
  if (debug) {
    DEBUG = true
    log('Debug mode enabled - detailed logs will be written to ~/.mcp-auth/')
  }

  // Parse transport strategy
  let transportStrategy: TransportStrategy = 'http-first' // Default
  const transportIndex = args.indexOf('--transport')
  if (transportIndex !== -1 && transportIndex < args.length - 1) {
    const strategy = args[transportIndex + 1]
    if (strategy === 'sse-only' || strategy === 'http-only' || strategy === 'sse-first' || strategy === 'http-first') {
      transportStrategy = strategy as TransportStrategy
      log(`Using transport strategy: ${transportStrategy}`)
    } else {
      log(`Warning: Ignoring invalid transport strategy: ${strategy}. Valid values are: sse-only, http-only, sse-first, http-first`)
    }
  }

  // Parse host
  let host = 'localhost' // Default
  const hostIndex = args.indexOf('--host')
  if (hostIndex !== -1 && hostIndex < args.length - 1) {
    host = args[hostIndex + 1]
    log(`Using callback hostname: ${host}`)
  }

  let staticOAuthClientMetadata: StaticOAuthClientMetadata = null
  const staticOAuthClientMetadataIndex = args.indexOf('--static-oauth-client-metadata')
  if (staticOAuthClientMetadataIndex !== -1 && staticOAuthClientMetadataIndex < args.length - 1) {
    const staticOAuthClientMetadataArg = args[staticOAuthClientMetadataIndex + 1]
    if (staticOAuthClientMetadataArg.startsWith('@')) {
      const filePath = staticOAuthClientMetadataArg.slice(1)
      staticOAuthClientMetadata = JSON.parse(await readFile(filePath, 'utf8'))
      log(`Using static OAuth client metadata from file: ${filePath}`)
    } else {
      staticOAuthClientMetadata = JSON.parse(staticOAuthClientMetadataArg)
      log(`Using static OAuth client metadata from string`)
    }
  }

  // parse static OAuth client information, if provided
  // defaults to OAuth dynamic client registration
  let staticOAuthClientInfo: StaticOAuthClientInformationFull = null
  const staticOAuthClientInfoIndex = args.indexOf('--static-oauth-client-info')
  if (staticOAuthClientInfoIndex !== -1 && staticOAuthClientInfoIndex < args.length - 1) {
    const staticOAuthClientInfoArg = args[staticOAuthClientInfoIndex + 1]
    if (staticOAuthClientInfoArg.startsWith('@')) {
      const filePath = staticOAuthClientInfoArg.slice(1)
      staticOAuthClientInfo = JSON.parse(await readFile(filePath, 'utf8'))
      log(`Using static OAuth client information from file: ${filePath}`)
    } else {
      staticOAuthClientInfo = JSON.parse(staticOAuthClientInfoArg)
      log(`Using static OAuth client information from string`)
    }
  }

  if (!serverUrl) {
    log(usage)
    process.exit(1)
  }

  const url = new URL(serverUrl)
  const isLocalhost = (url.hostname === 'localhost' || url.hostname === '127.0.0.1') && url.protocol === 'http:'

  if (!(url.protocol == 'https:' || isLocalhost || allowHttp)) {
    log('Error: Non-HTTPS URLs are only allowed for localhost or when --allow-http flag is provided')
    log(usage)
    process.exit(1)
  }
  const serverUrlHash = getServerUrlHash(serverUrl)

  // Set server hash globally for debug logging
  global.currentServerUrlHash = serverUrlHash

  if (DEBUG) {
    debugLog(`Starting mcp-remote with server URL: ${serverUrl}`)
  }

  const defaultPort = calculateDefaultPort(serverUrlHash)

  // Use the specified port, or the existing client port or fallback to find an available one
  const [existingClientPort, availablePort] = await Promise.all([findExistingClientPort(serverUrlHash), findAvailablePort(defaultPort)])
  let callbackPort: number

  if (specifiedPort) {
    if (existingClientPort && specifiedPort !== existingClientPort) {
      log(
        `Warning! Specified callback port of ${specifiedPort}, which conflicts with existing client registration port ${existingClientPort}. Deleting existing client data to force reregistration.`,
      )
      await rm(getConfigFilePath(serverUrlHash, 'client_info.json'))
    }
    log(`Using specified callback port: ${specifiedPort}`)
    callbackPort = specifiedPort
  } else if (existingClientPort) {
    log(`Using existing client port: ${existingClientPort}`)
    callbackPort = existingClientPort
  } else {
    log(`Using automatically selected callback port: ${availablePort}`)
    callbackPort = availablePort
  }

  if (Object.keys(headers).length > 0) {
    log(`Using custom headers: ${JSON.stringify(headers)}`)
  }
  // Replace environment variables in headers
  // example `Authorization: Bearer ${TOKEN}` will read process.env.TOKEN
  for (const [key, value] of Object.entries(headers)) {
    headers[key] = value.replace(/\$\{([^}]+)}/g, (match, envVarName) => {
      const envVarValue = process.env[envVarName]

      if (envVarValue !== undefined) {
        log(`Replacing ${match} with environment value in header '${key}'`)
        return envVarValue
      } else {
        log(`Warning: Environment variable '${envVarName}' not found for header '${key}'.`)
        return ''
      }
    })
  }

  // Parse tool prefix option
  let toolPrefix: string | undefined
  const toolPrefixIndex = args.indexOf('--tool-prefix')
  if (toolPrefixIndex !== -1 && toolPrefixIndex < args.length - 1) {
    toolPrefix = args[toolPrefixIndex + 1]
    log(`Using tool prefix: ${toolPrefix}`)
  }

  // Parse tool filter option (comma-separated list of allowed tools)
  let toolFilter: string[] | undefined
  const toolFilterIndex = args.indexOf('--tool-filter')
  if (toolFilterIndex !== -1 && toolFilterIndex < args.length - 1) {
    toolFilter = args[toolFilterIndex + 1]
      .split(',')
      .map((t) => t.trim())
      .filter((t) => t.length > 0)
    log(`Using tool filter: ${toolFilter.join(', ')}`)
  }

  return {
    serverUrl,
    callbackPort,
    headers,
    transportStrategy,
    host,
    debug,
    staticOAuthClientMetadata,
    staticOAuthClientInfo,
    toolPrefix,
    toolFilter,
  }
}

/**
 * Sets up signal handlers for graceful shutdown
 * @param cleanup Cleanup function to run on shutdown
 */
export function setupSignalHandlers(cleanup: () => Promise<void>) {
  process.on('SIGINT', async () => {
    log('\nShutting down...')
    await cleanup()
    process.exit(0)
  })

  // Keep the process alive
  process.stdin.resume()
  process.stdin.on('end', async () => {
    log('\nShutting down...')
    await cleanup()
    process.exit(0)
  })
}

/**
 * Generates a hash for the server URL to use in filenames
 * @param serverUrl The server URL to hash
 * @returns The hashed server URL
 */
export function getServerUrlHash(serverUrl: string): string {
  return crypto.createHash('md5').update(serverUrl).digest('hex')
}

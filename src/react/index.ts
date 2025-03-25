import { CallToolResultSchema, JSONRPCMessage, ListToolsResultSchema, Tool } from '@modelcontextprotocol/sdk/types.js'
import { useCallback, useEffect, useRef, useState } from 'react'
import { SSEClientTransport } from '@modelcontextprotocol/sdk/client/sse.js'
import { Client } from '@modelcontextprotocol/sdk/client/index.js'
import {
  OAuthClientProvider,
  discoverOAuthMetadata,
  exchangeAuthorization,
  startAuthorization,
} from '@modelcontextprotocol/sdk/client/auth.js'
import { OAuthClientInformation, OAuthMetadata, OAuthTokens } from '@modelcontextprotocol/sdk/shared/auth.js'

function assert(condition: unknown, message: string): asserts condition {
  if (!condition) {
    throw new Error(message)
  }
}

export type UseMcpOptions = {
  /** The /sse URL of your remote MCP server */
  url: string
  /** OAuth client name for registration */
  clientName?: string
  /** OAuth client URI for registration */
  clientUri?: string
  /** Custom callback URL for OAuth redirect (defaults to /oauth/callback on the current origin) */
  callbackUrl?: string
  /** Storage key prefix for OAuth data (defaults to "mcp_auth") */
  storageKeyPrefix?: string
  /** Custom configuration for the MCP client */
  clientConfig?: {
    name?: string
    version?: string
  }
  /** Whether to enable debug logging */
  debug?: boolean
  /** Auto retry connection if it fails, with delay in ms (default: false) */
  autoRetry?: boolean | number
  /** Auto reconnect if connection is lost, with delay in ms (default: 3000) */
  autoReconnect?: boolean | number
  /** Popup window features (dimensions and behavior) for OAuth */
  popupFeatures?: string
}

export type UseMcpResult = {
  tools: Tool[]
  /**
   * The current state of the MCP connection. This will be one of:
   * - 'discovering': Finding out whether there is in fact a server at that URL, and what its capabilities are
   * - 'authenticating': The server has indicated we must authenticate, so we can't proceed until that's complete
   * - 'connecting': The connection to the MCP server is being established. This happens before we know whether we need to authenticate or not, and then again once we have credentials
   * - 'loading': We're connected to the MCP server, and now we're loading its resources/prompts/tools
   * - 'ready': The MCP server is connected and ready to be used
   * - 'failed': The connection to the MCP server failed
   * */
  state: 'discovering' | 'authenticating' | 'connecting' | 'loading' | 'ready' | 'failed'
  /** If the state is 'failed', this will be the error message */
  error?: string
  /**
   * If authorization was blocked, this will contain the URL to authorize manually
   * The app can render this as a link with target="_blank" so the user can complete
   * authorization without leaving the app
   */
  authUrl?: string
  /** All internal log messages */
  log: { level: 'debug' | 'info' | 'warn' | 'error'; message: string }[]
  /** Call a tool on the MCP server */
  callTool: (name: string, args?: Record<string, unknown>) => Promise<any>
  /** Manually retry connection if it's in a failed state */
  retry: () => void
  /** Manually disconnect from the MCP server */
  disconnect: () => void
  /**
   * Manually trigger authentication
   * @returns Auth URL that can be used to manually open a new window
   */
  authenticate: () => Promise<string | undefined>
  /**
   * Clear all localStorage items for this server
   */
  clearStorage: () => void
}

type StoredState = {
  authorizationUrl: string
  metadata: OAuthMetadata
  serverUrlHash: string
  expiry: number
}

/**
 * Browser-compatible OAuth client provider for MCP
 */
class BrowserOAuthClientProvider implements OAuthClientProvider {
  private storageKeyPrefix: string
  serverUrlHash: string
  private clientName: string
  private clientUri: string
  private callbackUrl: string
  // Store additional options for popup windows
  private popupFeatures: string

  constructor(
    readonly serverUrl: string,
    options: {
      storageKeyPrefix?: string
      clientName?: string
      clientUri?: string
      callbackUrl?: string
      popupFeatures?: string
    } = {},
  ) {
    this.storageKeyPrefix = options.storageKeyPrefix || 'mcp:auth'
    this.serverUrlHash = this.hashString(serverUrl)
    this.clientName = options.clientName || 'MCP Browser Client'
    this.clientUri = options.clientUri || window.location.origin
    this.callbackUrl = options.callbackUrl || new URL('/oauth/callback', window.location.origin).toString()
    this.popupFeatures = options.popupFeatures || 'width=600,height=700,resizable=yes,scrollbars=yes'
  }

  get redirectUrl(): string {
    return this.callbackUrl
  }

  get clientMetadata() {
    return {
      redirect_uris: [this.redirectUrl],
      token_endpoint_auth_method: 'none',
      grant_types: ['authorization_code', 'refresh_token'],
      response_types: ['code'],
      client_name: this.clientName,
      client_uri: this.clientUri,
    }
  }

  /**
   * Clears all storage items related to this server
   * @returns The number of items cleared
   */
  clearStorage(): number {
    const prefix = `${this.storageKeyPrefix}_${this.serverUrlHash}`
    const keysToRemove = []

    // Find all keys that match the prefix
    for (let i = 0; i < localStorage.length; i++) {
      const key = localStorage.key(i)
      if (key && key.startsWith(prefix)) {
        keysToRemove.push(key)
      }
    }

    // Also check for any state keys
    for (let i = 0; i < localStorage.length; i++) {
      const key = localStorage.key(i)
      if (key && key.startsWith(`${this.storageKeyPrefix}:state_`)) {
        // Load state to check if it's for this server
        try {
          const state = JSON.parse(localStorage.getItem(key) || '{}')
          if (state.serverUrlHash === this.serverUrlHash) {
            keysToRemove.push(key)
          }
        } catch (e) {
          // Ignore JSON parse errors
        }
      }
    }

    // Remove all matching keys
    keysToRemove.forEach((key) => localStorage.removeItem(key))

    return keysToRemove.length
  }

  private hashString(str: string): string {
    // Simple hash function for browser environments
    let hash = 0
    for (let i = 0; i < str.length; i++) {
      const char = str.charCodeAt(i)
      hash = (hash << 5) - hash + char
      hash = hash & hash // Convert to 32bit integer
    }
    return Math.abs(hash).toString(16)
  }

  getKey(key: string): string {
    return `${this.storageKeyPrefix}_${this.serverUrlHash}_${key}`
  }

  async clientInformation(): Promise<OAuthClientInformation | undefined> {
    const key = this.getKey('client_info')
    const data = localStorage.getItem(key)
    if (!data) return undefined

    try {
      return JSON.parse(data) as OAuthClientInformation
    } catch (e) {
      return undefined
    }
  }

  async saveClientInformation(clientInformation: OAuthClientInformation): Promise<void> {
    const key = this.getKey('client_info')
    localStorage.setItem(key, JSON.stringify(clientInformation))
  }

  async tokens(): Promise<OAuthTokens | undefined> {
    const key = this.getKey('tokens')
    const data = localStorage.getItem(key)
    if (!data) return undefined

    try {
      return JSON.parse(data) as OAuthTokens
    } catch (e) {
      return undefined
    }
  }

  async saveTokens(tokens: OAuthTokens): Promise<void> {
    const key = this.getKey('tokens')
    localStorage.setItem(key, JSON.stringify(tokens))
  }

  /**
   * Redirect method that matches the interface expected by OAuthClientProvider
   */
  async redirectToAuthorization(authorizationUrl: URL): Promise<void> {
    // Simply open the URL in the current window
    console.log('WE WERE ABOUT TO REDIRECT BUT WE DONT DO THAT HERE')
    // window.location.href = authorizationUrl.toString()
  }

  /**
   * Extended popup-based authorization method specific to browser environments
   */
  async openAuthorizationPopup(
    authorizationUrl: URL,
    metadata: OAuthMetadata,
  ): Promise<{ success: boolean; popupBlocked?: boolean; url: string }> {
    // Use existing state parameter if it exists in the URL
    const existingState = authorizationUrl.searchParams.get('state')

    if (!existingState) {
      // This should not happen as startAuthFlow should've added state
      // But if it doesn't exist, add it as a fallback
      const state = Math.random().toString(36).substring(2)
      const stateKey = `${this.storageKeyPrefix}:state_${state}`

      localStorage.setItem(
        stateKey,
        JSON.stringify({
          authorizationUrl: authorizationUrl.toString(),
          metadata,
          serverUrlHash: this.serverUrlHash,
          expiry: +new Date() + 1000 * 60 * 5 /* 5 minutes */,
        } as StoredState),
      )

      authorizationUrl.searchParams.set('state', state)
    }

    const authUrl = authorizationUrl.toString()

    // Store the auth URL in case we need it for manual authentication
    localStorage.setItem(this.getKey('auth_url'), authUrl)

    try {
      // Open the authorization URL in a popup window
      const popup = window.open(authUrl, 'mcp_auth', this.popupFeatures)

      // Check if popup was blocked or closed immediately
      if (!popup || popup.closed || popup.closed === undefined) {
        console.warn('Popup blocked. Returning error.')
        return { success: false, popupBlocked: true, url: authUrl }
      }

      // Try to access the popup to confirm it's not blocked
      try {
        // Just accessing any property will throw if popup is blocked
        const popupLocation = popup.location
        // If we can read location.href, the popup is definitely working
        if (popupLocation.href) {
          // Successfully opened popup
          return { success: true, url: authUrl }
        }
      } catch (e) {
        // Access to the popup was denied, indicating it's blocked
        console.warn('Popup blocked (security exception).')
        return { success: false, popupBlocked: true, url: authUrl }
      }

      // If we got here, popup is working
      return { success: true, url: authUrl }
    } catch (e) {
      // Error opening popup
      console.warn('Error opening popup:', e)
      return { success: false, popupBlocked: true, url: authUrl }
    }
  }

  async saveCodeVerifier(codeVerifier: string): Promise<void> {
    const key = this.getKey('code_verifier')
    localStorage.setItem(key, codeVerifier)
  }

  async codeVerifier(): Promise<string> {
    const key = this.getKey('code_verifier')
    const verifier = localStorage.getItem(key)
    if (!verifier) {
      throw new Error('No code verifier found in storage')
    }
    return verifier
  }
}

/**
 * Class to encapsulate all MCP client functionality,
 * including authentication flow and connection management
 */
class McpClient {
  // State
  private _state: UseMcpResult['state'] = 'discovering'
  private _error?: string
  private _tools: Tool[] = []
  private _log: UseMcpResult['log'] = []
  private _authUrl?: string

  // Client and transport
  private client: Client | null = null
  private transport: SSEClientTransport | null = null
  private authProvider: BrowserOAuthClientProvider | undefined = undefined

  // Authentication state
  private metadata?: OAuthMetadata
  private authUrlRef?: URL
  private authState?: string
  private codeVerifier?: string
  private connecting = false

  // Update callbacks
  private onStateChange: (state: UseMcpResult['state']) => void
  private onToolsChange: (tools: Tool[]) => void
  private onErrorChange: (error?: string) => void
  private onLogChange: (log: UseMcpResult['log']) => void
  private onAuthUrlChange: (authUrl?: string) => void

  constructor(
    private url: string,
    private options: {
      clientName?: string
      clientUri?: string
      callbackUrl?: string
      storageKeyPrefix?: string
      clientConfig?: {
        name?: string
        version?: string
      }
      debug?: boolean
      autoRetry?: boolean | number
      autoReconnect?: boolean | number
      popupFeatures?: string
    },
    callbacks: {
      onStateChange: (state: UseMcpResult['state']) => void
      onToolsChange: (tools: Tool[]) => void
      onErrorChange: (error?: string) => void
      onLogChange: (log: UseMcpResult['log']) => void
      onAuthUrlChange: (authUrl?: string) => void
    },
  ) {
    // Initialize callbacks
    this.onStateChange = callbacks.onStateChange
    this.onToolsChange = callbacks.onToolsChange
    this.onErrorChange = callbacks.onErrorChange
    this.onLogChange = callbacks.onLogChange
    this.onAuthUrlChange = callbacks.onAuthUrlChange

    // Initialize auth provider
    this.initAuthProvider()
  }

  get state(): UseMcpResult['state'] {
    return this._state
  }

  get tools(): Tool[] {
    return this._tools
  }

  get error(): string | undefined {
    return this._error
  }

  get log(): UseMcpResult['log'] {
    return this._log
  }

  get authUrl(): string | undefined {
    return this._authUrl
  }

  /**
   * Initialize the auth provider
   */
  private initAuthProvider(): void {
    if (!this.authProvider) {
      this.authProvider = new BrowserOAuthClientProvider(this.url, {
        storageKeyPrefix: this.options.storageKeyPrefix,
        clientName: this.options.clientName,
        clientUri: this.options.clientUri,
        callbackUrl: this.options.callbackUrl,
      })
    }
  }

  /**
   * Add a log entry
   */
  private addLog(level: 'debug' | 'info' | 'warn' | 'error', message: string): void {
    if (level === 'debug' && !this.options.debug) return
    this._log = [...this._log, { level, message }]
    this.onLogChange(this._log)
  }

  /**
   * Update the state
   */
  private setState(state: UseMcpResult['state']): void {
    this._state = state
    this.onStateChange(state)
  }

  /**
   * Update the error
   */
  private setError(error?: string): void {
    this._error = error
    this.onErrorChange(error)
  }

  /**
   * Update the tools
   */
  private setTools(tools: Tool[]): void {
    this._tools = tools
    this.onToolsChange(tools)
  }

  /**
   * Update the auth URL
   */
  private setAuthUrl(authUrl?: string): void {
    this._authUrl = authUrl
    this.onAuthUrlChange(authUrl)
  }

  /**
   * Handle OAuth discovery and authentication
   */
  private async discoverOAuthAndAuthenticate(error: Error): Promise<void> {
    try {
      // Discover OAuth metadata now that we know we need it
      if (!this.metadata) {
        this.addLog('info', 'Discovering OAuth metadata...')
        this.metadata = await discoverOAuthMetadata(this.url)
        this.addLog('debug', `OAuth metadata: ${this.metadata ? 'Found' : 'Not available'}`)
      }

      // If metadata is found, start auth flow
      if (this.metadata) {
        this.setState('authenticating')

        try {
          // Start authentication process
          await this.handleAuthentication()

          // After successful auth, retry connection
          // Important: We need to fully disconnect and reconnect
          await this.disconnect()
          await this.connect()
        } catch (authErr) {
          this.addLog('error', `Authentication error: ${authErr instanceof Error ? authErr.message : String(authErr)}`)
          this.setState('failed')
          this.setError(`Authentication failed: ${authErr instanceof Error ? authErr.message : String(authErr)}`)
          this.connecting = false
        }
      } else {
        // No OAuth metadata available
        this.setState('failed')
        this.setError(`Authentication required but no OAuth metadata found: ${error.message}`)
        this.connecting = false
      }
    } catch (oauthErr) {
      this.addLog('error', `OAuth discovery error: ${oauthErr instanceof Error ? oauthErr.message : String(oauthErr)}`)
      this.setState('failed')
      this.setError(`Authentication setup failed: ${oauthErr instanceof Error ? oauthErr.message : String(oauthErr)}`)
      this.connecting = false
    }
  }

  /**
   * Connect to the MCP server
   */
  async connect(): Promise<void> {
    // Prevent multiple simultaneous connection attempts
    if (this.connecting) return
    this.connecting = true

    try {
      this.setState('discovering')
      this.setError(undefined)

      // Create MCP client
      this.client = new Client(
        {
          name: this.options.clientConfig?.name || 'mcp-react-client',
          version: this.options.clientConfig?.version || '0.1.0',
        },
        {
          capabilities: {
            sampling: {},
          },
        },
      )

      // Create SSE transport
      this.setState('connecting')
      this.addLog('info', 'Creating transport...')

      const serverUrl = new URL(this.url)
      this.transport = new SSEClientTransport(serverUrl, {
        authProvider: this.authProvider,
      })

      // Set up transport handlers
      this.transport.onmessage = (message: JSONRPCMessage) => {
        // @ts-expect-error TODO: fix this type
        this.addLog('debug', `Received message: ${message.method || message.id}`)
      }

      this.transport.onerror = (err: Error) => {
        this.addLog('error', `Transport error: ${err.message}`)

        if (err.message.includes('Unauthorized')) {
          // Only discover OAuth metadata and authenticate if we get a 401
          this.discoverOAuthAndAuthenticate(err)
        } else {
          this.setState('failed')
          this.setError(`Connection error: ${err.message}`)
          this.connecting = false
        }
      }

      this.transport.onclose = () => {
        this.addLog('info', 'Connection closed')
        // If we were previously connected, try to reconnect
        if (this.state === 'ready' && this.options.autoReconnect) {
          const delay = typeof this.options.autoReconnect === 'number' ? this.options.autoReconnect : 3000
          this.addLog('info', `Will reconnect in ${delay}ms...`)
          setTimeout(() => {
            this.disconnect().then(() => this.connect())
          }, delay)
        }
      }

      // Try connecting transport
      try {
        this.addLog('info', 'Starting transport...')
        // await this.transport.start()
      } catch (err) {
        this.addLog('error', `Transport start error: ${err instanceof Error ? err.message : String(err)}`)

        if (err instanceof Error && err.message.includes('Unauthorized')) {
          // Only discover OAuth and authenticate if we get a 401
          await this.discoverOAuthAndAuthenticate(err)
          return // Important: Return here to avoid proceeding with the unauthorized connection
        } else {
          this.setState('failed')
          this.setError(`Connection error: ${err instanceof Error ? err.message : String(err)}`)
          this.connecting = false
          return
        }
      }

      // Connect client
      try {
        this.addLog('info', 'Connecting client...')
        this.setState('loading')
        await this.client.connect(this.transport)
        this.addLog('info', 'Client connected')

        // Load tools
        try {
          this.addLog('info', 'Loading tools...')
          const toolsResponse = await this.client.request({ method: 'tools/list' }, ListToolsResultSchema)
          this.setTools(toolsResponse.tools)
          this.addLog('info', `Loaded ${toolsResponse.tools.length} tools`)

          // Connection completed successfully
          this.setState('ready')
          this.connecting = false
        } catch (toolErr) {
          this.addLog('error', `Error loading tools: ${toolErr instanceof Error ? toolErr.message : String(toolErr)}`)
          // We're still connected, just couldn't load tools
          this.setState('ready')
          this.connecting = false
        }
      } catch (connectErr) {
        this.addLog('error', `Client connect error: ${connectErr instanceof Error ? connectErr.message : String(connectErr)}`)

        if (connectErr instanceof Error && connectErr.message.includes('Unauthorized')) {
          // Only discover OAuth and authenticate if we get a 401
          await this.discoverOAuthAndAuthenticate(connectErr)
        } else {
          this.setState('failed')
          this.setError(`Connection error: ${connectErr instanceof Error ? connectErr.message : String(connectErr)}`)
          this.connecting = false
        }
      }
    } catch (err) {
      this.addLog('error', `Unexpected error: ${err instanceof Error ? err.message : String(err)}`)
      this.setState('failed')
      this.setError(`Unexpected error: ${err instanceof Error ? err.message : String(err)}`)
      this.connecting = false
    }
  }

  /**
   * Disconnect from the MCP server
   */
  async disconnect(): Promise<void> {
    if (this.client) {
      try {
        await this.client.close()
      } catch (err) {
        this.addLog('error', `Error closing client: ${err instanceof Error ? err.message : String(err)}`)
      }
      this.client = null
    }

    if (this.transport) {
      try {
        await this.transport.close()
      } catch (err) {
        this.addLog('error', `Error closing transport: ${err instanceof Error ? err.message : String(err)}`)
      }
      this.transport = null
    }

    this.connecting = false
    this.setState('discovering')
    this.setTools([])
    this.setError(undefined)
  }

  /**
   * Start the auth flow and get the auth URL
   */
  async startAuthFlow(): Promise<URL | undefined> {
    if (!this.authProvider || !this.metadata) {
      throw new Error('Auth provider or metadata not available')
    }

    this.addLog('info', 'Starting authentication flow...')

    // Check if we have client info
    let clientInfo = await this.authProvider.clientInformation()

    if (!clientInfo) {
      // Register client dynamically
      this.addLog('info', 'No client information found, registering...')
      // Note: In a complete implementation, you'd register the client here
      // This would be done server-side in a real application
      throw new Error('Dynamic client registration not implemented in this example')
    }

    // Start authorization flow
    this.addLog('info', 'Preparing authorization...')
    const { authorizationUrl, codeVerifier } = await startAuthorization(this.url, {
      metadata: this.metadata,
      clientInformation: clientInfo,
      redirectUrl: this.authProvider.redirectUrl,
    })

    // Save code verifier and auth URL for later use
    await this.authProvider.saveCodeVerifier(codeVerifier)
    this.codeVerifier = codeVerifier

    // Generate state parameter that will be used for both popup and manual flows
    const state = Math.random().toString(36).substring(2)
    const stateKey = `${this.options.storageKeyPrefix}:state_${state}`

    // Store state for later retrieval
    localStorage.setItem(
      stateKey,
      JSON.stringify({
        authorizationUrl: authorizationUrl.toString(),
        metadata: this.metadata,
        serverUrlHash: this.authProvider.serverUrlHash,
        expiry: +new Date() + 1000 * 60 * 5 /* 5 minutes */,
      } as StoredState),
    )

    // Add state to the URL
    authorizationUrl.searchParams.set('state', state)

    // Store the state and URL for later use
    this.authState = state
    this.authUrlRef = authorizationUrl

    // Set manual auth URL (already includes state parameter)
    this.setAuthUrl(authorizationUrl.toString())

    return authorizationUrl
  }

  /**
   * Handle authentication flow
   */
  async handleAuthentication(): Promise<string> {
    if (!this.authProvider) {
      throw new Error('Auth provider not available')
    }

    // Get or create the auth URL
    if (!this.authUrlRef) {
      try {
        await this.startAuthFlow()
      } catch (err) {
        this.addLog('error', `Failed to start auth flow: ${err instanceof Error ? err.message : String(err)}`)
        throw err
      }
    }

    if (!this.authUrlRef) {
      throw new Error('Failed to create authorization URL')
    }

    // Set up listener for post-auth message
    const authPromise = new Promise<string>((resolve, reject) => {
      let pollIntervalId: number | undefined

      const timeoutId = setTimeout(
        () => {
          window.removeEventListener('message', messageHandler)
          if (pollIntervalId) clearTimeout(pollIntervalId)
          reject(new Error('Authentication timeout after 5 minutes'))
        },
        5 * 60 * 1000,
      )

      const messageHandler = (event: MessageEvent) => {
        // Verify origin for security
        if (event.origin !== window.location.origin) return

        if (event.data && event.data.type === 'mcp_auth_callback' && event.data.code) {
          window.removeEventListener('message', messageHandler)
          clearTimeout(timeoutId)
          if (pollIntervalId) clearTimeout(pollIntervalId)

          resolve(event.data.code)
        }
      }

      window.addEventListener('message', messageHandler)

      // Add polling fallback to check for tokens in localStorage
      const pollForTokens = () => {
        try {
          // Check if tokens have appeared in localStorage
          const tokensKey = this.authProvider!.getKey('tokens')
          const storedTokens = localStorage.getItem(tokensKey)

          if (storedTokens) {
            // Tokens found, clean up and resolve
            window.removeEventListener('message', messageHandler)
            clearTimeout(timeoutId)
            if (pollIntervalId) clearTimeout(pollIntervalId)

            // Parse tokens to make sure they're valid
            const tokens = JSON.parse(storedTokens)
            if (tokens.access_token) {
              console.log('Found tokens in localStorage via polling')
              // Resolve with an object that indicates tokens are already available
              // This will signal to handleAuthCompletion that no token exchange is needed
              resolve('TOKENS_ALREADY_EXCHANGED')
            }
          }
        } catch (err) {
          // Error during polling, continue anyway
          console.error(err)
        }
      }

      // Start polling every 500ms using setTimeout for recursive polling
      const poll = () => {
        pollIntervalId = setTimeout(poll, 500) as unknown as number
        pollForTokens()
      }

      poll() // Start the polling
    })

    // Redirect to authorization
    this.addLog('info', 'Opening authorization window...')
    assert(this.metadata, 'Metadata not available')
    const redirectResult = await this.authProvider.openAuthorizationPopup(this.authUrlRef, this.metadata)

    if (!redirectResult.success) {
      // Popup was blocked
      this.setState('failed')
      this.setError('Authentication popup was blocked by the browser. Please click the link to authenticate in a new window.')
      this.setAuthUrl(redirectResult.url)
      this.addLog('warn', 'Authentication popup was blocked. User needs to manually authorize.')
      throw new Error('Authentication popup blocked')
    }

    // Wait for auth to complete
    this.addLog('info', 'Waiting for authorization...')
    const code = await authPromise
    this.addLog('info', 'Authorization code received')

    return code
  }

  /**
   * Handle authentication completion
   * @param code - The authorization code or special token indicator
   */
  async handleAuthCompletion(code: string): Promise<void> {
    if (!this.authProvider || !this.transport) {
      throw new Error('Authentication context not available')
    }

    try {
      // Check if this is our special token indicator
      if (code === 'TOKENS_ALREADY_EXCHANGED') {
        this.addLog('info', 'Using already exchanged tokens from localStorage')
        // No need to exchange tokens, they're already in localStorage
      } else {
        // We received an authorization code that needs to be exchanged
        this.addLog('info', 'Finishing authorization with code exchange...')
        await this.transport.finishAuth(code)
        this.addLog('info', 'Authorization code exchanged for tokens')
      }

      this.addLog('info', 'Authorization completed')

      // Reset auth URL state
      this.authUrlRef = undefined
      this.setAuthUrl(undefined)

      // Reconnect with the new auth token - important to do a full disconnect/connect cycle
      await this.disconnect()
      await this.connect()
    } catch (err) {
      this.addLog('error', `Auth completion error: ${err instanceof Error ? err.message : String(err)}`)
      this.setState('failed')
      this.setError(`Authentication failed: ${err instanceof Error ? err.message : String(err)}`)
    }
  }

  /**
   * Call a tool on the MCP server
   */
  async callTool(name: string, args?: Record<string, unknown>): Promise<any> {
    if (!this.client || this.state !== 'ready') {
      throw new Error('MCP client not ready')
    }

    try {
      const result = await this.client.request(
        {
          method: 'tools/call',
          params: { name, arguments: args },
        },
        CallToolResultSchema,
      )
      return result
    } catch (err) {
      this.addLog('error', `Error calling tool ${name}: ${err instanceof Error ? err.message : String(err)}`)
      throw err
    }
  }

  /**
   * Retry connection
   */
  retry(): void {
    if (this.state === 'failed') {
      this.disconnect().then(() => this.connect())
    }
  }

  /**
   * Manually trigger authentication
   */
  async authenticate(): Promise<string | undefined> {
    if (!this.authProvider) {
      try {
        // Discover OAuth metadata if we don't have it yet
        this.addLog('info', 'Discovering OAuth metadata...')
        this.metadata = await discoverOAuthMetadata(this.url)
        this.addLog('debug', `OAuth metadata: ${this.metadata ? 'Found' : 'Not available'}`)

        if (!this.metadata) {
          throw new Error('No OAuth metadata available')
        }

        // Initialize the auth provider now that we have metadata
        this.initAuthProvider()
      } catch (err) {
        this.addLog('error', `Failed to discover OAuth metadata: ${err instanceof Error ? err.message : String(err)}`)
        return undefined
      }
    }

    try {
      // If we don't have an auth URL yet with state param, start a new flow
      if (!this.authUrlRef || !this.authUrlRef.searchParams.get('state')) {
        await this.startAuthFlow()
      }

      if (!this.authUrlRef) {
        throw new Error('Failed to create authorization URL')
      }

      // The URL already has the state parameter from startAuthFlow
      return this.authUrlRef.toString()
    } catch (err) {
      this.addLog('error', `Error preparing manual authentication: ${err instanceof Error ? err.message : String(err)}`)
      return undefined
    }
  }

  /**
   * Clear all localStorage items for this server
   */
  clearStorage(): number {
    if (!this.authProvider) {
      this.addLog('warn', 'Cannot clear storage: auth provider not initialized')
      return 0
    }

    // Use the provider's method to clear storage
    const clearedCount = this.authProvider.clearStorage()

    // Clear auth-related state in the class
    this.authUrlRef = undefined
    this.setAuthUrl(undefined)
    this.metadata = undefined
    this.codeVerifier = undefined

    this.addLog('info', `Cleared ${clearedCount} storage items for server`)

    return clearedCount
  }
}

/**
 * useMcp is a React hook that connects to a remote MCP server, negotiates auth
 * (including opening a popup window or new tab to complete the OAuth flow),
 * and enables passing a list of tools (once loaded) to ai-sdk (using `useChat`).
 */
export function useMcp(options: UseMcpOptions): UseMcpResult {
  const [state, setState] = useState<UseMcpResult['state']>('discovering')
  const [tools, setTools] = useState<Tool[]>([])
  const [error, setError] = useState<string | undefined>(undefined)
  const [log, setLog] = useState<UseMcpResult['log']>([])
  const [authUrl, setAuthUrl] = useState<string | undefined>(undefined)

  // Use a ref to maintain a single instance of the McpClient
  const clientRef = useRef<McpClient | null>(null)
  const isInitialMount = useRef<boolean>(true)

  // Initialize the client if it doesn't exist yet
  const getClient = useCallback(() => {
    if (!clientRef.current) {
      clientRef.current = new McpClient(
        options.url,
        {
          clientName: options.clientName || 'MCP React Client',
          clientUri: options.clientUri || window.location.origin,
          callbackUrl: options.callbackUrl || new URL('/oauth/callback', window.location.origin).toString(),
          storageKeyPrefix: options.storageKeyPrefix || 'mcp:auth',
          clientConfig: options.clientConfig || {
            name: 'mcp-react-client',
            version: '0.1.0',
          },
          debug: options.debug || false,
          autoRetry: options.autoRetry || false,
          autoReconnect: options.autoReconnect || 3000,
          popupFeatures: options.popupFeatures || 'width=600,height=700,resizable=yes,scrollbars=yes',
        },
        {
          onStateChange: setState,
          onToolsChange: setTools,
          onErrorChange: setError,
          onLogChange: setLog,
          onAuthUrlChange: setAuthUrl,
        },
      )
    }
    return clientRef.current
  }, [
    options.url,
    options.clientName,
    options.clientUri,
    options.callbackUrl,
    options.storageKeyPrefix,
    options.clientConfig,
    options.debug,
    options.autoRetry,
    options.autoReconnect,
    options.popupFeatures,
  ])

  // Connect on initial mount
  useEffect(() => {
    if (isInitialMount.current) {
      isInitialMount.current = false
      const client = getClient()
      client.connect()
    }
  }, [getClient])

  // Auto-retry on failure
  useEffect(() => {
    if (state === 'failed' && options.autoRetry) {
      const delay = typeof options.autoRetry === 'number' ? options.autoRetry : 5000
      const timeoutId = setTimeout(() => {
        const client = getClient()
        client.retry()
      }, delay)

      return () => {
        clearTimeout(timeoutId)
      }
    }
  }, [state, options.autoRetry, getClient])

  // Set up message listener for auth callback
  useEffect(() => {
    const messageHandler = (event: MessageEvent) => {
      if (event.origin !== window.location.origin) return

      if (event.data && event.data.type === 'mcp_auth_callback') {
        const client = getClient()

        // If code is provided, use it; otherwise, assume tokens are already in localStorage
        if (event.data.code) {
          client.handleAuthCompletion(event.data.code).catch((err) => {
            console.error('Auth callback error:', err)
          })
        } else {
          // Tokens were already exchanged by the popup
          client.handleAuthCompletion('TOKENS_ALREADY_EXCHANGED').catch((err) => {
            console.error('Auth callback error:', err)
          })
        }
      }
    }

    window.addEventListener('message', messageHandler)
    return () => {
      window.removeEventListener('message', messageHandler)
    }
  }, [getClient])

  // Clean up on unmount
  useEffect(() => {
    return () => {
      if (clientRef.current) {
        clientRef.current.disconnect()
      }
    }
  }, [])

  // Public methods - proxied to the client
  const callTool = useCallback(
    async (name: string, args?: Record<string, unknown>) => {
      const client = getClient()
      return client.callTool(name, args)
    },
    [getClient],
  )

  const retry = useCallback(() => {
    const client = getClient()
    client.retry()
  }, [getClient])

  const disconnect = useCallback(async () => {
    const client = getClient()
    await client.disconnect()
  }, [getClient])

  const authenticate = useCallback(async (): Promise<string | undefined> => {
    const client = getClient()
    return client.authenticate()
  }, [getClient])

  const clearStorage = useCallback(() => {
    const client = getClient()
    client.clearStorage()
  }, [getClient])

  return {
    state,
    tools,
    error,
    log,
    authUrl,
    callTool,
    retry,
    disconnect,
    authenticate,
    clearStorage,
  }
}

/**
 * onMcpAuthorization is invoked when the oauth flow completes. This is usually mounted
 * on /oauth/callback, and passed the entire URL query parameters. This first uses the state
 * parameter to look up in LocalStorage the context for the current auth flow, and then
 * completes the flow by exchanging the authorization code for an access token.
 *
 * Once it's updated LocalStorage with the auth token, it will post a message back to the original
 * window to inform any running `useMcp` hooks that the auth flow is complete.
 */
export async function onMcpAuthorization(
  query: Record<string, string>,
  {
    storageKeyPrefix = 'mcp:auth',
  }: {
    storageKeyPrefix?: string
  } = {},
) {
  try {
    // Extract the authorization code and state
    const code = query.code
    const state = query.state

    if (!code) {
      throw new Error('No authorization code received')
    }

    if (!state) {
      throw new Error('No state parameter received')
    }

    // Find the matching auth state in localStorage
    const stateKey = `${storageKeyPrefix}:state_${state}`
    const storedState = localStorage.getItem(stateKey)
    console.log({ stateKey, storedState })
    if (!storedState) {
      throw new Error('No matching auth state found in storage')
    }
    const { authorizationUrl, serverUrlHash, metadata, expiry } = JSON.parse(storedState)
    if (expiry < Date.now()) {
      throw new Error('Auth state has expired')
    }

    // Find all related auth data with the same prefix and server hash
    const clientInfoKey = `${storageKeyPrefix}_${serverUrlHash}_client_info`
    const codeVerifierKey = `${storageKeyPrefix}_${serverUrlHash}_code_verifier`
    console.log({ authorizationUrl, clientInfoKey, codeVerifierKey })

    const clientInfoStr = localStorage.getItem(clientInfoKey)
    const codeVerifier = localStorage.getItem(codeVerifierKey)

    if (!clientInfoStr) {
      throw new Error('No client information found in storage')
    }

    if (!codeVerifier) {
      throw new Error('No code verifier found in storage')
    }

    // Parse client info
    const clientInfo = JSON.parse(clientInfoStr) as OAuthClientInformation

    const tokens = await exchangeAuthorization(new URL('/', authorizationUrl), {
      metadata,
      clientInformation: clientInfo,
      authorizationCode: code,
      codeVerifier,
    })

    // Save the tokens
    const tokensKey = `${storageKeyPrefix}_${serverUrlHash}_tokens`
    console.log({ tokensKey, tokens })
    localStorage.setItem(tokensKey, JSON.stringify(tokens))

    // Post message back to the parent window
    if (window.opener && !window.opener.closed) {
      window.opener.postMessage(
        {
          type: 'mcp_auth_callback',
          // Don't send the code back since we've already done the token exchange
          // This signals to the main window that tokens are already in localStorage
        },
        window.location.origin,
      )
      // Close the popup
      window.close()
    } else {
      // If no parent window, we're in a redirect flow
      // Redirect back to the main page
      window.location.href = '/'
    }

    return { success: true }
  } catch (error) {
    console.error('Error in MCP authorization:', error)

    // Create a readable error message for display
    const errorMessage = error instanceof Error ? error.message : String(error)

    // If the popup is still open, show the error
    const errorHtml = `
      <html>
        <head>
          <title>Authentication Error</title>
          <style>
            body { font-family: sans-serif; padding: 2rem; line-height: 1.5; }
            .error { color: #e53e3e; background: #fed7d7; padding: 1rem; border-radius: 0.25rem; }
          </style>
        </head>
        <body>
          <h1>Authentication Error</h1>
          <div class="error">
            <p>${errorMessage}</p>
          </div>
          <p>You can close this window and try again.</p>
        </body>
      </html>
    `

    document.body.innerHTML = errorHtml

    return { success: false, error: errorMessage }
  }
}

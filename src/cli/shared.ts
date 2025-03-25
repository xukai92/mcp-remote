/**
 * Shared utilities for MCP OAuth clients and proxies.
 * Contains common functionality for authentication, file storage, and proxying.
 */

import express from 'express'
import open from 'open'
import fs from 'fs/promises'
import path from 'path'
import os from 'os'
import crypto from 'crypto'
import net from 'net'
import { OAuthClientProvider } from '@modelcontextprotocol/sdk/client/auth.js'
import {
  OAuthClientInformation,
  OAuthClientInformationFull,
  OAuthClientInformationSchema,
  OAuthTokens,
  OAuthTokensSchema,
} from '@modelcontextprotocol/sdk/shared/auth.js'
import { OAuthCallbackServerOptions, OAuthProviderOptions } from '../lib/types.js'

/**
 * Implements the OAuthClientProvider interface for Node.js environments.
 * Handles OAuth flow and token storage for MCP clients.
 */
export class NodeOAuthClientProvider implements OAuthClientProvider {
  private configDir: string
  private serverUrlHash: string
  private callbackPath: string
  private clientName: string
  private clientUri: string

  /**
   * Creates a new NodeOAuthClientProvider
   * @param options Configuration options for the provider
   */
  constructor(readonly options: OAuthProviderOptions) {
    this.serverUrlHash = crypto.createHash('md5').update(options.serverUrl).digest('hex')
    this.configDir = options.configDir || path.join(os.homedir(), '.mcp-auth')
    this.callbackPath = options.callbackPath || '/oauth/callback'
    this.clientName = options.clientName || 'MCP CLI Client'
    this.clientUri = options.clientUri || 'https://github.com/modelcontextprotocol/mcp-cli'
  }

  get redirectUrl(): string {
    return `http://127.0.0.1:${this.options.callbackPort}${this.callbackPath}`
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
   * Ensures the configuration directory exists
   * @private
   */
  private async ensureConfigDir() {
    try {
      await fs.mkdir(this.configDir, { recursive: true })
    } catch (error) {
      console.error('Error creating config directory:', error)
      throw error
    }
  }

  /**
   * Reads a JSON file and parses it with the provided schema
   * @param filename The name of the file to read
   * @param schema The schema to validate against
   * @returns The parsed file content or undefined if the file doesn't exist
   * @private
   */
  private async readFile<T>(filename: string, schema: any): Promise<T | undefined> {
    try {
      await this.ensureConfigDir()
      const filePath = path.join(this.configDir, `${this.serverUrlHash}_${filename}`)
      const content = await fs.readFile(filePath, 'utf-8')
      return await schema.parseAsync(JSON.parse(content))
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
        return undefined
      }
      return undefined
    }
  }

  /**
   * Writes a JSON object to a file
   * @param filename The name of the file to write
   * @param data The data to write
   * @private
   */
  private async writeFile(filename: string, data: any) {
    try {
      await this.ensureConfigDir()
      const filePath = path.join(this.configDir, `${this.serverUrlHash}_${filename}`)
      await fs.writeFile(filePath, JSON.stringify(data, null, 2), 'utf-8')
    } catch (error) {
      console.error(`Error writing ${filename}:`, error)
      throw error
    }
  }

  /**
   * Writes a text string to a file
   * @param filename The name of the file to write
   * @param text The text to write
   * @private
   */
  private async writeTextFile(filename: string, text: string) {
    try {
      await this.ensureConfigDir()
      const filePath = path.join(this.configDir, `${this.serverUrlHash}_${filename}`)
      await fs.writeFile(filePath, text, 'utf-8')
    } catch (error) {
      console.error(`Error writing ${filename}:`, error)
      throw error
    }
  }

  /**
   * Reads text from a file
   * @param filename The name of the file to read
   * @returns The file content as a string
   * @private
   */
  private async readTextFile(filename: string): Promise<string> {
    try {
      await this.ensureConfigDir()
      const filePath = path.join(this.configDir, `${this.serverUrlHash}_${filename}`)
      return await fs.readFile(filePath, 'utf-8')
    } catch (error) {
      throw new Error('No code verifier saved for session')
    }
  }

  /**
   * Gets the client information if it exists
   * @returns The client information or undefined
   */
  async clientInformation(): Promise<OAuthClientInformation | undefined> {
    return this.readFile<OAuthClientInformation>('client_info.json', OAuthClientInformationSchema)
  }

  /**
   * Saves client information
   * @param clientInformation The client information to save
   */
  async saveClientInformation(clientInformation: OAuthClientInformationFull): Promise<void> {
    await this.writeFile('client_info.json', clientInformation)
  }

  /**
   * Gets the OAuth tokens if they exist
   * @returns The OAuth tokens or undefined
   */
  async tokens(): Promise<OAuthTokens | undefined> {
    return this.readFile<OAuthTokens>('tokens.json', OAuthTokensSchema)
  }

  /**
   * Saves OAuth tokens
   * @param tokens The tokens to save
   */
  async saveTokens(tokens: OAuthTokens): Promise<void> {
    await this.writeFile('tokens.json', tokens)
  }

  /**
   * Redirects the user to the authorization URL
   * @param authorizationUrl The URL to redirect to
   */
  async redirectToAuthorization(authorizationUrl: URL): Promise<void> {
    console.error(`\nPlease authorize this client by visiting:\n${authorizationUrl.toString()}\n`)
    try {
      await open(authorizationUrl.toString())
      console.error('Browser opened automatically.')
    } catch (error) {
      console.error('Could not open browser automatically. Please copy and paste the URL above into your browser.')
    }
  }

  /**
   * Saves the PKCE code verifier
   * @param codeVerifier The code verifier to save
   */
  async saveCodeVerifier(codeVerifier: string): Promise<void> {
    await this.writeTextFile('code_verifier.txt', codeVerifier)
  }

  /**
   * Gets the PKCE code verifier
   * @returns The code verifier
   */
  async codeVerifier(): Promise<string> {
    return await this.readTextFile('code_verifier.txt')
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
 * @returns A promise that resolves to an object with parsed serverUrl and callbackPort
 */
export async function parseCommandLineArgs(args: string[], defaultPort: number, usage: string) {
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

  return { serverUrl, callbackPort }
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

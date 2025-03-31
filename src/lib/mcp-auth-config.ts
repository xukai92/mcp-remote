import crypto from 'crypto'
import path from 'path'
import os from 'os'
import fs from 'fs/promises'

/**
 * MCP Remote Authentication Configuration
 * 
 * This module handles the storage and retrieval of authentication-related data for MCP Remote.
 * 
 * Configuration directory structure:
 * - The config directory is determined by MCP_REMOTE_CONFIG_DIR env var or defaults to ~/.mcp-auth
 * - Each file is prefixed with a hash of the server URL to separate configurations for different servers
 * 
 * Files stored in the config directory:
 * - {server_hash}_client_info.json: Contains OAuth client registration information
 *   - Format: OAuthClientInformation object with client_id and other registration details
 * - {server_hash}_tokens.json: Contains OAuth access and refresh tokens
 *   - Format: OAuthTokens object with access_token, refresh_token, and expiration information
 * - {server_hash}_code_verifier.txt: Contains the PKCE code verifier for the current OAuth flow
 *   - Format: Plain text string used for PKCE verification
 * 
 * All JSON files are stored with 2-space indentation for readability.
 */

/**
 * Known configuration file names that might need to be cleaned
 */
export const knownConfigFiles = [
  'client_info.json',
  'tokens.json',
  'code_verifier.txt',
];

/**
 * Deletes all known configuration files for a specific server
 * @param serverUrlHash The hash of the server URL
 */
export async function cleanServerConfig(serverUrlHash: string): Promise<void> {
  console.error(`Cleaning configuration files for server: ${serverUrlHash}`)
  for (const filename of knownConfigFiles) {
    await deleteConfigFile(serverUrlHash, filename)
  }
}

/**
 * Gets the configuration directory path
 * @returns The path to the configuration directory
 */
export function getConfigDir(): string {
  return process.env.MCP_REMOTE_CONFIG_DIR || path.join(os.homedir(), '.mcp-auth')
}

/**
 * Ensures the configuration directory exists
 */
export async function ensureConfigDir(): Promise<void> {
  try {
    const configDir = getConfigDir()
    await fs.mkdir(configDir, { recursive: true })
  } catch (error) {
    console.error('Error creating config directory:', error)
    throw error
  }
}

/**
 * Generates a hash for the server URL to use in filenames
 * @param serverUrl The server URL to hash
 * @returns The hashed server URL
 */
export function getServerUrlHash(serverUrl: string): string {
  return crypto.createHash('md5').update(serverUrl).digest('hex')
}

/**
 * Gets the file path for a config file
 * @param serverUrlHash The hash of the server URL
 * @param filename The name of the file
 * @returns The absolute file path
 */
export function getConfigFilePath(serverUrlHash: string, filename: string): string {
  const configDir = getConfigDir()
  return path.join(configDir, `${serverUrlHash}_${filename}`)
}

/**
 * Deletes a config file if it exists
 * @param serverUrlHash The hash of the server URL
 * @param filename The name of the file to delete
 */
export async function deleteConfigFile(serverUrlHash: string, filename: string): Promise<void> {
  try {
    const filePath = getConfigFilePath(serverUrlHash, filename)
    await fs.unlink(filePath)
  } catch (error) {
    // Ignore if file doesn't exist
    if ((error as NodeJS.ErrnoException).code !== 'ENOENT') {
      console.error(`Error deleting ${filename}:`, error)
    }
  }
}

/**
 * Reads a JSON file and parses it with the provided schema
 * @param serverUrlHash The hash of the server URL
 * @param filename The name of the file to read
 * @param schema The schema to validate against
 * @param clean Whether to clean (delete) before reading
 * @returns The parsed file content or undefined if the file doesn't exist
 */
export async function readJsonFile<T>(
  serverUrlHash: string, 
  filename: string, 
  schema: any,
  clean: boolean = false
): Promise<T | undefined> {
  try {
    await ensureConfigDir()
    
    // If clean flag is set, delete the file before trying to read it
    if (clean) {
      await deleteConfigFile(serverUrlHash, filename)
      return undefined
    }
    
    const filePath = getConfigFilePath(serverUrlHash, filename)
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
 * @param serverUrlHash The hash of the server URL
 * @param filename The name of the file to write
 * @param data The data to write
 */
export async function writeJsonFile(
  serverUrlHash: string, 
  filename: string, 
  data: any
): Promise<void> {
  try {
    await ensureConfigDir()
    const filePath = getConfigFilePath(serverUrlHash, filename)
    await fs.writeFile(filePath, JSON.stringify(data, null, 2), 'utf-8')
  } catch (error) {
    console.error(`Error writing ${filename}:`, error)
    throw error
  }
}

/**
 * Reads a text file
 * @param serverUrlHash The hash of the server URL
 * @param filename The name of the file to read
 * @param errorMessage Optional custom error message
 * @param clean Whether to clean (delete) before reading
 * @returns The file content as a string
 */
export async function readTextFile(
  serverUrlHash: string, 
  filename: string,
  errorMessage?: string,
  clean: boolean = false
): Promise<string> {
  try {
    await ensureConfigDir()
    
    // If clean flag is set, delete the file before trying to read it
    if (clean) {
      await deleteConfigFile(serverUrlHash, filename)
      throw new Error('File deleted due to clean flag')
    }
    
    const filePath = getConfigFilePath(serverUrlHash, filename)
    return await fs.readFile(filePath, 'utf-8')
  } catch (error) {
    throw new Error(errorMessage || `Error reading ${filename}`)
  }
}

/**
 * Writes a text string to a file
 * @param serverUrlHash The hash of the server URL
 * @param filename The name of the file to write
 * @param text The text to write
 */
export async function writeTextFile(
  serverUrlHash: string, 
  filename: string, 
  text: string
): Promise<void> {
  try {
    await ensureConfigDir()
    const filePath = getConfigFilePath(serverUrlHash, filename)
    await fs.writeFile(filePath, text, 'utf-8')
  } catch (error) {
    console.error(`Error writing ${filename}:`, error)
    throw error
  }
}
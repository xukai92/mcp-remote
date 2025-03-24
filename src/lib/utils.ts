import { OAuthClientProvider, UnauthorizedError } from "@modelcontextprotocol/sdk/client/auth.js";
import { SSEClientTransport } from "@modelcontextprotocol/sdk/client/sse.js";
import { Transport } from "@modelcontextprotocol/sdk/shared/transport.js";

/**
 * Creates a bidirectional proxy between two transports
 * @param params The transport connections to proxy between
 */
export function mcpProxy({transportToClient, transportToServer}: {
  transportToClient: Transport;
  transportToServer: Transport
}) {
  let transportToClientClosed = false
  let transportToServerClosed = false

  transportToClient.onmessage = (message) => {
    console.error('[Local→Remote]', message.method || message.id)
    transportToServer.send(message).catch(onServerError)
  }

  transportToServer.onmessage = (message) => {
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
  console.error('Connecting to remote server:', serverUrl)
  const url = new URL(serverUrl)
  const transport = new SSEClientTransport(url, {authProvider})

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
        const newTransport = new SSEClientTransport(url, {authProvider})
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
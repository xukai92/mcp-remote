import { Tool, JSONRPCMessage } from "@modelcontextprotocol/sdk/types.js";
import { useCallback, useEffect, useState, useRef } from "react";
import { SSEClientTransport } from "@modelcontextprotocol/sdk/client/sse.js";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { ListToolsResultSchema } from "@modelcontextprotocol/sdk/types.js";
import { discoverOAuthMetadata, startAuthorization, exchangeAuthorization } from "@modelcontextprotocol/sdk/client/auth.js";
import { OAuthClientInformation, OAuthMetadata, OAuthTokens } from "@modelcontextprotocol/sdk/shared/auth.js";

export type UseMcpOptions = {
  /** The /sse URL of your remote MCP server */
  url: string,
  /** OAuth client name for registration */
  clientName?: string,
  /** OAuth client URI for registration */
  clientUri?: string,
  /** Custom callback URL for OAuth redirect (defaults to /oauth/callback on the current origin) */
  callbackUrl?: string,
  /** Storage key prefix for OAuth data (defaults to "mcp_auth") */
  storageKeyPrefix?: string,
  /** Custom configuration for the MCP client */
  clientConfig?: {
    name?: string,
    version?: string,
  },
  /** Whether to enable debug logging */
  debug?: boolean,
  /** Auto retry connection if it fails, with delay in ms (default: false) */
  autoRetry?: boolean | number,
  /** Auto reconnect if connection is lost, with delay in ms (default: 3000) */
  autoReconnect?: boolean | number,
}

export type UseMcpResult = {
  tools: Tool[],
  /**
   * The current state of the MCP connection. This will be one of:
   * - 'discovering': Finding out whether there is in fact a server at that URL, and what its capabilities are
   * - 'authenticating': The server has indicated we must authenticate, so we can't proceed until that's complete
   * - 'connecting': The connection to the MCP server is being established. This happens before we know whether we need to authenticate or not, and then again once we have credentials
   * - 'loading': We're connected to the MCP server, and now we're loading its resources/prompts/tools
   * - 'ready': The MCP server is connected and ready to be used
   * - 'failed': The connection to the MCP server failed
   * */
  state: 'discovering' | 'authenticating' | 'connecting' | 'loading' | 'ready' | 'failed',
  /** If the state is 'failed', this will be the error message */
  error?: string,
  /** All internal log messages */
  log: {level: 'debug' | 'info' | 'warn' | 'error', message: string}[],
  /** Call a tool on the MCP server */
  callTool: (name: string, args?: Record<string, unknown>) => Promise<any>,
  /** Manually retry connection if it's in a failed state */
  retry: () => void,
  /** Manually disconnect from the MCP server */
  disconnect: () => void,
}

/**
 * Browser-compatible OAuth client provider for MCP
 */
class BrowserOAuthClientProvider {
  private storageKeyPrefix: string;
  private serverUrlHash: string;
  private clientName: string;
  private clientUri: string;
  private callbackUrl: string;

  constructor(
    readonly serverUrl: string,
    options: {
      storageKeyPrefix?: string;
      clientName?: string;
      clientUri?: string;
      callbackUrl?: string;
    } = {}
  ) {
    this.storageKeyPrefix = options.storageKeyPrefix || "mcp_auth";
    this.serverUrlHash = this.hashString(serverUrl);
    this.clientName = options.clientName || "MCP Browser Client";
    this.clientUri = options.clientUri || window.location.origin;
    this.callbackUrl = options.callbackUrl || new URL("/oauth/callback", window.location.origin).toString();
  }

  get redirectUrl(): string {
    return this.callbackUrl;
  }

  get clientMetadata() {
    return {
      redirect_uris: [this.redirectUrl],
      token_endpoint_auth_method: "none",
      grant_types: ["authorization_code", "refresh_token"],
      response_types: ["code"],
      client_name: this.clientName,
      client_uri: this.clientUri,
    };
  }

  private hashString(str: string): string {
    // Simple hash function for browser environments
    let hash = 0;
    for (let i = 0; i < str.length; i++) {
      const char = str.charCodeAt(i);
      hash = (hash << 5) - hash + char;
      hash = hash & hash; // Convert to 32bit integer
    }
    return Math.abs(hash).toString(16);
  }

  private getKey(key: string): string {
    return `${this.storageKeyPrefix}_${this.serverUrlHash}_${key}`;
  }

  async clientInformation(): Promise<OAuthClientInformation | undefined> {
    const key = this.getKey("client_info");
    const data = localStorage.getItem(key);
    if (!data) return undefined;

    try {
      return JSON.parse(data) as OAuthClientInformation;
    } catch (e) {
      return undefined;
    }
  }

  async saveClientInformation(clientInformation: OAuthClientInformation): Promise<void> {
    const key = this.getKey("client_info");
    localStorage.setItem(key, JSON.stringify(clientInformation));
  }

  async tokens(): Promise<OAuthTokens | undefined> {
    const key = this.getKey("tokens");
    const data = localStorage.getItem(key);
    if (!data) return undefined;

    try {
      return JSON.parse(data) as OAuthTokens;
    } catch (e) {
      return undefined;
    }
  }

  async saveTokens(tokens: OAuthTokens): Promise<void> {
    const key = this.getKey("tokens");
    localStorage.setItem(key, JSON.stringify(tokens));
  }

  async redirectToAuthorization(authorizationUrl: URL): Promise<void> {
    // Store the auth state for the popup flow
    const stateKey = this.getKey("auth_state");
    const state = Math.random().toString(36).substring(2);
    localStorage.setItem(stateKey, state);
    authorizationUrl.searchParams.set("state", state);

    // Open the authorization URL in a popup window
    const popup = window.open(authorizationUrl.toString(), "mcp_auth", "width=600,height=700");

    if (!popup || popup.closed) {
      console.warn("Popup blocked. Redirecting in the same window...");
      window.location.href = authorizationUrl.toString();
    }
  }

  async saveCodeVerifier(codeVerifier: string): Promise<void> {
    const key = this.getKey("code_verifier");
    localStorage.setItem(key, codeVerifier);
  }

  async codeVerifier(): Promise<string> {
    const key = this.getKey("code_verifier");
    const verifier = localStorage.getItem(key);
    if (!verifier) {
      throw new Error("No code verifier found in storage");
    }
    return verifier;
  }
}

/**
 * useMcp is a React hook that connects to a remote MCP server, negotiates auth
 * (including opening a popup window or new tab to complete the OAuth flow),
 * and enables passing a list of tools (once loaded) to ai-sdk (using `useChat`).
 */
export function useMcp(options: UseMcpOptions): UseMcpResult {
  const [state, setState] = useState<UseMcpResult['state']>('discovering');
  const [tools, setTools] = useState<Tool[]>([]);
  const [error, setError] = useState<string | undefined>(undefined);
  const [log, setLog] = useState<UseMcpResult['log']>([]);

  const clientRef = useRef<Client | null>(null);
  const transportRef = useRef<SSEClientTransport | null>(null);
  const authProviderRef = useRef<BrowserOAuthClientProvider | null>(null);
  const metadataRef = useRef<OAuthMetadata | undefined>(undefined);
  const connectingRef = useRef<boolean>(false);
  const isInitialMount = useRef<boolean>(true);

  // Set up default options
  const {
    url,
    clientName = "MCP React Client",
    clientUri = window.location.origin,
    callbackUrl = new URL("/oauth/callback", window.location.origin).toString(),
    storageKeyPrefix = "mcp_auth",
    clientConfig = {
      name: "mcp-react-client",
      version: "0.1.0",
    },
    debug = false,
    autoRetry = false,
    autoReconnect = 3000,
  } = options;

  // Add to log
  const addLog = useCallback((level: 'debug' | 'info' | 'warn' | 'error', message: string) => {
    if (level === 'debug' && !debug) return;
    setLog(prevLog => [...prevLog, { level, message }]);
  }, [debug]);

  // Call a tool on the MCP server
  const callTool = useCallback(async (name: string, args?: Record<string, unknown>) => {
    if (!clientRef.current || state !== 'ready') {
      throw new Error("MCP client not ready");
    }

    try {
      const result = await clientRef.current.request(
        {
          method: "tools/call",
          params: { name, arguments: args },
        }
      );
      return result;
    } catch (err) {
      addLog('error', `Error calling tool ${name}: ${err instanceof Error ? err.message : String(err)}`);
      throw err;
    }
  }, [state, addLog]);

  // Disconnect from the MCP server
  const disconnect = useCallback(async () => {
    if (clientRef.current) {
      try {
        await clientRef.current.close();
      } catch (err) {
        addLog('error', `Error closing client: ${err instanceof Error ? err.message : String(err)}`);
      }
      clientRef.current = null;
    }

    if (transportRef.current) {
      try {
        await transportRef.current.close();
      } catch (err) {
        addLog('error', `Error closing transport: ${err instanceof Error ? err.message : String(err)}`);
      }
      transportRef.current = null;
    }

    connectingRef.current = false;
    setState('discovering');
    setTools([]);
    setError(undefined);
  }, [addLog]);
  let handleAuthentication: () => Promise<string>;

  // Initialize connection to MCP server
  const connect = useCallback(async () => {
    // Prevent multiple simultaneous connection attempts
    if (connectingRef.current) return;
    connectingRef.current = true;

    try {
      setState('discovering');
      setError(undefined);

      // Create auth provider if not already created
      if (!authProviderRef.current) {
        authProviderRef.current = new BrowserOAuthClientProvider(url, {
          storageKeyPrefix,
          clientName,
          clientUri,
          callbackUrl,
        });
      }

      // Discover OAuth metadata if not already discovered
      if (!metadataRef.current) {
        addLog('info', 'Discovering OAuth metadata...');
        metadataRef.current = await discoverOAuthMetadata(url);
        addLog('debug', `OAuth metadata: ${metadataRef.current ? 'Found' : 'Not available'}`);
      }

      // Create MCP client
      clientRef.current = new Client(
        {
          name: clientConfig.name || "mcp-react-client",
          version: clientConfig.version || "0.1.0",
        },
        {
          capabilities: {
            sampling: {},
          },
        }
      );

      // Set up auth flow - check if we have tokens
      const tokens = await authProviderRef.current.tokens();

      // Create SSE transport
      setState('connecting');
      addLog('info', 'Creating transport...');

      const serverUrl = new URL(url);
      transportRef.current = new SSEClientTransport(serverUrl, {
        authProvider: authProviderRef.current
      });

      // Set up transport handlers
      transportRef.current.onmessage = (message: JSONRPCMessage) => {
        addLog('debug', `Received message: ${message.method || message.id}`);
      };

      transportRef.current.onerror = (err: Error) => {
        addLog('error', `Transport error: ${err.message}`);

        if (err.message.includes('Unauthorized')) {
          setState('authenticating');
          handleAuthentication().catch(authErr => {
            addLog('error', `Authentication error: ${authErr.message}`);
            setState('failed');
            setError(`Authentication failed: ${authErr.message}`);
            connectingRef.current = false;
          });
        } else {
          setState('failed');
          setError(`Connection error: ${err.message}`);
          connectingRef.current = false;
        }
      };

      transportRef.current.onclose = () => {
        addLog('info', 'Connection closed');
        // If we were previously connected, try to reconnect
        if (state === 'ready' && autoReconnect) {
          const delay = typeof autoReconnect === 'number' ? autoReconnect : 3000;
          addLog('info', `Will reconnect in ${delay}ms...`);
          setTimeout(() => {
            disconnect().then(() => connect());
          }, delay);
        }
      };

      // Connect transport
      try {
        addLog('info', 'Starting transport...');
        await transportRef.current.start();
      } catch (err) {
        addLog('error', `Transport start error: ${err instanceof Error ? err.message : String(err)}`);

        if (err instanceof Error && err.message.includes('Unauthorized')) {
          setState('authenticating');
          // Start authentication process
          await handleAuthentication();
          // After successful auth, retry connection
          return connect();
        } else {
          setState('failed');
          setError(`Connection error: ${err instanceof Error ? err.message : String(err)}`);
          connectingRef.current = false;
          return;
        }
      }

      // Connect client
      try {
        addLog('info', 'Connecting client...');
        setState('loading');
        await clientRef.current.connect(transportRef.current);
        addLog('info', 'Client connected');

        // Load tools
        try {
          addLog('info', 'Loading tools...');
          const toolsResponse = await clientRef.current.request(
            { method: "tools/list" },
            ListToolsResultSchema
          );
          setTools(toolsResponse.tools);
          addLog('info', `Loaded ${toolsResponse.tools.length} tools`);

          // Connection completed successfully
          setState('ready');
          connectingRef.current = false;
        } catch (toolErr) {
          addLog('error', `Error loading tools: ${toolErr instanceof Error ? toolErr.message : String(toolErr)}`);
          // We're still connected, just couldn't load tools
          setState('ready');
          connectingRef.current = false;
        }
      } catch (connectErr) {
        addLog('error', `Client connect error: ${connectErr instanceof Error ? connectErr.message : String(connectErr)}`);
        setState('failed');
        setError(`Connection error: ${connectErr instanceof Error ? connectErr.message : String(connectErr)}`);
        connectingRef.current = false;
      }
    } catch (err) {
      addLog('error', `Unexpected error: ${err instanceof Error ? err.message : String(err)}`);
      setState('failed');
      setError(`Unexpected error: ${err instanceof Error ? err.message : String(err)}`);
      connectingRef.current = false;
    }
  }, [url, clientName, clientUri, callbackUrl, storageKeyPrefix, clientConfig, debug, autoReconnect, addLog, handleAuthentication, disconnect]);

  // Handle authentication flow
  handleAuthentication = useCallback(async () => {
    if (!authProviderRef.current || !metadataRef.current) {
      throw new Error("Auth provider or metadata not available");
    }

    addLog('info', 'Starting authentication flow...');

    // Check if we have client info
    let clientInfo = await authProviderRef.current.clientInformation();

    if (!clientInfo) {
      // Register client dynamically
      addLog('info', 'No client information found, registering...');
      // Note: In a complete implementation, you'd register the client here
      // This would be done server-side in a real application
      throw new Error("Dynamic client registration not implemented in this example");
    }

    // Start authorization flow
    addLog('info', 'Starting authorization...');
    const {authorizationUrl, codeVerifier} = await startAuthorization(url, {
      metadata: metadataRef.current,
      clientInformation: clientInfo,
      redirectUrl: authProviderRef.current.redirectUrl
    });

    // Save code verifier
    await authProviderRef.current.saveCodeVerifier(codeVerifier);

    // Set up listener for post-auth message
    const authPromise = new Promise<string>((resolve, reject) => {
      const timeoutId = setTimeout(() => {
        window.removeEventListener('message', messageHandler);
        reject(new Error("Authentication timeout after 5 minutes"));
      }, 5 * 60 * 1000);

      const messageHandler = (event: MessageEvent) => {
        // Verify origin for security
        if (event.origin !== window.location.origin) return;

        if (event.data && event.data.type === 'mcp_auth_callback' && event.data.code) {
          window.removeEventListener('message', messageHandler);
          clearTimeout(timeoutId);
          resolve(event.data.code);
        }
      };

      window.addEventListener('message', messageHandler);
    });

    // Redirect to authorization
    await authProviderRef.current.redirectToAuthorization(authorizationUrl);

    // Wait for auth to complete
    addLog('info', 'Waiting for authorization...');
    const code = await authPromise;
    addLog('info', 'Authorization code received');

    return code;
  }, [url, addLog]);

  // Handle auth completion - this is called when we receive a message from the popup
  const handleAuthCompletion = useCallback(async (code: string) => {
    if (!authProviderRef.current || !transportRef.current || !metadataRef.current) {
      throw new Error("Authentication context not available");
    }

    try {
      addLog('info', 'Finishing authorization...');
      await transportRef.current.finishAuth(code);
      addLog('info', 'Authorization completed');

      // Reconnect with the new auth token
      await disconnect();
      connect();
    } catch (err) {
      addLog('error', `Auth completion error: ${err instanceof Error ? err.message : String(err)}`);
      setState('failed');
      setError(`Authentication failed: ${err instanceof Error ? err.message : String(err)}`);
    }
  }, [addLog, disconnect, connect]);

  // Retry connection
  const retry = useCallback(() => {
    if (state === 'failed') {
      disconnect().then(() => connect());
    }
  }, [state, disconnect, connect]);

  // Set up message listener for auth callback
  useEffect(() => {
    const messageHandler = (event: MessageEvent) => {
      // Verify origin for security
      if (event.origin !== window.location.origin) return;

      if (event.data && event.data.type === 'mcp_auth_callback' && event.data.code) {
        handleAuthCompletion(event.data.code).catch(err => {
          addLog('error', `Auth callback error: ${err.message}`);
        });
      }
    };

    window.addEventListener('message', messageHandler);
    return () => {
      window.removeEventListener('message', messageHandler);
    };
  }, [handleAuthCompletion, addLog]);

  // Initial connection and auto-retry
  useEffect(() => {
    if (isInitialMount.current) {
      isInitialMount.current = false;
      connect();
    } else if (state === 'failed' && autoRetry) {
      const delay = typeof autoRetry === 'number' ? autoRetry : 5000;
      const timeoutId = setTimeout(() => {
        addLog('info', 'Auto-retrying connection...');
        disconnect().then(() => connect());
      }, delay);

      return () => {
        clearTimeout(timeoutId);
      };
    }
  }, [state, autoRetry, connect, disconnect, addLog]);

  // Clean up on unmount
  useEffect(() => {
    return () => {
      if (clientRef.current || transportRef.current) {
        disconnect();
      }
    };
  }, [disconnect]);

  return {
    state,
    tools,
    error,
    log,
    callTool,
    retry,
    disconnect
  };
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
export async function onMcpAuthorization(query: Record<string, string>) {
  try {
    // Extract the authorization code and state
    const code = query.code;
    const state = query.state;

    if (!code) {
      throw new Error("No authorization code received");
    }

    if (!state) {
      throw new Error("No state parameter received");
    }

    // Find the matching auth state in localStorage
    const storageKeys = Object.keys(localStorage).filter(key =>
      key.includes('_auth_state') && localStorage.getItem(key) === state
    );

    if (storageKeys.length === 0) {
      throw new Error("No matching auth state found in storage");
    }

    const storageKey = storageKeys[0];
    const keyParts = storageKey.split('_');
    const serverUrlHash = keyParts[1];
    const storageKeyPrefix = keyParts[0];

    // Find all related auth data with the same prefix and server hash
    const clientInfoKey = `${storageKeyPrefix}_${serverUrlHash}_client_info`;
    const codeVerifierKey = `${storageKeyPrefix}_${serverUrlHash}_code_verifier`;

    const clientInfoStr = localStorage.getItem(clientInfoKey);
    const codeVerifier = localStorage.getItem(codeVerifierKey);

    if (!clientInfoStr) {
      throw new Error("No client information found in storage");
    }

    if (!codeVerifier) {
      throw new Error("No code verifier found in storage");
    }

    // Parse client info
    const clientInfo = JSON.parse(clientInfoStr) as OAuthClientInformation;

    // Find the server URL from other keys in localStorage
    const serverUrlKeys = Object.keys(localStorage).filter(key =>
      key.startsWith(`${storageKeyPrefix}_server_`) && key.includes(serverUrlHash)
    );

    let serverUrl: string;
    if (serverUrlKeys.length > 0) {
      serverUrl = localStorage.getItem(serverUrlKeys[0]) || '';
    } else {
      // If we can't find the server URL, try to construct it from the current URL
      // This is a fallback and may not always work
      const currentUrl = new URL(window.location.href);
      serverUrl = `${currentUrl.protocol}//${currentUrl.host}`;
    }

    if (!serverUrl) {
      throw new Error("Could not determine server URL");
    }

    // Exchange the code for tokens
    const metadata = await discoverOAuthMetadata(serverUrl);

    const tokens = await exchangeAuthorization(serverUrl, {
      metadata,
      clientInformation: clientInfo,
      authorizationCode: code,
      codeVerifier,
    });

    // Save the tokens
    const tokensKey = `${storageKeyPrefix}_${serverUrlHash}_tokens`;
    localStorage.setItem(tokensKey, JSON.stringify(tokens));

    // Post message back to the parent window
    if (window.opener && !window.opener.closed) {
      window.opener.postMessage({
        type: 'mcp_auth_callback',
        code
      }, window.location.origin);
      // Close the popup
      window.close();
    } else {
      // If no parent window, we're in a redirect flow
      // Redirect back to the main page
      window.location.href = '/';
    }

    return { success: true };
  } catch (error) {
    console.error('Error in MCP authorization:', error);

    // Create a readable error message for display
    const errorMessage = error instanceof Error ? error.message : String(error);

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
    `;

    document.body.innerHTML = errorHtml;

    return { success: false, error: errorMessage };
  }
}
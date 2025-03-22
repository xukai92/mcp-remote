import { Tool } from "@modelcontextprotocol/sdk/types.js";
import { useCallback, useState } from "react";

export type UseMcpOptions = {
  /** The /sse URL of your remote MCP server */
  url: string,

  // more options here as I think of them
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

  // more as i think of them
}

/**
 * useMcp is a React hook that connects to a remote MCP server, negotiates auth
 * (including opening a popup window or new tab to complete the OAuth flow),
 * and enables passing a list of tools (once loaded) to ai-sdk (using `useChat`).
 *
 * The authorization flow
 */
export function useMcp(
  options: UseMcpOptions
):UseMcpResult {
  // TODO: implement hook
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
  // TODO: implement
}
/**
 * AVERION provider-host write gates. Upstream Postiz leaves every flag unset,
 * which keeps the existing product behavior. The provider host sets them.
 */

export const MCP_WRITE_TOOL_NAMES = [
  'uploadFromUrlTool',
  'generateImageTool',
  'triggerTool',
  'generateVideoTool',
  'uploadWidgetTicketTool',
  'postSettingsTool',
  'schedulePostTool',
  'integrationSchedulePostTool',
  'uploadWidgetTool',
  'clippingWidgetTicketTool',
  'clippingTool',
] as const;

const writeToolNames = new Set<string>(MCP_WRITE_TOOL_NAMES);

export function envFlag(name: string): boolean {
  const value = (process.env[name] || '').trim().toLowerCase();
  return value === '1' || value === 'true' || value === 'yes';
}

export function mcpWriteAllowed(): boolean {
  return !envFlag('MCP_WRITE_DISABLED');
}

export function filterMcpWriteTools<T extends Record<string, unknown>>(
  tools: T
): T {
  if (mcpWriteAllowed()) {
    return tools;
  }

  return Object.fromEntries(
    Object.entries(tools).filter(([name]) => !writeToolNames.has(name))
  ) as T;
}

export function mcpScopes(scopes: string[]): string[] {
  if (mcpWriteAllowed()) {
    return scopes;
  }
  return scopes.filter((scope) => scope !== 'mcp:write');
}

export function publicApiWriteAllowed(): boolean {
  return !envFlag('PUBLIC_API_WRITE_DISABLED');
}

export function publicApiWriteDecision(
  method: string,
  authenticated: boolean
): 'ok' | 'unauthorized' | 'forbidden' {
  const write = !['GET', 'HEAD', 'OPTIONS'].includes(method.toUpperCase());
  if (!write || publicApiWriteAllowed()) {
    return authenticated || !write ? 'ok' : 'unauthorized';
  }
  return authenticated ? 'forbidden' : 'unauthorized';
}

export function exposeOrgApiKeyToUsers(): boolean {
  return (process.env.ORG_API_KEY_BROWSER_EXPOSURE || '').trim().toLowerCase() !==
    'false';
}

/**
 * Direct autonomy (RSS autopost that publishes without a person) stays off
 * unless a real OpenAI key is set AND AUTOPOST_ENABLED=true.
 * An empty key, or the historical placeholder, is not autonomy.
 */
export function directAiAutonomyEnabled(): boolean {
  const key = (process.env.OPENAI_API_KEY || '').trim();
  if (!key || key === 'sk-proj-') {
    return false;
  }
  return envFlag('AUTOPOST_ENABLED');
}

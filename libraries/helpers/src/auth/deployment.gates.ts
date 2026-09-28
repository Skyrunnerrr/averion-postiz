/**
 * AVERION provider-host write gates.
 * Flags left unset keep upstream Postiz behavior. Autopost is included:
 * without AVERION_PROVIDER_PROFILE and without TOKEN_ENCRYPTION_REQUIRED,
 * directAiAutonomyEnabled() is true and AUTOPOST_ENABLED is not consulted,
 * so an active autopost starts the same way it did upstream. OPENAI_API_KEY
 * alone is enough; an empty key does not block the cron.
 * When either of those host flags is set, autopost stays off unless
 * AUTOPOST_ENABLED=true and OPENAI_API_KEY is a real key. The placeholder
 * sk-proj- does not count as a key.
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

export function averionHostProfile(): boolean {
  return (
    envFlag('AVERION_PROVIDER_PROFILE') || envFlag('TOKEN_ENCRYPTION_REQUIRED')
  );
}

/**
 * Upstream (no AVERION host flag): always allowed, matching the previous
 * autopost cron which started whenever the autopost was active.
 * AVERION host: real OPENAI_API_KEY and AUTOPOST_ENABLED are both required.
 */
export function directAiAutonomyEnabled(): boolean {
  if (!averionHostProfile()) {
    return true;
  }

  const key = (process.env.OPENAI_API_KEY || '').trim();
  if (!key || key === 'sk-proj-') {
    return false;
  }
  return envFlag('AUTOPOST_ENABLED');
}

import {
  directAiAutonomyEnabled,
  exposeOrgApiKeyToUsers,
  filterMcpWriteTools,
  mcpScopes,
  mcpWriteAllowed,
  publicApiWriteDecision,
} from './deployment.gates';

describe('AVERION deployment write gates', () => {
  const previous = {
    MCP_WRITE_DISABLED: process.env.MCP_WRITE_DISABLED,
    PUBLIC_API_WRITE_DISABLED: process.env.PUBLIC_API_WRITE_DISABLED,
    ORG_API_KEY_BROWSER_EXPOSURE: process.env.ORG_API_KEY_BROWSER_EXPOSURE,
    OPENAI_API_KEY: process.env.OPENAI_API_KEY,
    AUTOPOST_ENABLED: process.env.AUTOPOST_ENABLED,
  };

  afterEach(() => {
    for (const [key, value] of Object.entries(previous)) {
      if (value === undefined) {
        delete process.env[key];
      } else {
        process.env[key] = value;
      }
    }
  });

  it('removes MCP write tools and the write scope when MCP writes are disabled', () => {
    process.env.MCP_WRITE_DISABLED = 'true';
    expect(mcpWriteAllowed()).toBe(false);

    const tools = filterMcpWriteTools({
      integrationList: { read: true },
      integrationSchedulePostTool: { write: true },
      schedulePostTool: { write: true },
      triggerTool: { write: true },
      postsListTool: { read: true },
    });

    expect(tools).toEqual({
      integrationList: { read: true },
      postsListTool: { read: true },
    });
    expect(mcpScopes(['openid', 'mcp:read', 'mcp:write'])).toEqual([
      'openid',
      'mcp:read',
    ]);
  });

  it('refuses public API writes for anonymous and authenticated callers when the gate is on', () => {
    process.env.PUBLIC_API_WRITE_DISABLED = 'true';
    expect(publicApiWriteDecision('POST', false)).toBe('unauthorized');
    expect(publicApiWriteDecision('POST', true)).toBe('forbidden');
    expect(publicApiWriteDecision('GET', true)).toBe('ok');
    expect(publicApiWriteDecision('GET', false)).toBe('ok');
  });

  it('hides the org API key and keeps direct AI autonomy off by default', () => {
    process.env.ORG_API_KEY_BROWSER_EXPOSURE = 'false';
    delete process.env.OPENAI_API_KEY;
    delete process.env.AUTOPOST_ENABLED;

    expect(exposeOrgApiKeyToUsers()).toBe(false);
    expect(directAiAutonomyEnabled()).toBe(false);

    process.env.OPENAI_API_KEY = 'sk-proj-';
    expect(directAiAutonomyEnabled()).toBe(false);

    process.env.OPENAI_API_KEY = 'sk-real';
    expect(directAiAutonomyEnabled()).toBe(false);

    process.env.AUTOPOST_ENABLED = 'true';
    expect(directAiAutonomyEnabled()).toBe(true);
  });
});

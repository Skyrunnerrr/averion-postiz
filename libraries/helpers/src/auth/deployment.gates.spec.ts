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
    TOKEN_ENCRYPTION_REQUIRED: process.env.TOKEN_ENCRYPTION_REQUIRED,
    AVERION_PROVIDER_PROFILE: process.env.AVERION_PROVIDER_PROFILE,
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

  it('hides the org API key when browser exposure is turned off', () => {
    process.env.ORG_API_KEY_BROWSER_EXPOSURE = 'false';
    expect(exposeOrgApiKeyToUsers()).toBe(false);
  });

  it('lets a real OpenAI key drive autopost when no AVERION profile is set', () => {
    delete process.env.TOKEN_ENCRYPTION_REQUIRED;
    delete process.env.AVERION_PROVIDER_PROFILE;
    delete process.env.AUTOPOST_ENABLED;
    delete process.env.OPENAI_API_KEY;

    expect(directAiAutonomyEnabled()).toBe(true);

    process.env.OPENAI_API_KEY = 'sk-real';
    expect(directAiAutonomyEnabled()).toBe(true);
  });

  it('requires AUTOPOST_ENABLED and a real key only on an AVERION host', () => {
    delete process.env.AUTOPOST_ENABLED;
    process.env.TOKEN_ENCRYPTION_REQUIRED = 'true';
    process.env.OPENAI_API_KEY = 'sk-real';
    expect(directAiAutonomyEnabled()).toBe(false);

    process.env.OPENAI_API_KEY = 'sk-proj-';
    process.env.AUTOPOST_ENABLED = 'true';
    expect(directAiAutonomyEnabled()).toBe(false);

    process.env.OPENAI_API_KEY = 'sk-real';
    expect(directAiAutonomyEnabled()).toBe(true);

    delete process.env.TOKEN_ENCRYPTION_REQUIRED;
    delete process.env.AUTOPOST_ENABLED;
    process.env.AVERION_PROVIDER_PROFILE = 'true';
    process.env.OPENAI_API_KEY = 'sk-real';
    expect(directAiAutonomyEnabled()).toBe(false);
  });
});

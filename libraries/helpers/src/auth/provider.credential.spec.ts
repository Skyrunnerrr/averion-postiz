import {
  assertRedisPayloadHasNoCredential,
  assertTokenEncryptionConfigured,
  CredentialAuthError,
  openCredential,
  PlaintextCredentialError,
  redactAuthDetailsForWorkflow,
  redactIntegrationRecord,
  redactPostForWorkflow,
  scrubProviderSecrets,
  sealCredential,
  TokenEncryptionConfigurationError,
  withProviderSecrets,
  WORKFLOW_HELD_CREDENTIAL,
} from './provider.credential';

const PLAIN = 'IGQVJ-averion-original-token-9f3a';
const REFRESH = 'IGQVJ-averion-original-refresh-9f3a';

function useKey(required = true) {
  process.env.TOKEN_ENCRYPTION_KEY = Buffer.alloc(32, 7).toString('base64');
  process.env.TOKEN_ENCRYPTION_REQUIRED = required ? 'true' : '';
}

describe('provider credential envelope', () => {
  const previousKey = process.env.TOKEN_ENCRYPTION_KEY;
  const previousRequired = process.env.TOKEN_ENCRYPTION_REQUIRED;

  afterEach(() => {
    if (previousKey === undefined) {
      delete process.env.TOKEN_ENCRYPTION_KEY;
    } else {
      process.env.TOKEN_ENCRYPTION_KEY = previousKey;
    }
    if (previousRequired === undefined) {
      delete process.env.TOKEN_ENCRYPTION_REQUIRED;
    } else {
      process.env.TOKEN_ENCRYPTION_REQUIRED = previousRequired;
    }
  });

  it('stores no original token and opens it only with the same key and field', () => {
    useKey();
    const stored = sealCredential(PLAIN, 'token');
    const storedRefresh = sealCredential(REFRESH, 'refreshToken');

    expect(stored).not.toContain(PLAIN);
    expect(storedRefresh).not.toContain(REFRESH);
    expect(stored.startsWith('pzce1.')).toBe(true);
    expect(openCredential(stored, 'token')).toBe(PLAIN);
    expect(openCredential(storedRefresh, 'refreshToken')).toBe(REFRESH);
  });

  it('produces different ciphertext for the same plaintext', () => {
    useKey();
    expect(sealCredential(PLAIN, 'token')).not.toBe(sealCredential(PLAIN, 'token'));
  });

  it('fails closed on a plaintext credential when encryption is required', () => {
    useKey();
    expect(() => openCredential(PLAIN, 'token')).toThrow(PlaintextCredentialError);
  });

  it('fails authentication for the wrong key, a swapped field, and a tampered tag', () => {
    useKey();
    const stored = sealCredential(PLAIN, 'token');

    process.env.TOKEN_ENCRYPTION_KEY = Buffer.alloc(32, 9).toString('base64');
    expect(() => openCredential(stored, 'token')).toThrow(CredentialAuthError);

    useKey();
    expect(() => openCredential(stored, 'refreshToken')).toThrow(CredentialAuthError);

    const parts = stored.split('.');
    const tag = Buffer.from(parts[4], 'base64url');
    tag[0] ^= 0xff;
    parts[4] = tag.toString('base64url');
    expect(() => openCredential(parts.join('.'), 'token')).toThrow(
      CredentialAuthError
    );
  });

  it('fails boot when encryption is required and the key is missing', () => {
    delete process.env.TOKEN_ENCRYPTION_KEY;
    process.env.TOKEN_ENCRYPTION_REQUIRED = 'true';
    expect(() => assertTokenEncryptionConfigured()).toThrow(
      TokenEncryptionConfigurationError
    );
  });

  it('keeps workflow, exception, and cache payloads free of the original token', async () => {
    useKey();
    const stored = sealCredential(PLAIN, 'token');
    const integration = redactIntegrationRecord({
      id: 'int-1',
      token: stored,
      refreshToken: sealCredential(REFRESH, 'refreshToken'),
      name: 'channel',
    });
    const post = redactPostForWorkflow({
      id: 'post-1',
      integration: { id: 'int-1', token: PLAIN, refreshToken: REFRESH },
    });
    const refresh = redactAuthDetailsForWorkflow({
      id: 'user',
      accessToken: PLAIN,
      refreshToken: REFRESH,
    });

    const scrubbed = await withProviderSecrets([PLAIN, REFRESH], async () =>
      scrubProviderSecrets(
        `graph error access_token=${PLAIN} body ${PLAIN} refresh_token=${REFRESH} ${stored}`
      )
    );

    const history = JSON.stringify({ integration, post, refresh, scrubbed });
    expect(history).not.toContain(PLAIN);
    expect(history).not.toContain(REFRESH);
    expect(history).not.toContain(stored);
    expect(scrubbed).not.toContain(PLAIN);
    expect(refresh.accessToken).toBe(WORKFLOW_HELD_CREDENTIAL);
    expect(integration.token).toBe('');
    expect(post.integration.token).toBe('');

    expect(() =>
      assertRedisPayloadHasNoCredential(JSON.stringify({ clicks: 3, views: 10 }))
    ).not.toThrow();
    expect(() => assertRedisPayloadHasNoCredential(stored)).toThrow(
      /provider credential/
    );
    expect(() =>
      assertRedisPayloadHasNoCredential(`{"accessToken":"${PLAIN}"}`)
    ).toThrow(/provider credential/);
  });
});

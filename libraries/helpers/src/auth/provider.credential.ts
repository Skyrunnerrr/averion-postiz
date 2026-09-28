import { AsyncLocalStorage } from 'async_hooks';
import crypto from 'crypto';

/**
 * Application-level envelope for Integration.token and Integration.refreshToken.
 *
 * pzce1.<keyId>.<nonce>.<ciphertext>.<tag>
 * - keyId: first 6 bytes of SHA-256(key), base64url
 * - nonce: 12 random bytes, base64url
 * - ciphertext: AES-256-GCM, base64url
 * - tag: 16-byte GCM tag, base64url
 * AAD is `pzce1:<field>` so a token ciphertext cannot be reused as a refresh token.
 * The key never leaves process env. Ciphertext is not a usable provider token.
 */
const ENVELOPE_PREFIX = 'pzce1';
const KEY_BYTES = 32;
const NONCE_BYTES = 12;
const TAG_BYTES = 16;
const KEY_ID_BYTES = 6;

export type CredentialField = 'token' | 'refreshToken';

export class TokenEncryptionConfigurationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'TokenEncryptionConfigurationError';
  }
}

export class PlaintextCredentialError extends Error {
  constructor() {
    super('Plaintext provider credential refused');
    this.name = 'PlaintextCredentialError';
  }
}

export class CredentialAuthError extends Error {
  constructor() {
    super('Provider credential failed authentication');
    this.name = 'CredentialAuthError';
  }
}

const providerSecrets = new AsyncLocalStorage<string[]>();

export function tokenEncryptionRequired(): boolean {
  const value = (process.env.TOKEN_ENCRYPTION_REQUIRED || '').trim().toLowerCase();
  return value === '1' || value === 'true' || value === 'yes';
}

export function readTokenEncryptionKey(): Buffer | null {
  const raw = (process.env.TOKEN_ENCRYPTION_KEY || '').trim();
  if (!raw) {
    return null;
  }

  const key = /^[0-9a-fA-F]{64}$/.test(raw)
    ? Buffer.from(raw, 'hex')
    : Buffer.from(raw, 'base64');

  if (key.length !== KEY_BYTES) {
    throw new TokenEncryptionConfigurationError(
      'TOKEN_ENCRYPTION_KEY must decode to 32 bytes'
    );
  }

  return key;
}

export function assertTokenEncryptionConfigured(): void {
  const required = tokenEncryptionRequired();
  const present = !!(process.env.TOKEN_ENCRYPTION_KEY || '').trim();

  if (required && !present) {
    throw new TokenEncryptionConfigurationError(
      'TOKEN_ENCRYPTION_REQUIRED is set but TOKEN_ENCRYPTION_KEY is missing'
    );
  }

  if (present) {
    readTokenEncryptionKey();
  }
}

export function isCredentialEnvelope(value: string): boolean {
  return typeof value === 'string' && value.startsWith(`${ENVELOPE_PREFIX}.`);
}

function aadFor(field: CredentialField): Buffer {
  return Buffer.from(`${ENVELOPE_PREFIX}:${field}`, 'utf8');
}

function keyId(key: Buffer): Buffer {
  return crypto.createHash('sha256').update(key).digest().subarray(0, KEY_ID_BYTES);
}

export function sealCredential(plaintext: string, field: CredentialField): string {
  if (!plaintext) {
    return plaintext;
  }

  if (isCredentialEnvelope(plaintext)) {
    return plaintext;
  }

  const key = readTokenEncryptionKey();
  if (!key) {
    if (tokenEncryptionRequired()) {
      throw new TokenEncryptionConfigurationError(
        'TOKEN_ENCRYPTION_REQUIRED is set but TOKEN_ENCRYPTION_KEY is missing'
      );
    }
    return plaintext;
  }

  const nonce = crypto.randomBytes(NONCE_BYTES);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, nonce);
  cipher.setAAD(aadFor(field));
  const ciphertext = Buffer.concat([
    cipher.update(plaintext, 'utf8'),
    cipher.final(),
  ]);
  const tag = cipher.getAuthTag();

  return [
    ENVELOPE_PREFIX,
    keyId(key).toString('base64url'),
    nonce.toString('base64url'),
    ciphertext.toString('base64url'),
    tag.toString('base64url'),
  ].join('.');
}

export function openCredential(stored: string, field: CredentialField): string {
  if (!stored) {
    return stored;
  }

  if (!isCredentialEnvelope(stored)) {
    if (tokenEncryptionRequired()) {
      throw new PlaintextCredentialError();
    }
    return stored;
  }

  const key = readTokenEncryptionKey();
  if (!key) {
    throw new TokenEncryptionConfigurationError(
      'Encrypted provider credential found but TOKEN_ENCRYPTION_KEY is missing'
    );
  }

  const parts = stored.split('.');
  if (parts.length !== 5 || parts[0] !== ENVELOPE_PREFIX) {
    throw new CredentialAuthError();
  }

  const keyIdBytes = Buffer.from(parts[1], 'base64url');
  const nonce = Buffer.from(parts[2], 'base64url');
  const ciphertext = Buffer.from(parts[3], 'base64url');
  const tag = Buffer.from(parts[4], 'base64url');
  const expectedKeyId = keyId(key);

  if (
    keyIdBytes.length !== expectedKeyId.length ||
    nonce.length !== NONCE_BYTES ||
    tag.length !== TAG_BYTES ||
    !crypto.timingSafeEqual(keyIdBytes, expectedKeyId)
  ) {
    throw new CredentialAuthError();
  }

  try {
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, nonce);
    decipher.setAAD(aadFor(field));
    decipher.setAuthTag(tag);
    return Buffer.concat([
      decipher.update(ciphertext),
      decipher.final(),
    ]).toString('utf8');
  } catch (err) {
    throw new CredentialAuthError();
  }
}

export function openIntegrationForProviderCall<
  T extends { token?: string | null; refreshToken?: string | null }
>(integration: T): T {
  return {
    ...integration,
    token: openCredential(integration.token || '', 'token'),
    refreshToken: integration.refreshToken
      ? openCredential(integration.refreshToken, 'refreshToken')
      : integration.refreshToken,
  };
}

export function withProviderSecrets<T>(
  secrets: Array<string | null | undefined>,
  fn: () => Promise<T>
): Promise<T> {
  const parent = providerSecrets.getStore() || [];
  const next = parent.concat(
    secrets.filter((secret): secret is string => !!secret && secret.length >= 12)
  );
  return providerSecrets.run(next, fn);
}

export function scrubProviderSecrets(
  value: string,
  extraSecrets: Array<string | null | undefined> = []
): string {
  if (!value) {
    return value;
  }

  let out = value
    .replace(/access_token=([^&\s"'<>]+)/gi, 'access_token=[redacted]')
    .replace(/refresh_token=([^&\s"'<>]+)/gi, 'refresh_token=[redacted]')
    .replace(
      /("(?:access_token|refresh_token|accessToken|refreshToken)"\s*:\s*")([^"]+)(")/gi,
      '$1[redacted]$3'
    )
    .replace(/(Bearer\s+)[A-Za-z0-9._\-+/=]{12,}/gi, '$1[redacted]')
    .replace(/pzce1\.[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+){3}/g, '[redacted-credential]');

  const secrets = (providerSecrets.getStore() || []).concat(
    extraSecrets.filter((secret): secret is string => !!secret && secret.length >= 12)
  );
  for (const secret of secrets) {
    if (secret && out.includes(secret)) {
      out = out.split(secret).join('[redacted]');
    }
  }

  return out;
}

export function assertRedisPayloadHasNoCredential(payload: string): void {
  if (!payload) {
    return;
  }

  if (
    payload.includes(`${ENVELOPE_PREFIX}.`) ||
    /access_token=/i.test(payload) ||
    /refresh_token=/i.test(payload) ||
    /"(?:accessToken|refreshToken|access_token|refresh_token)"\s*:/i.test(payload)
  ) {
    throw new Error('Refusing to cache a provider credential');
  }

  const secrets = providerSecrets.getStore() || [];
  for (const secret of secrets) {
    if (secret && payload.includes(secret)) {
      throw new Error('Refusing to cache a provider credential');
    }
  }
}

/** Non-secret marker returned to Temporal so workflows can see that a refresh worked. */
export const WORKFLOW_HELD_CREDENTIAL = 'credential-held-by-activity';

export function redactIntegrationRecord<T extends Record<string, any> | null | undefined>(
  integration: T
): T {
  if (!integration) {
    return integration;
  }

  return {
    ...integration,
    token: '',
    refreshToken:
      integration.refreshToken == null ? integration.refreshToken : '',
  };
}

export function redactPostForWorkflow<T extends Record<string, any> | null | undefined>(
  post: T
): T {
  if (!post || typeof post !== 'object' || !post.integration) {
    return post;
  }

  return {
    ...post,
    integration: redactIntegrationRecord(post.integration),
  };
}

export function redactAuthDetailsForWorkflow<
  T extends { accessToken?: string; refreshToken?: string } | false | null | undefined
>(value: T): T {
  if (!value) {
    return value;
  }

  return {
    ...value,
    accessToken: value.accessToken ? WORKFLOW_HELD_CREDENTIAL : '',
    refreshToken: value.refreshToken ? WORKFLOW_HELD_CREDENTIAL : '',
  };
}

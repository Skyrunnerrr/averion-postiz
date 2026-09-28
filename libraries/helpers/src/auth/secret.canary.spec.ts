import crypto from 'crypto';
import { Context } from '@temporalio/activity';
import { setHeartbeatDetails } from '@gitroom/nestjs-libraries/temporal/temporal.heartbeat';
import {
  assertRedisPayloadHasNoCredential,
  assertTokenEncryptionConfigured,
  openCredential,
  redactAuthDetailsForWorkflow,
  redactIntegrationRecord,
  redactPostForWorkflow,
  scrubProviderSecrets,
  sealCredential,
  withProviderSecrets,
} from './provider.credential';

jest.mock('@temporalio/activity', () => {
  const sent: string[] = [];
  const ctx = {
    info: { activityType: 'fixture' },
    sent,
    heartbeat(details?: string) {
      sent.push(details == null ? '' : String(details));
    },
  };
  return {
    Context: {
      current: () => ctx,
    },
  };
});

type HeartbeatContext = {
  heartbeat: (details?: string) => void;
  sent: string[];
};

function containsNeedle(blobs: string[], needles: string[]) {
  return blobs.some((blob) =>
    needles.some((needle) => needle.length > 0 && blob.includes(needle))
  );
}

describe('provider secret canary', () => {
  const previousKey = process.env.TOKEN_ENCRYPTION_KEY;
  const previousRequired = process.env.TOKEN_ENCRYPTION_REQUIRED;
  const previousCanary = process.env.AVERION_P2_CANARY;

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
    if (previousCanary === undefined) {
      delete process.env.AVERION_P2_CANARY;
    } else {
      process.env.AVERION_P2_CANARY = previousCanary;
    }
  });

  it('keeps captured db, temporal, heartbeat, log, exception, and redis fixtures free of the process canary', async () => {
    const canary = `AVERION_P2_CANARY_${crypto.randomBytes(16).toString('hex')}`;
    const refreshCanary = `AVERION_P2_CANARY_${crypto.randomBytes(16).toString('hex')}`;
    process.env.AVERION_P2_CANARY = canary;
    process.env.TOKEN_ENCRYPTION_KEY = Buffer.alloc(32, 7).toString('base64');
    process.env.TOKEN_ENCRYPTION_REQUIRED = 'true';

    const logs: string[] = [];
    const originalLog = console.log;
    const originalError = console.error;
    const capture = (...args: unknown[]) => {
      logs.push(
        args
          .map((item) => {
            if (typeof item === 'string') {
              return item;
            }
            if (item instanceof Error) {
              return `${item.name}: ${item.message}`;
            }
            try {
              return JSON.stringify(item);
            } catch {
              return '';
            }
          })
          .join(' ')
      );
    };
    console.log = capture;
    console.error = capture;

    try {
      const stored = sealCredential(canary, 'token');
      const storedRefresh = sealCredential(refreshCanary, 'refreshToken');
      const sealed =
        stored.startsWith('pzce1.') && storedRefresh.startsWith('pzce1.');

      const dbRepresentation = JSON.stringify({
        id: 'int-canary',
        token: stored,
        refreshToken: storedRefresh,
        name: 'channel',
      });
      const redactedDb = JSON.stringify(
        redactIntegrationRecord({
          id: 'int-canary',
          token: stored,
          refreshToken: storedRefresh,
          name: 'channel',
        })
      );
      const temporalPost = JSON.stringify(
        redactPostForWorkflow({
          id: 'post-canary',
          integration: {
            id: 'int-canary',
            token: canary,
            refreshToken: refreshCanary,
          },
        })
      );
      const temporalRefresh = JSON.stringify(
        redactAuthDetailsForWorkflow({
          id: 'user',
          accessToken: canary,
          refreshToken: refreshCanary,
        })
      );

      let serialized = '';
      let redisRepresentation = '';
      let heartbeatDetails = '';
      let heartbeatSent = '';

      await withProviderSecrets([canary, refreshCanary], async () => {
        setHeartbeatDetails(
          `instagram graph access_token=${canary} refresh_token=${refreshCanary} ${canary}`
        );
        const ctx = Context.current() as unknown as HeartbeatContext;
        heartbeatDetails = String(
          (ctx as unknown as Record<symbol, unknown>)[
            Symbol.for('postiz.heartbeatDetails')
          ] ?? ''
        );
        ctx.heartbeat(heartbeatDetails);
        heartbeatSent = ctx.sent.join('\n');

        const providerError = new Error(
          `graph failed access_token=${canary} refresh_token=${refreshCanary}`
        );
        console.log(scrubProviderSecrets(providerError.message));
        console.error(
          'withHeartbeat: heartbeat failed',
          scrubProviderSecrets(providerError.stack || providerError.message)
        );

        try {
          openCredential(canary, 'token');
        } catch (err) {
          const error = err as Error;
          serialized += JSON.stringify({
            name: error.name,
            message: scrubProviderSecrets(error.message),
            stack: scrubProviderSecrets(error.stack || ''),
          });
        }

        const parts = stored.split('.');
        const tag = Buffer.from(parts[4], 'base64url');
        tag[0] ^= 0xff;
        parts[4] = tag.toString('base64url');
        try {
          openCredential(parts.join('.'), 'token');
        } catch (err) {
          const error = err as Error;
          serialized += JSON.stringify({
            name: error.name,
            message: scrubProviderSecrets(error.message),
            stack: scrubProviderSecrets(error.stack || ''),
          });
        }

        const safeRedis = JSON.stringify({ clicks: 4, views: 1 });
        assertRedisPayloadHasNoCredential(safeRedis);
        redisRepresentation = safeRedis;
        try {
          assertRedisPayloadHasNoCredential(
            JSON.stringify({ accessToken: canary })
          );
        } catch (err) {
          const error = err as Error;
          redisRepresentation += JSON.stringify({
            name: error.name,
            message: scrubProviderSecrets(error.message),
          });
        }
      });

      const savedKey = process.env.TOKEN_ENCRYPTION_KEY;
      delete process.env.TOKEN_ENCRYPTION_KEY;
      try {
        assertTokenEncryptionConfigured();
      } catch (err) {
        const error = err as Error;
        serialized += JSON.stringify({
          name: error.name,
          message: error.message,
        });
      } finally {
        process.env.TOKEN_ENCRYPTION_KEY = savedKey;
      }

      const exercised =
        sealed &&
        dbRepresentation.includes('pzce1.') &&
        redactedDb.length > 0 &&
        temporalPost.length > 0 &&
        temporalRefresh.includes('credential-held-by-activity') &&
        heartbeatDetails.length > 0 &&
        heartbeatSent.length > 0 &&
        serialized.includes('PlaintextCredentialError') &&
        serialized.includes('CredentialAuthError') &&
        serialized.includes('TokenEncryptionConfigurationError') &&
        redisRepresentation.includes('clicks') &&
        logs.length > 0;

      const leaked = containsNeedle(
        [
          dbRepresentation,
          redactedDb,
          temporalPost,
          temporalRefresh,
          heartbeatDetails,
          heartbeatSent,
          serialized,
          redisRepresentation,
          logs.join('\n'),
        ],
        [canary, refreshCanary]
      );

      expect(exercised).toBe(true);
      expect(leaked).toBe(false);
    } finally {
      console.log = originalLog;
      console.error = originalError;
      delete process.env.AVERION_P2_CANARY;
    }
  });
});

/**
 * What getMissingContent and checkPostAnalytics do with a refresh result.
 * A falsy refresh leaves the channel connected. Disconnect only when the
 * refresh call returned a result that has no access token.
 */
export type RefreshChannelOutcome =
  | { kind: 'empty' }
  | { kind: 'disconnect' }
  | { kind: 'continue'; accessToken: string };

export function refreshChannelOutcome(
  data: false | null | undefined | { accessToken?: string }
): RefreshChannelOutcome {
  if (!data) {
    return { kind: 'empty' };
  }
  if (!data.accessToken) {
    return { kind: 'disconnect' };
  }
  return { kind: 'continue', accessToken: data.accessToken };
}

/**
 * Classifies the value refresh() already returned.
 * This function does not disconnect a channel.
 *
 * getMissingContent and checkPostAnalytics call refresh() with
 * disconnectOnFailure: false. On a falsy provider refresh, or a result with
 * no access token, that call returns false and does not call
 * disconnectChannel. kind 'empty' then means return [] and leave the channel
 * connected.
 *
 * kind 'disconnect' is only a truthy result that has no access token.
 * refresh() does not return that shape: it turns a missing token into false
 * before the caller sees it. Other callers leave disconnectOnFailure at its
 * default (true) and still disconnect.
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

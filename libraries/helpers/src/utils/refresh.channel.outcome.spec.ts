import { refreshChannelOutcome } from './refresh.channel.outcome';

describe('refreshChannelOutcome', () => {
  it('does not disconnect when refresh returns false', () => {
    expect(refreshChannelOutcome(false)).toEqual({ kind: 'empty' });
    expect(refreshChannelOutcome(null)).toEqual({ kind: 'empty' });
    expect(refreshChannelOutcome(undefined)).toEqual({ kind: 'empty' });
  });

  it('disconnects only when the refresh result has no access token', () => {
    expect(refreshChannelOutcome({ accessToken: '' })).toEqual({
      kind: 'disconnect',
    });
  });

  it('continues with the access token from a successful refresh', () => {
    expect(refreshChannelOutcome({ accessToken: 'next-token' })).toEqual({
      kind: 'continue',
      accessToken: 'next-token',
    });
  });
});

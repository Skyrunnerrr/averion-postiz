import { InstagramStandaloneProvider } from './instagram.standalone.provider';
import { NotEnoughScopes } from '@gitroom/nestjs-libraries/integrations/social.abstract';

describe('instagram standalone oauth scopes', () => {
  const provider = new InstagramStandaloneProvider();

  beforeAll(() => {
    process.env.INSTAGRAM_APP_ID = 'averion-app';
    process.env.FRONTEND_URL = 'https://provider.example';
  });

  it('authorizes and checks exactly instagram_business_basic and instagram_business_content_publish', async () => {
    expect(provider.scopes).toEqual([
      'instagram_business_basic',
      'instagram_business_content_publish',
    ]);

    const { url } = await provider.generateAuthUrl();
    const scope = new URL(url).searchParams.get('scope') || '';
    expect(scope.split(',')).toEqual([
      'instagram_business_basic',
      'instagram_business_content_publish',
    ]);
    expect(scope).not.toContain('comment');
    expect(scope).not.toContain('insight');

    expect(
      provider.checkScopes(provider.scopes, [
        'instagram_business_basic',
        'instagram_business_content_publish',
      ])
    ).toBe(true);
    expect(() =>
      provider.checkScopes(provider.scopes, ['instagram_business_basic'])
    ).toThrow(NotEnoughScopes);
    expect(() =>
      provider.checkScopes(provider.scopes, [
        'instagram_business_basic',
        'instagram_business_manage_comments',
      ])
    ).toThrow(NotEnoughScopes);
  });
});

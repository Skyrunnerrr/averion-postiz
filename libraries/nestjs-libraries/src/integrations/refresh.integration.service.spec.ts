jest.mock(
  '@gitroom/nestjs-libraries/integrations/integration.manager',
  () => ({
    IntegrationManager: class IntegrationManager {},
  })
);

jest.mock(
  '@gitroom/nestjs-libraries/database/prisma/integrations/integration.service',
  () => ({
    IntegrationService: class IntegrationService {},
  })
);

jest.mock('nestjs-temporal-core', () => ({
  TemporalService: class TemporalService {},
}));

jest.mock('@sentry/nestjs', () => ({
  captureException: jest.fn(),
}));

jest.mock('@gitroom/helpers/utils/sanitize.post.content', () => ({
  postContentPlainText: (value: string) => value,
  sanitizePostContent: (value: string) => value,
}));

jest.mock('@gitroom/nestjs-libraries/dtos/posts/create.post.dto', () => ({
  CreatePostDto: class CreatePostDto {},
}));

jest.mock(
  '@gitroom/nestjs-libraries/dtos/generator/create.generated.posts.dto',
  () => ({
    CreateGeneratedPostsDto: class CreateGeneratedPostsDto {},
  })
);

jest.mock('@gitroom/nestjs-libraries/openai/openai.service', () => ({
  OpenaiService: class OpenaiService {},
}));

jest.mock(
  '@gitroom/nestjs-libraries/database/prisma/media/media.service',
  () => ({
    MediaService: class MediaService {},
  })
);

jest.mock(
  '@gitroom/nestjs-libraries/short-linking/short.link.service',
  () => ({
    ShortLinkService: class ShortLinkService {},
  })
);

jest.mock(
  '@gitroom/nestjs-libraries/database/prisma/posts/posts.repository',
  () => ({
    PostsRepository: class PostsRepository {},
  })
);

jest.mock('@gitroom/nestjs-libraries/upload/upload.factory', () => ({
  UploadFactory: {
    createStorage: () => ({}),
  },
}));

import { RefreshIntegrationService } from '@gitroom/nestjs-libraries/integrations/refresh.integration.service';
import { PostsService } from '@gitroom/nestjs-libraries/database/prisma/posts/posts.service';

function channel() {
  return {
    id: 'int-1',
    organizationId: 'org-1',
    name: 'channel',
    picture: 'pic',
    internalId: 'internal',
    rootInternalId: 'internal',
    providerIdentifier: 'instagram-standalone',
    token: 'stored-token',
    refreshToken: 'stored-refresh',
    tokenExpiration: new Date(Date.now() - 60_000),
  };
}

describe('refresh disconnect on failure', () => {
  const integrationService = {
    createOrUpdateIntegration: jest.fn(),
    refreshNeeded: jest.fn(),
    informAboutRefreshError: jest.fn(),
    disconnectChannel: jest.fn(),
  };
  const provider = {
    missing: jest.fn(),
    postAnalytics: jest.fn(),
    refreshToken: jest.fn(),
    refreshWait: false,
    oneTimeToken: false,
    reConnect: undefined as undefined,
  };
  const manager = {
    getSocialIntegration: jest.fn(() => provider),
  };
  let refreshService: RefreshIntegrationService;
  let posts: PostsService;
  let postRepository: { getPostById: jest.Mock };

  beforeEach(() => {
    delete process.env.TOKEN_ENCRYPTION_REQUIRED;
    delete process.env.TOKEN_ENCRYPTION_KEY;
    jest.clearAllMocks();
    provider.refreshToken.mockResolvedValue(false);
    manager.getSocialIntegration.mockReturnValue(provider);
    refreshService = new RefreshIntegrationService(
      manager as never,
      integrationService as never,
      {} as never
    );
    postRepository = {
      getPostById: jest.fn(),
    };
    posts = new PostsService(
      postRepository as never,
      manager as never,
      integrationService as never,
      {} as never,
      {} as never,
      {} as never,
      {} as never,
      refreshService
    );
  });

  it('disconnects on a falsy refresh when disconnectOnFailure stays at the default', async () => {
    const result = await refreshService.refresh(channel() as never);

    expect(result).toBe(false);
    expect(integrationService.disconnectChannel).toHaveBeenCalledWith(
      'org-1',
      expect.objectContaining({ id: 'int-1' })
    );
  });

  it('disconnects when the refresh result has no access token', async () => {
    provider.refreshToken.mockResolvedValue({ accessToken: '' });

    const result = await refreshService.refresh(channel() as never, 'cron');

    expect(result).toBe(false);
    expect(integrationService.refreshNeeded).toHaveBeenCalled();
    expect(integrationService.disconnectChannel).toHaveBeenCalled();
  });

  it('getMissingContent does not disconnect when refresh is falsy', async () => {
    postRepository.getPostById.mockResolvedValue({
      releaseId: 'missing',
      integration: channel(),
    });

    await expect(posts.getMissingContent('org-1', 'post-1')).resolves.toEqual(
      []
    );
    expect(provider.refreshToken).toHaveBeenCalled();
    expect(integrationService.disconnectChannel).not.toHaveBeenCalled();
    expect(integrationService.refreshNeeded).not.toHaveBeenCalled();
  });

  it('getMissingContent does not disconnect when the refresh result has no access token', async () => {
    provider.refreshToken.mockResolvedValue({ accessToken: '' });
    postRepository.getPostById.mockResolvedValue({
      releaseId: 'missing',
      integration: channel(),
    });

    await expect(posts.getMissingContent('org-1', 'post-1')).resolves.toEqual(
      []
    );
    expect(integrationService.disconnectChannel).not.toHaveBeenCalled();
  });

  it('checkPostAnalytics does not disconnect when refresh is falsy', async () => {
    postRepository.getPostById.mockResolvedValue({
      id: 'post-1',
      releaseId: 'release-1',
      integration: channel(),
    });

    await expect(
      posts.checkPostAnalytics('org-1', 'post-1', Date.now())
    ).resolves.toEqual([]);
    expect(provider.refreshToken).toHaveBeenCalled();
    expect(integrationService.disconnectChannel).not.toHaveBeenCalled();
    expect(integrationService.refreshNeeded).not.toHaveBeenCalled();
  });
});

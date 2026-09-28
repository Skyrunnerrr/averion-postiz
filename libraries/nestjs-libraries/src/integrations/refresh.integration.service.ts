import { forwardRef, Inject, Injectable } from '@nestjs/common';
import { Integration } from '@prisma/client';
import { IntegrationManager } from '@gitroom/nestjs-libraries/integrations/integration.manager';
import { IntegrationService } from '@gitroom/nestjs-libraries/database/prisma/integrations/integration.service';
import {
  AuthTokenDetails,
  SocialProvider,
} from '@gitroom/nestjs-libraries/integrations/social/social.integrations.interface';
import { TemporalService } from 'nestjs-temporal-core';
import {
  openIntegrationForProviderCall,
  withProviderSecrets,
} from '@gitroom/helpers/auth/provider.credential';

export type RefreshCallOptions = {
  /**
   * Upstream default is true: a falsy refresh or a missing access token
   * disconnects the channel. getMissingContent and checkPostAnalytics pass
   * false so those paths return false and leave the channel connected.
   */
  disconnectOnFailure?: boolean;
};

@Injectable()
export class RefreshIntegrationService {
  constructor(
    private _integrationManager: IntegrationManager,
    @Inject(forwardRef(() => IntegrationService))
    private _integrationService: IntegrationService,
    private _temporalService: TemporalService
  ) {}
  async refresh(
    integration: Integration,
    cause = '',
    options: RefreshCallOptions = {}
  ): Promise<false | AuthTokenDetails> {
    const socialProvider = this._integrationManager.getSocialIntegration(
      integration.providerIdentifier
    );

    const refresh = await this.refreshProcess(
      integration,
      socialProvider,
      cause,
      options.disconnectOnFailure !== false
    );

    if (!refresh) {
      return false as const;
    }

    await this._integrationService.createOrUpdateIntegration(
      undefined,
      !!socialProvider.oneTimeToken,
      integration.organizationId,
      integration.name,
      integration.picture!,
      'social',
      integration.internalId,
      integration.providerIdentifier,
      refresh.accessToken,
      refresh.refreshToken,
      refresh.expiresIn
    );

    return refresh;
  }

  public async setBetweenSteps(integration: Integration, cause = '') {
    await this._integrationService.setBetweenRefreshSteps(integration.id);
    await this._integrationService.informAboutRefreshError(
      integration.organizationId,
      integration,
      cause
    );
  }

  public async startRefreshWorkflow(orgId: string, id: string, integration: SocialProvider) {
    if (!integration.refreshCron) {
      return false;
    }

    return this._temporalService.client
      .getRawClient()
      ?.workflow.start(`refreshTokenWorkflow`, {
        workflowId: `refresh_${id}`,
        args: [{integrationId: id, organizationId: orgId}],
        taskQueue: 'main',
        workflowIdConflictPolicy: 'TERMINATE_EXISTING',
      });
  }

  private async refreshProcess(
    integration: Integration,
    socialProvider: SocialProvider,
    cause = '',
    disconnectOnFailure = true
  ): Promise<AuthTokenDetails | false> {
    const opened = openIntegrationForProviderCall(integration);
    const refresh: false | AuthTokenDetails = await withProviderSecrets(
      [opened.token, opened.refreshToken],
      () => socialProvider.refreshToken(opened.refreshToken).catch(() => false)
    );

    if (!refresh || !refresh.accessToken) {
      if (disconnectOnFailure) {
        await this._integrationService.refreshNeeded(
          integration.organizationId,
          integration.id
        );

        await this._integrationService.informAboutRefreshError(
          integration.organizationId,
          integration,
          cause
        );

        await this._integrationService.disconnectChannel(
          integration.organizationId,
          integration
        );
      }

      return false;
    }

    if (
      !socialProvider.reConnect ||
      integration.rootInternalId === integration.internalId
    ) {
      return refresh;
    }

    const reConnect = await withProviderSecrets(
      [refresh.accessToken, refresh.refreshToken],
      () =>
        socialProvider.reConnect(
          integration.rootInternalId,
          integration.internalId,
          refresh.accessToken
        )
    );

    return {
      ...refresh,
      ...reConnect,
    };
  }
}

import type { InteractionResults } from 'oidc-provider';
import { BadRequestHttpError } from '../../util/errors/BadRequestHttpError';
import type { Interaction } from './InteractionHandler';

// TODO:
export function assertOidcInteraction(oidcInteraction?: Interaction): asserts oidcInteraction is Interaction {
  if (!oidcInteraction) {
    throw new BadRequestHttpError(
      'This action can only be performed as part of an OIDC authentication flow.',
      { errorCode: 'E0002' },
    );
  }
}

// TODO:
export async function finishInteraction(oidcInteraction: Interaction, result: InteractionResults, mergeWithLastSubmission: boolean): Promise<string> {
  if (mergeWithLastSubmission) {
    result = { ...oidcInteraction.lastSubmission, ...result };
  }

  oidcInteraction.result = result;
  await oidcInteraction.save(oidcInteraction.exp - Math.floor(Date.now() / 1000));

  return oidcInteraction.returnTo;
}

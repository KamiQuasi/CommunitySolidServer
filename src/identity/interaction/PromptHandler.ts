import { BadRequestHttpError } from '../../util/errors/BadRequestHttpError';
import { FoundHttpError } from '../../util/errors/FoundHttpError';
import type { JsonInteractionHandlerInput } from './JsonInteractionHandler';
import { JsonInteractionHandler } from './JsonInteractionHandler';
import type { InteractionRoute } from './routing/InteractionRoute';

// TODO: there is not really a reason for this to have a path, could just be small utility class

/**
 * Redirects requests based on the OIDC Interaction prompt.
 * Errors in case no match was found.
 */
export class PromptHandler extends JsonInteractionHandler {
  private readonly promptRoutes: Record<string, InteractionRoute>;

  public constructor(promptRoutes: Record<string, InteractionRoute>) {
    super();
    this.promptRoutes = promptRoutes;
  }

  public async handle({ oidcInteraction }: JsonInteractionHandlerInput): Promise<never> {
    const prompt = oidcInteraction?.prompt.name;
    if (prompt && this.promptRoutes[prompt]) {
      const location = this.promptRoutes[prompt].getPath({});
      throw new FoundHttpError(location!);
    }
    throw new BadRequestHttpError(`Unsupported prompt: ${prompt}`);
  }
}

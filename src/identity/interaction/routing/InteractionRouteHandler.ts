import { NotFoundHttpError } from '../../../util/errors/NotFoundHttpError';
import type { JsonInteractionHandlerInput, JsonRepresentation } from '../JsonInteractionHandler';
import { JsonInteractionHandler } from '../JsonInteractionHandler';
import type { AccountRoute } from './InteractionRoute';

/**
 * InteractionHandler that only accepts input of which the target matches the stored route.
 *
 * Rejects operations that target a different route,
 * otherwise the input parameters are passed to the source handler.
 *
 * Makes sure that if there is an account ID in the URL it matches the logged in user.
 */
export class InteractionRouteHandler extends JsonInteractionHandler {
  private readonly route: AccountRoute;
  private readonly source: JsonInteractionHandler;

  public constructor(route: AccountRoute, source: JsonInteractionHandler) {
    super();
    this.route = route;
    this.source = source;
  }

  public async canHandle(input: JsonInteractionHandlerInput): Promise<void> {
    const { target, accountId } = input;
    const match = this.route.matchPath(target.path);
    // TODO: to be fully correct we should have type InteractionHandler and have PathAccountId string constant
    if (!match || (match.accountId && match.accountId !== accountId)) {
      throw new NotFoundHttpError();
    }
    await this.source.canHandle(input);
  }

  public async handle(input: JsonInteractionHandlerInput): Promise<JsonRepresentation> {
    return this.source.handle(input);
  }
}

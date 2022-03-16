import { RepresentationMetadata } from '../../http/representation/RepresentationMetadata';
import { getLoggerFor } from '../../logging/LogUtil';
import { InternalServerError } from '../../util/errors/InternalServerError';
import { SOLID_HTTP } from '../../util/Vocabularies';
import type { AccountStore } from '../account/AccountStore';
import { finishInteraction } from './InteractionUtil';
import type { Json, JsonInteractionHandlerInput, JsonRepresentation } from './JsonInteractionHandler';
import { JsonInteractionHandler } from './JsonInteractionHandler';
import type { AccountRoute } from './routing/InteractionRoute';

// TODO:
export class ResolveLoginHandler extends JsonInteractionHandler {
  protected readonly logger = getLoggerFor(this);

  // TODO: this needs to be a constant somewhere. AccountUtil/LoginUtil?
  //       or new specific type that extends JsonInteractionHandler
  private readonly loginHandler: JsonInteractionHandler<{ accountId?: string }>;
  private readonly accountStore: AccountStore;
  private readonly accountRoute: AccountRoute;

  public constructor(loginHandler: JsonInteractionHandler<{ accountId?: string }>, accountStore: AccountStore, accountRoute: AccountRoute) {
    super();
    this.loginHandler = loginHandler;
    this.accountStore = accountStore;
    this.accountRoute = accountRoute;
  }

  public async canHandle(input: JsonInteractionHandlerInput): Promise<void> {
    await this.loginHandler.canHandle(input);
  }

  public async handle(input: JsonInteractionHandlerInput): Promise<JsonRepresentation> {
    const result = await this.loginHandler.handle(input);
    const { accountId } = result.json;

    // Only add required login metadata if there was a successful login
    if (!accountId) {
      return result;
    }

    const account = await this.accountStore.find(accountId);
    if (!account) {
      this.logger.error(`Authenticated user with ID ${accountId} but could not find a matching Account.`);
      throw new InternalServerError('Could not find a matching account.');
    }

    const path = this.accountRoute.getPath({ accountId });
    const json: Json = { ...result.json, account: path };
    // Not throwing redirect error since we can't add cookie metadata then
    if (input.oidcInteraction) {
      // TODO: would be nice if these were constants and we had typings
      // TODO: perhaps different name so we don't have 2 accountIds
      json.location = await finishInteraction(input.oidcInteraction, { account: accountId }, true);
    }

    const cookie = await this.accountStore.generateCookie(accountId);
    const metadata = result.metadata ?? new RepresentationMetadata(input.target);
    metadata.add(SOLID_HTTP.terms.accountCookie, cookie);
    metadata.set(SOLID_HTTP.terms.location, path);

    return { json, metadata };
  }
}

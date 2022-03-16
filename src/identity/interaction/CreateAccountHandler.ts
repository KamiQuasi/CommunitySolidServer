import { RepresentationMetadata } from '../../http/representation/RepresentationMetadata';
import { SOLID_HTTP } from '../../util/Vocabularies';
import type { AccountStore } from '../account/AccountStore';
import type { Json, JsonInteractionHandlerInput, JsonRepresentation } from './JsonInteractionHandler';
import { JsonInteractionHandler } from './JsonInteractionHandler';
import type { AccountRoute } from './routing/InteractionRoute';
import type { JsonView } from './ViewUtil';

// TODO:
export class CreateAccountHandler extends JsonInteractionHandler implements JsonView {
  private readonly accountStore: AccountStore;
  private readonly accountRoute: AccountRoute;

  public constructor(accountStore: AccountStore, accountRoute: AccountRoute) {
    super();
    this.accountStore = accountStore;
    this.accountRoute = accountRoute;
  }

  public async getView(): Promise<JsonRepresentation<NodeJS.Dict<Json>>> {
    return { json: {}};
  }

  public async handle({ target }: JsonInteractionHandlerInput): Promise<JsonRepresentation> {
    const account = await this.accountStore.create();

    const path = this.accountRoute.getPath({ accountId: account.id });
    const metadata = new RepresentationMetadata(target);
    metadata.set(SOLID_HTTP.terms.location, path);

    // Add cookie so users are logged in as the new account they just created
    const cookie = await this.accountStore.generateCookie(account.id);
    metadata.add(SOLID_HTTP.terms.accountCookie, cookie);

    return { json: { account: path!, accountId: account.id }, metadata };
  }
}

import { BadRequestHttpError } from '../../util/errors/BadRequestHttpError';
import { SOLID_HTTP } from '../../util/Vocabularies';
import type { AccountStore } from '../account/AccountStore';
import type { JsonInteractionHandlerInput, JsonRepresentation } from './JsonInteractionHandler';
import { JsonInteractionHandler } from './JsonInteractionHandler';

// TODO:
export class LogoutHandler extends JsonInteractionHandler {
  public readonly accountStore: AccountStore;

  public constructor(accountStore: AccountStore) {
    super();
    this.accountStore = accountStore;
  }

  public async handle({ metadata, accountId }: JsonInteractionHandlerInput): Promise<JsonRepresentation> {
    const cookie = metadata.get(SOLID_HTTP.terms.accountCookie)?.value;
    if (cookie) {
      // Make sure the user is logged in with the relevant account for the given cookie
      const foundId = await this.accountStore.findByCookie(cookie);
      if (foundId !== accountId) {
        throw new BadRequestHttpError('Invalid cookie.');
      }

      await this.accountStore.deleteCookie(cookie);
    }

    return { json: {}};
  }
}

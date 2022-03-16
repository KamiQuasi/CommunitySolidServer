import { BadRequestHttpError } from '../../util/errors/BadRequestHttpError';
import type { AccountStore } from '../account/AccountStore';
import { getRequiredAccount } from '../account/AccountUtil';
import type { JsonInteractionHandlerInput, JsonRepresentation } from './JsonInteractionHandler';
import { JsonInteractionHandler } from './JsonInteractionHandler';

// TODO:
export class WebIdUnlinker extends JsonInteractionHandler {
  private readonly accountStore: AccountStore;

  public constructor(accountStore: AccountStore) {
    super();
    this.accountStore = accountStore;
  }

  public async handle({ target, accountId }: JsonInteractionHandlerInput): Promise<JsonRepresentation> {
    const account = await getRequiredAccount(this.accountStore, accountId);

    // TODO: might be suited for AccountUtil
    const webId = Object.entries(account.webIds).find((entry): boolean => entry[1] === target.path)?.[0];

    if (!webId) {
      throw new BadRequestHttpError('Could not find matching WebID.');
    }

    // eslint-disable-next-line @typescript-eslint/no-dynamic-delete
    delete account.webIds[webId];
    await this.accountStore.update(account);
    return { json: {}};
  }
}

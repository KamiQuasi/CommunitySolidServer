import type { AccountStore } from '../account/AccountStore';
import { getRequiredAccount } from '../account/AccountUtil';
import type { JsonInteractionHandlerInput, JsonRepresentation } from './JsonInteractionHandler';
import { JsonInteractionHandler } from './JsonInteractionHandler';

// TODO:
export class AccountViewHandler extends JsonInteractionHandler {
  private readonly accountStore: AccountStore;

  public constructor(accountStore: AccountStore) {
    super();
    this.accountStore = accountStore;
  }

  public async handle({ accountId }: JsonInteractionHandlerInput): Promise<JsonRepresentation> {
    const account = await getRequiredAccount(this.accountStore, accountId);
    return { json: account };
  }
}

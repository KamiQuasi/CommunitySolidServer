import type { KeyValueStorage } from '../../../storage/keyvalue/KeyValueStorage';
import { BadRequestHttpError } from '../../../util/errors/BadRequestHttpError';
import type { AccountStore } from '../../account/AccountStore';
import { getRequiredAccount } from '../../account/AccountUtil';
import type { JsonInteractionHandlerInput, JsonRepresentation } from '../JsonInteractionHandler';
import { JsonInteractionHandler } from '../JsonInteractionHandler';
import type { ClientCredentials } from './ClientCredentialsAdapterFactory';

/**
 * Handles the deletion of credential tokens.
 */
export class DeleteCredentialsHandler extends JsonInteractionHandler {
  private readonly accountStore: AccountStore;
  private readonly credentialsStorage: KeyValueStorage<string, ClientCredentials>;

  public constructor(accountStore: AccountStore, credentialsStorage: KeyValueStorage<string, ClientCredentials>) {
    super();
    this.accountStore = accountStore;
    this.credentialsStorage = credentialsStorage;
  }

  public async handle({ target, accountId }: JsonInteractionHandlerInput): Promise<JsonRepresentation> {
    const account = await getRequiredAccount(this.accountStore, accountId);

    // TODO: might be suited for AccountUtil
    const token = Object.entries(account.credentials).find((entry): boolean => entry[1] === target.path)?.[0];

    if (!token) {
      throw new BadRequestHttpError('Could not find matching credential token.');
    }

    await this.credentialsStorage.delete(token);
    // eslint-disable-next-line @typescript-eslint/no-dynamic-delete
    delete account.credentials[token];
    await this.accountStore.update(account);
    return { json: {}};
  }
}

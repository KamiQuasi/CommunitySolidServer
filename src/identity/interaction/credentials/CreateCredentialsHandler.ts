import { randomBytes } from 'crypto';
import { v4 } from 'uuid';
import { object, string } from 'yup';
import type { KeyValueStorage } from '../../../storage/keyvalue/KeyValueStorage';
import { BadRequestHttpError } from '../../../util/errors/BadRequestHttpError';
import { sanitizeUrlPart } from '../../../util/StringUtil';
import type { AccountStore } from '../../account/AccountStore';
import { getRequiredAccount } from '../../account/AccountUtil';
import type { JsonInteractionHandlerInput, JsonRepresentation } from '../JsonInteractionHandler';
import { JsonInteractionHandler } from '../JsonInteractionHandler';
import type { AccountCredentialsRoute } from '../routing/InteractionRoute';
import { parseSchema } from '../ViewUtil';
import type { JsonView } from '../ViewUtil';
import type { ClientCredentials } from './ClientCredentialsAdapterFactory';

// TODO: there is no way for a user to know which WebID is associated with which token
//       ^ ViewCredentialsHandler
const inSchema = object({
  name: string().trim().optional(),
  webId: string().trim().required(),
});

type OutType = {
  id: string;
  secret: string;
  url: string;
};

/**
 * Handles the creation of credential tokens.
 */
export class CreateCredentialsHandler extends JsonInteractionHandler<OutType> implements JsonView {
  private readonly accountStore: AccountStore;
  private readonly credentialsStorage: KeyValueStorage<string, ClientCredentials>;
  private readonly credentialsRoute: AccountCredentialsRoute;

  public constructor(accountStore: AccountStore, credentialsStorage: KeyValueStorage<string, ClientCredentials>, credentialsRoute: AccountCredentialsRoute) {
    super();
    this.accountStore = accountStore;
    this.credentialsStorage = credentialsStorage;
    this.credentialsRoute = credentialsRoute;
  }

  public async getView(): Promise<JsonRepresentation> {
    return { json: parseSchema(inSchema) };
  }

  public async handle({ accountId, json }: JsonInteractionHandlerInput): Promise<JsonRepresentation<OutType>> {
    const account = await getRequiredAccount(this.accountStore, accountId);

    const validated = await inSchema.validate(json);

    const name = validated.name ? sanitizeUrlPart(validated.name.trim()) : '';

    if (typeof account.webIds[validated.webId] !== 'string') {
      throw new BadRequestHttpError('WebID does not belong to this account.');
    }

    const id = `${name}_${v4()}`;
    const secret = randomBytes(64).toString('hex');

    // Store the credentials, and point to them from the account
    const path = this.credentialsRoute.getPath({ accountId, credentialsId: id });
    account.credentials[id] = path!;
    await this.accountStore.update(account);
    await this.credentialsStorage.set(id, { accountId: accountId!, secret, webId: validated.webId });

    return { json: { id, secret, url: account.credentials[id] }};
  }
}

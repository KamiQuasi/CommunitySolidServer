import { BadRequestHttpError } from '../../../../util/errors/BadRequestHttpError';
import type { AccountStore } from '../../../account/AccountStore';
import { getRequiredAccount } from '../../../account/AccountUtil';
import type { JsonInteractionHandlerInput, JsonRepresentation } from '../../JsonInteractionHandler';
import { JsonInteractionHandler } from '../../JsonInteractionHandler';
import type { AccountPasswordRoute } from '../../routing/InteractionRoute';
import type { PasswordStore } from './PasswordStore';

// TODO: duplicate from create password handler, should be constant somewhere
const loginMethod = 'password';

// TODO:
export class DeletePasswordHandler extends JsonInteractionHandler {
  private readonly accountStore: AccountStore;
  private readonly passwordStore: PasswordStore;
  private readonly passwordRoute: AccountPasswordRoute;

  public constructor(accountStore: AccountStore, passwordStore: PasswordStore, passwordRoute: AccountPasswordRoute) {
    super();
    this.accountStore = accountStore;
    this.passwordStore = passwordStore;
    this.passwordRoute = passwordRoute;
  }

  public async handle({ target, accountId }: JsonInteractionHandlerInput): Promise<JsonRepresentation> {
    const account = await getRequiredAccount(this.accountStore, accountId);

    const deleteTarget = account.logins[loginMethod];

    if (deleteTarget !== target.path) {
      throw new BadRequestHttpError('Invalid password URL.');
    }

    const passwordId = this.passwordRoute.matchPath(target.path)?.passwordId;
    // TODO: util functions for consistency?
    // The password ID is the email address
    const email = decodeURIComponent(passwordId!);

    // This needs to happen first since this checks that there is at least 1 login method
    // eslint-disable-next-line @typescript-eslint/no-dynamic-delete
    delete account.logins[loginMethod];
    await this.accountStore.update(account);

    await this.passwordStore.delete(email);
    return { json: {}};
  }
}

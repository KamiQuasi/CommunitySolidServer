import { object, string } from 'yup';
import { BadRequestHttpError } from '../../../../util/errors/BadRequestHttpError';
import type { AccountStore } from '../../../account/AccountStore';
import { getRequiredAccount } from '../../../account/AccountUtil';
import type { JsonInteractionHandlerInput, JsonRepresentation } from '../../JsonInteractionHandler';
import { JsonInteractionHandler } from '../../JsonInteractionHandler';
import type { AccountPasswordRoute } from '../../routing/InteractionRoute';
import { parseSchema } from '../../ViewUtil';
import type { JsonView } from '../../ViewUtil';
import type { PasswordStore } from './PasswordStore';
import Dict = NodeJS.Dict;

// TODO: duplicate from create password handler, should be constant somewhere
const loginMethod = 'password';

const inSchema = object({
  oldPassword: string().trim().min(1).required(),
  password: string().trim().min(1).required(),
  // TODO: why not do password confirmation at frontend?
  confirmPassword: string().trim().required(),
});

// TODO:
export class UpdatePasswordHandler extends JsonInteractionHandler implements JsonView {
  private readonly accountStore: AccountStore;
  private readonly passwordStore: PasswordStore;
  private readonly passwordRoute: AccountPasswordRoute;

  public constructor(accountStore: AccountStore, passwordStore: PasswordStore, passwordRoute: AccountPasswordRoute) {
    super();
    this.accountStore = accountStore;
    this.passwordStore = passwordStore;
    this.passwordRoute = passwordRoute;
  }

  public async getView(): Promise<JsonRepresentation> {
    return { json: parseSchema(inSchema) };
  }

  public async handle({ target, accountId, json }: JsonInteractionHandlerInput): Promise<JsonRepresentation> {
    const account = await getRequiredAccount(this.accountStore, accountId);

    const passwordTarget = account.logins[loginMethod];

    if (passwordTarget !== target.path) {
      throw new BadRequestHttpError('Invalid password URL.');
    }

    const { oldPassword, password, confirmPassword } = await inSchema.validate(json);
    if (password !== confirmPassword) {
      throw new BadRequestHttpError('Password confirmation is incorrect.');
    }

    const passwordId = this.passwordRoute.matchPath(target.path)?.passwordId;
    // TODO: util functions for consistency?
    // The password ID is the email address
    const email = decodeURIComponent(passwordId!);

    // Make sure the old password is correct
    try {
      await this.passwordStore.authenticate(email, oldPassword);
    } catch {
      throw new BadRequestHttpError('Old password is invalid.');
    }

    await this.passwordStore.changePassword(email, password);

    return { json: {}};
  }
}

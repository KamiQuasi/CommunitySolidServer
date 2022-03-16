import { object, string } from 'yup';
import { getLoggerFor } from '../../../../logging/LogUtil';
import { BadRequestHttpError } from '../../../../util/errors/BadRequestHttpError';
import { ConflictHttpError } from '../../../../util/errors/ConflictHttpError';
import type { AccountStore } from '../../../account/AccountStore';
import { getRequiredAccount } from '../../../account/AccountUtil';
import type { JsonInteractionHandlerInput, JsonRepresentation } from '../../JsonInteractionHandler';
import { JsonInteractionHandler } from '../../JsonInteractionHandler';
import type { AccountPasswordRoute } from '../../routing/InteractionRoute';
import { parseSchema } from '../../ViewUtil';
import type { JsonView } from '../../ViewUtil';
import type { PasswordStore } from './PasswordStore';
import Dict = NodeJS.Dict;

const inSchema = object({
  email: string().trim().email().required(),
  password: string().trim().min(1).required(),
  // TODO: why not do password confirmation at frontend?
  confirmPassword: string().trim().required(),
});

// TODO: constant
const loginMethod = 'password';

// TODO:
export class CreatePasswordHandler extends JsonInteractionHandler implements JsonView {
  protected readonly logger = getLoggerFor(this);

  private readonly passwordStore: PasswordStore;
  private readonly accountStore: AccountStore;
  private readonly passwordRoute: AccountPasswordRoute;

  public constructor(passwordStore: PasswordStore, accountStore: AccountStore, passwordRoute: AccountPasswordRoute) {
    super();
    this.passwordStore = passwordStore;
    this.accountStore = accountStore;
    this.passwordRoute = passwordRoute;
  }

  public async getView(): Promise<JsonRepresentation> {
    return { json: parseSchema(inSchema) };
  }

  public async handle({ accountId, json }: JsonInteractionHandlerInput): Promise<JsonRepresentation> {
    const account = await getRequiredAccount(this.accountStore, accountId);

    if (account.logins[loginMethod]) {
      throw new ConflictHttpError('This account already has this login method');
    }

    const { email, password, confirmPassword } = await inSchema.validate(json);
    if (password !== confirmPassword) {
      throw new BadRequestHttpError('Password confirmation is incorrect.');
    }

    await this.passwordStore.create(email, account.id, password);

    // In case we use email verification this would have to be checked separately
    await this.passwordStore.verify(email);

    const path = this.passwordRoute.getPath({ accountId, passwordId: encodeURIComponent(email) });
    account.logins[loginMethod] = path!;
    await this.accountStore.update(account);

    return { json: { [loginMethod]: account.logins[loginMethod] }};
  }
}

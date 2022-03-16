import { object, string } from 'yup';
import { getLoggerFor } from '../../../../logging/LogUtil';
import type { JsonInteractionHandlerInput, JsonRepresentation } from '../../JsonInteractionHandler';
import { JsonInteractionHandler } from '../../JsonInteractionHandler';
import { parseSchema } from '../../ViewUtil';
import type { JsonView } from '../../ViewUtil';
import type { PasswordStore } from './PasswordStore';

const inSchema = object({
  email: string().trim().email().required(),
  password: string().trim().required(),
});

/**
 * Handles the submission of the Login Form and logs the user in.
 */
export class PasswordLoginHandler extends JsonInteractionHandler implements JsonView {
  protected readonly logger = getLoggerFor(this);

  private readonly passwordStore: PasswordStore;

  public constructor(passwordStore: PasswordStore) {
    super();
    this.passwordStore = passwordStore;
  }

  public async getView(): Promise<JsonRepresentation> {
    return { json: parseSchema(inSchema) };
  }

  public async handle({ json }: JsonInteractionHandlerInput): Promise<JsonRepresentation> {
    const { email, password } = await inSchema.validate(json);
    // Try to log in, will error if email/password combination is invalid
    const accountId = await this.passwordStore.authenticate(email, password);
    this.logger.debug(`Logging in user ${email}`);

    return { json: { accountId }};
  }
}

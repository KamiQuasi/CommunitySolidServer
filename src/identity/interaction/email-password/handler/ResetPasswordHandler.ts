import assert from 'assert';
import { object, string } from 'yup';
import { getLoggerFor } from '../../../../logging/LogUtil';
import { BadRequestHttpError } from '../../../../util/errors/BadRequestHttpError';
import type { JsonInteractionHandlerInput, JsonRepresentation } from '../../JsonInteractionHandler';
import { JsonInteractionHandler } from '../../JsonInteractionHandler';
import { parseSchema } from '../../ViewUtil';
import type { JsonView } from '../../ViewUtil';
import type { PasswordStore } from './PasswordStore';

const inSchema = object({
  recordId: string().trim().min(1).required(),
  password: string().trim().required(),
  // TODO: why not do password confirmation at frontend?
  confirmPassword: string().trim().required(),
});

/**
 * Resets a password if a valid `recordId` is provided,
 * which should have been generated by a different handler.
 */
export class ResetPasswordHandler extends JsonInteractionHandler implements JsonView {
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
    // Validate input data
    const { password, confirmPassword, recordId } = await inSchema.validate(json);
    if (password !== confirmPassword) {
      throw new BadRequestHttpError('Password confirmation is incorrect.');
    }

    await this.resetPassword(recordId, password);
    return { json: {}};
  }

  /**
   * Resets the password for the account associated with the given recordId.
   */
  private async resetPassword(recordId: string, newPassword: string): Promise<void> {
    const email = await this.passwordStore.getForgotPasswordRecord(recordId);
    assert(email, 'This reset password link is no longer valid.');
    await this.passwordStore.deleteForgotPasswordRecord(recordId);
    await this.passwordStore.changePassword(email, newPassword);
    this.logger.debug(`Resetting password for user ${email}`);
  }
}

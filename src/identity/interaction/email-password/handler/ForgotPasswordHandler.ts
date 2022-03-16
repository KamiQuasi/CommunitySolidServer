import { object, string } from 'yup';
import { getLoggerFor } from '../../../../logging/LogUtil';
import type { TemplateEngine } from '../../../../util/templates/TemplateEngine';
import type { JsonInteractionHandlerInput, JsonRepresentation } from '../../JsonInteractionHandler';
import { JsonInteractionHandler } from '../../JsonInteractionHandler';
import type { InteractionRoute } from '../../routing/InteractionRoute';
import { parseSchema } from '../../ViewUtil';
import type { JsonView } from '../../ViewUtil';
import type { EmailSender } from '../util/EmailSender';
import type { PasswordStore } from './PasswordStore';
import Dict = NodeJS.Dict;

const inSchema = object({
  email: string().trim().email().required(),
});

export interface ForgotPasswordHandlerArgs {
  passwordStore: PasswordStore;
  templateEngine: TemplateEngine<{ resetLink: string }>;
  emailSender: EmailSender;
  resetRoute: InteractionRoute;
}

/**
 * Handles the submission of the ForgotPassword form
 */
export class ForgotPasswordHandler extends JsonInteractionHandler implements JsonView {
  protected readonly logger = getLoggerFor(this);

  private readonly passwordStore: PasswordStore;
  private readonly templateEngine: TemplateEngine<{ resetLink: string }>;
  private readonly emailSender: EmailSender;
  private readonly resetRoute: InteractionRoute;

  public constructor(args: ForgotPasswordHandlerArgs) {
    super();
    this.passwordStore = args.passwordStore;
    this.templateEngine = args.templateEngine;
    this.emailSender = args.emailSender;
    this.resetRoute = args.resetRoute;
  }

  public async getView(): Promise<JsonRepresentation> {
    return { json: parseSchema(inSchema) };
  }

  public async handle({ json }: JsonInteractionHandlerInput): Promise<JsonRepresentation> {
    const { email } = await inSchema.validate(json);

    await this.resetPassword(email);
    return { json: { email }};
  }

  /**
   * Generates a record to reset the password for the given email address and then mails it.
   * In case there is no account, no error wil be thrown for privacy reasons.
   * Instead nothing will happen instead.
   */
  private async resetPassword(email: string): Promise<void> {
    let recordId: string;
    try {
      recordId = await this.passwordStore.generateForgotPasswordRecord(email);
    } catch {
      // Don't emit an error for privacy reasons
      this.logger.warn(`Password reset request for unknown email ${email}`);
      return;
    }
    await this.sendResetMail(recordId, email);
  }

  /**
   * Generates the link necessary for resetting the password and mails it to the given email address.
   */
  private async sendResetMail(recordId: string, email: string): Promise<void> {
    this.logger.info(`Sending password reset to ${email}`);
    const resetLink = `${this.resetRoute.getPath({})}?rid=${encodeURIComponent(recordId)}`;
    const renderedEmail = await this.templateEngine.render({ resetLink });
    await this.emailSender.handleSafe({
      recipient: email,
      subject: 'Reset your password',
      text: `To reset your password, go to this link: ${resetLink}`,
      html: renderedEmail,
    });
  }
}

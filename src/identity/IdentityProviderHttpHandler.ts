import { OkResponseDescription } from '../http/output/response/OkResponseDescription';
import type { ResponseDescription } from '../http/output/response/ResponseDescription';
import { getLoggerFor } from '../logging/LogUtil';
import type { OperationHttpHandlerInput } from '../server/OperationHttpHandler';
import { OperationHttpHandler } from '../server/OperationHttpHandler';
import type { RepresentationConverter } from '../storage/conversion/RepresentationConverter';
import { SOLID_HTTP } from '../util/Vocabularies';
import type { AccountStore } from './account/AccountStore';
import type { ProviderFactory } from './configuration/ProviderFactory';
import type { InteractionHandler,
  Interaction } from './interaction/InteractionHandler';

export interface IdentityProviderHttpHandlerArgs {
  /**
   * Used to generate the OIDC provider.
   */
  providerFactory: ProviderFactory;
  /**
   * Used for converting the input data.
   */
  converter: RepresentationConverter;
  /**
   * Used to determine the account of the requesting agent.
   */
  accountStore: AccountStore;
  /**
   * Handles the requests.
   */
  handler: InteractionHandler;
}

/**
 * Generates the active Interaction object if there is an ongoing OIDC interaction
 * and sends it to the {@link InteractionHandler}.
 *
 * Input data will first be converted to JSON.
 *
 * Only GET and POST methods are accepted.
 */
export class IdentityProviderHttpHandler extends OperationHttpHandler {
  protected readonly logger = getLoggerFor(this);

  private readonly providerFactory: ProviderFactory;
  private readonly converter: RepresentationConverter;
  private readonly accountStore: AccountStore;
  private readonly handler: InteractionHandler;

  public constructor(args: IdentityProviderHttpHandlerArgs) {
    super();
    this.providerFactory = args.providerFactory;
    this.converter = args.converter;
    this.accountStore = args.accountStore;
    this.handler = args.handler;
  }

  public async handle({ operation, request, response }: OperationHttpHandlerInput): Promise<ResponseDescription> {
    // This being defined means we're in an OIDC session
    let oidcInteraction: Interaction | undefined;
    try {
      const provider = await this.providerFactory.getProvider();
      oidcInteraction = await provider.interactionDetails(request, response);
      this.logger.debug('Found an active OIDC interaction.');
    } catch {
      this.logger.debug('No active OIDC interaction found.');
    }

    // Determine account
    // TODO: extract cookie (potentially in external class)
    const cookie = operation.body.metadata.get(SOLID_HTTP.terms.accountCookie)?.value;
    let accountId: string | undefined;
    if (cookie) {
      accountId = await this.accountStore.findByCookie(cookie);
    }

    const representation = await this.handler.handleSafe({ operation, oidcInteraction, accountId });
    return new OkResponseDescription(representation.metadata, representation.data);
  }
}

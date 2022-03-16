import type { InteractionResults } from 'oidc-provider';
import { boolean, object, string } from 'yup';
import { BadRequestHttpError } from '../../util/errors/BadRequestHttpError';
import { FoundHttpError } from '../../util/errors/FoundHttpError';
import type { AccountStore } from '../account/AccountStore';
import { getRequiredAccount } from '../account/AccountUtil';
import { assertOidcInteraction, finishInteraction } from './InteractionUtil';
import type { JsonInteractionHandlerInput, JsonRepresentation } from './JsonInteractionHandler';
import { JsonInteractionHandler } from './JsonInteractionHandler';
import { parseSchema } from './ViewUtil';
import type { JsonView } from './ViewUtil';

const inSchema = object({
  webId: string().trim().required(),
  remember: boolean().default(false),
});

// TODO:
export class WebIdPicker extends JsonInteractionHandler<never> implements JsonView {
  private readonly accountStore: AccountStore;

  public constructor(accountStore: AccountStore) {
    super();
    this.accountStore = accountStore;
  }

  public async getView({ accountId }: JsonInteractionHandlerInput): Promise<JsonRepresentation> {
    const account = await getRequiredAccount(this.accountStore, accountId);
    const description = parseSchema(inSchema);
    return { json: { ...description, webIds: Object.keys(account.webIds) }};
  }

  public async handle({ oidcInteraction, accountId, json }: JsonInteractionHandlerInput): Promise<never> {
    assertOidcInteraction(oidcInteraction);
    const account = await getRequiredAccount(this.accountStore, accountId);

    const { webId, remember } = await inSchema.validate(json);
    if (!account.webIds[webId]) {
      throw new BadRequestHttpError('WebID does not belong to this account.');
    }

    // TODO: this means the remember checkbox needs to be on this page
    // Update the interaction to get the redirect URL
    const login: InteractionResults['login'] = {
      // Note that `accountId` here is unrelated to our user accounts but is part of the OIDC library
      accountId: webId,
      // TODO: if we want to allow this there needs to be a way to forget it again
      remember,
    };

    const location = await finishInteraction(oidcInteraction, { login }, true);
    throw new FoundHttpError(location);
  }
}

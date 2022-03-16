import { createHash } from 'crypto';
import { object, string } from 'yup';
import type { ResourceStore } from '../../storage/ResourceStore';
import type { IdentifierStrategy } from '../../util/identifiers/IdentifierStrategy';
import { findStorage } from '../../util/ResourceUtil';
import type { AccountStore } from '../account/AccountStore';
import { getRequiredAccount } from '../account/AccountUtil';
import type { OwnershipValidator } from '../ownership/OwnershipValidator';
import type { JsonInteractionHandlerInput, JsonRepresentation } from './JsonInteractionHandler';
import { JsonInteractionHandler } from './JsonInteractionHandler';
import type { AccountWebIdRoute } from './routing/InteractionRoute';
import { parseSchema } from './ViewUtil';
import type { JsonView } from './ViewUtil';

const inSchema = object({
  webId: string().trim().required(),
});

// TODO:
export interface WebIdLinkerArgs {
  baseUrl: string;
  ownershipValidator: OwnershipValidator;
  accountStore: AccountStore;
  webIdRoute: AccountWebIdRoute;
  identifierStrategy: IdentifierStrategy;
  resourceStore: ResourceStore;
}

// TODO:
export class WebIdLinker extends JsonInteractionHandler implements JsonView {
  private readonly baseUrl: string;
  private readonly ownershipValidator: OwnershipValidator;
  private readonly accountStore: AccountStore;
  private readonly webIdRoute: AccountWebIdRoute;
  private readonly identifierStrategy: IdentifierStrategy;
  private readonly resourceStore: ResourceStore;

  public constructor(args: WebIdLinkerArgs) {
    super();
    this.baseUrl = args.baseUrl;
    this.ownershipValidator = args.ownershipValidator;
    this.accountStore = args.accountStore;
    this.webIdRoute = args.webIdRoute;
    this.identifierStrategy = args.identifierStrategy;
    this.resourceStore = args.resourceStore;
  }

  public async getView(): Promise<JsonRepresentation> {
    return { json: parseSchema(inSchema) };
  }

  public async handle({ accountId, json }: JsonInteractionHandlerInput): Promise<JsonRepresentation> {
    const account = await getRequiredAccount(this.accountStore, accountId);

    const { webId } = await inSchema.validate(json);

    // TODO: need to alert user to add oidcissuer triple on HTML response

    // Already getting parent here so we don't have to clean webId
    const baseUrl = await findStorage(this.identifierStrategy.getParentContainer({ path: webId }), this.resourceStore, this.identifierStrategy);
    // Only need to check ownership if the account is not the owner
    if (!baseUrl || typeof account.pods[baseUrl.path] !== 'string') {
      await this.ownershipValidator.handleSafe({ webId });
    }
    const webIdHash = createHash('sha256').update(webId).digest('hex');
    const path = this.webIdRoute.getPath({ accountId, webIdHash });
    account.webIds[webId] = path!;
    await this.accountStore.update(account);

    return { json: { url: account.webIds[webId], oidcIssuer: this.baseUrl }};
  }
}

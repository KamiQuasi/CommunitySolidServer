import type { AllClientMetadata } from 'oidc-provider';
import type { ProviderFactory } from '../configuration/ProviderFactory';
import { assertOidcInteraction } from './InteractionUtil';
import type { JsonInteractionHandlerInput, JsonRepresentation } from './JsonInteractionHandler';
import { JsonInteractionHandler } from './JsonInteractionHandler';

// TODO: Util type
export type ArrayElement<TArray> = TArray extends readonly (infer TEntry)[] ? TEntry : never;

// TODO:
export class ClientInfoHandler extends JsonInteractionHandler {
  private readonly providerFactory: ProviderFactory;

  public constructor(providerFactory: ProviderFactory) {
    super();
    this.providerFactory = providerFactory;
  }

  public async canHandle(input: JsonInteractionHandlerInput): Promise<void> {
    assertOidcInteraction(input.oidcInteraction);
  }

  public async handle({ oidcInteraction }: JsonInteractionHandlerInput): Promise<JsonRepresentation> {
    const provider = await this.providerFactory.getProvider();
    const client = await provider.Client.find(oidcInteraction!.params.client_id as string);
    const metadata: AllClientMetadata = client?.metadata() ?? {};

    // Only extract specific fields to prevent leaking information
    // Based on https://www.w3.org/ns/solid/oidc-context.jsonld
    const keys = [ 'client_id', 'client_uri', 'logo_uri', 'policy_uri',
      'client_name', 'contacts', 'grant_types', 'scope' ] as const;

    type KeyType = ArrayElement<typeof keys>;
    type ValType = AllClientMetadata[KeyType];

    const jsonLd = Object.fromEntries(
      keys.filter((key): boolean => key in metadata)
        .map((key): [ KeyType, ValType ] => [ key, metadata[key] ]),
    );
    jsonLd['@context'] = 'https://www.w3.org/ns/solid/oidc-context.jsonld';

    const webId = oidcInteraction?.session?.accountId;

    return { json: { client: jsonLd, webId }};
  }
}

import type { JsonInteractionHandlerInput, JsonRepresentation } from './JsonInteractionHandler';
import { JsonInteractionHandler } from './JsonInteractionHandler';
import type { AccountRoute } from './routing/InteractionRoute';

// TODO:
export class AccountControlHandler extends JsonInteractionHandler {
  private readonly controls: Record<string, AccountRoute>;

  public constructor(controls: Record<string, AccountRoute>) {
    super();
    this.controls = controls;
  }

  public async handle({ accountId }: JsonInteractionHandlerInput): Promise<JsonRepresentation> {
    const json: Record<string, string> = {};
    for (const [ key, route ] of Object.entries(this.controls)) {
      const path = route.getPath({ accountId });
      if (path) {
        json[key] = path;
      }
    }

    return { json };
  }
}

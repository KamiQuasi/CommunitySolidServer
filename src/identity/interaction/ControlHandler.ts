import type { Json, JsonInteractionHandlerInput, JsonRepresentation } from './JsonInteractionHandler';
import { JsonInteractionHandler } from './JsonInteractionHandler';

const INTERNAL_API_VERSION = '0.4';

// TODO:
/**
 * Adds `controls` and `apiVersion` fields to the output of its source handler,
 * such that clients can predictably find their way to other resources.
 * Control paths are determined by the input routes.
 */
export class ControlHandler extends JsonInteractionHandler {
  // TODO: either everywhere source or handler
  private readonly source: JsonInteractionHandler;
  private readonly key: string;
  private readonly controls: Record<string, JsonInteractionHandler>;

  public constructor(source: JsonInteractionHandler, key: string, controls: Record<string, JsonInteractionHandler>) {
    super();
    this.source = source;
    this.key = key;
    this.controls = controls;
  }

  public async canHandle(input: JsonInteractionHandlerInput): Promise<void> {
    await this.source.canHandle(input);
  }

  public async handle(input: JsonInteractionHandlerInput): Promise<JsonRepresentation> {
    const result = await this.source.handle(input);
    const controls: Record<string, Json> = {};

    for (const [ key, handler ] of Object.entries(this.controls)) {
      controls[key] = (await handler.handleSafe(input)).json;
    }

    // TODO: will need separate HTML controls

    const json = { ...result.json, [this.key]: controls, apiVersion: INTERNAL_API_VERSION };
    return {
      json,
      metadata: result.metadata,
    };
  }
}

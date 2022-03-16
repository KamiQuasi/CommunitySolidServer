/* eslint-disable tsdoc/syntax */
// tsdoc/syntax cannot handle `@range`
import type { Json, JsonRepresentation } from './JsonInteractionHandler';
import { JsonInteractionHandler } from './JsonInteractionHandler';

/**
 * An {@link JsonInteractionHandler} that always returns the same JSON response on all requests.
 */
export class StaticInteractionHandler extends JsonInteractionHandler {
  private readonly response: Record<string, Json>;

  /**
   * @param response - @range {json}
   */
  public constructor(response: Record<string, Json>) {
    super();
    this.response = response;
  }

  public async handle(): Promise<JsonRepresentation> {
    return { json: this.response };
  }
}

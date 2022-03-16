import type { Json, JsonRepresentation } from './JsonInteractionHandler';
import { JsonInteractionHandler } from './JsonInteractionHandler';
import type { InteractionRoute } from './routing/InteractionRoute';
import Dict = NodeJS.Dict;

// TODO:
export class StaticControlHandler extends JsonInteractionHandler {
  // TODO: rename to routes (here and in other one)
  // TODO: also rename class
  private readonly controls: Record<string, string>;
  // TODO: perhaps remove this and add separate LoginViewHandler back so we can also have descriptions there
  //       ^ or we could immediately include all login URLs in view, already do this in account controls!
  private readonly name?: string;

  public constructor(controls: Record<string, InteractionRoute>, name?: string) {
    super();
    this.controls = Object.fromEntries(
      Object.entries(controls).map(([ login, route ]): [ string, string ] => [ login, route.getPath({})! ]),
    );
    this.name = name;
  }

  public async handle(): Promise<JsonRepresentation> {
    let json: Dict<Json> = this.controls;
    if (this.name) {
      json = { [this.name]: json };
    }

    return { json };
  }
}

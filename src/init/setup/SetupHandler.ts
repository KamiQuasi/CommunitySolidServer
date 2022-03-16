import { boolean, object } from 'yup';
import type { AssertsShape } from 'yup/lib/object';
import type { RepresentationMetadata } from '../../http/representation/RepresentationMetadata';
import type {
  Json,
  JsonInteractionHandlerInput,
  JsonRepresentation,
} from '../../identity/interaction/JsonInteractionHandler';
import { JsonInteractionHandler } from '../../identity/interaction/JsonInteractionHandler';
import { parseSchema } from '../../identity/interaction/ViewUtil';
import type { JsonView } from '../../identity/interaction/ViewUtil';
import { getLoggerFor } from '../../logging/LogUtil';
import { NotImplementedHttpError } from '../../util/errors/NotImplementedHttpError';
import type { Initializer } from '../Initializer';

// TODO:
export interface SetupHandlerArgs {
  /**
   * Used for registering a pod during setup.
   */
  registrationHandler?: JsonInteractionHandler & JsonView;
  /**
   * Initializer to call in case no registration procedure needs to happen.
   * This Initializer should make sure the necessary resources are there so the server can work correctly.
   */
  initializer?: Initializer;
}

const inSchema = object({
  registration: object().optional(),
  initialize: boolean().default(false),
});

// TODO: add method filter handler + JsonConversionHandler, could also add JsonView interface

// TODO: problem is that everything needs to happen in 1 request
//       if we still want this might need to rewrite registration manager
//       problem is that this forces us into email/password registration again
//       unless extra parameters (e.g. type: 'password') are sent along as extra metadata
//       only account registration is needed though? rest can be done later?

/**
 * On POST requests, runs an initializer and/or performs a registration step, both optional.
 */
export class SetupHandler extends JsonInteractionHandler implements JsonView {
  protected readonly logger = getLoggerFor(this);

  private readonly registrationHandler?: JsonInteractionHandler & JsonView;
  private readonly initializer?: Initializer;

  public constructor(args: SetupHandlerArgs) {
    super();
    this.registrationHandler = args.registrationHandler;
    this.initializer = args.initializer;
  }

  public async getView(input: JsonInteractionHandlerInput): Promise<JsonRepresentation> {
    // TODO
    const json = parseSchema(inSchema);
    if (this.registrationHandler) {
      const registrationView = await this.registrationHandler.getView(input);
      json.fields.registration = { ...registrationView.json, ...json.fields.registration };
    }
    return { json };
  }

  public async handle(input: JsonInteractionHandlerInput): Promise<JsonRepresentation> {
    const validated = await inSchema.validate(input.json);
    const json: { registration?: Json; initialize?: boolean } = {};
    let metadata: RepresentationMetadata | undefined;
    if (validated.registration) {
      const representation = await this.register(input, validated);
      json.registration = representation.json;
      ({ metadata } = representation);
    } else if (validated.initialize) {
      // We only want to initialize if no registration happened
      await this.initialize();
      json.initialize = true;
    }

    this.logger.debug(`Setup result: ${JSON.stringify(json)}`);

    return { json, metadata };
  }

  /**
   * Call the initializer.
   * Errors if no initializer was defined.
   */
  private async initialize(): Promise<void> {
    if (!this.initializer) {
      throw new NotImplementedHttpError('This server is not configured with a setup initializer.');
    }
    await this.initializer.handleSafe();
  }

  /**
   * Register a user based on the given input.
   * Errors if no registration manager is defined.
   */
  private async register(input: JsonInteractionHandlerInput, validated: AssertsShape<typeof inSchema.fields>): Promise<JsonRepresentation> {
    if (!this.registrationHandler) {
      throw new NotImplementedHttpError('This server is not configured to support registration during setup.');
    }
    return this.registrationHandler.handleSafe({ ...input, ...validated.registration });
  }
}

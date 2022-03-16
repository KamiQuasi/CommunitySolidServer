import { object } from 'yup';
import { RepresentationMetadata } from '../../http/representation/RepresentationMetadata';
import { getLoggerFor } from '../../logging/LogUtil';
import { createErrorMessage } from '../../util/errors/ErrorUtil';
import type { Json, JsonInteractionHandlerInput, JsonRepresentation } from './JsonInteractionHandler';
import { JsonInteractionHandler } from './JsonInteractionHandler';
import { parseSchema } from './ViewUtil';
import type { JsonView } from './ViewUtil';
import Dict = NodeJS.Dict;

// TODO: any reason to still keep this? Need solution for setuphandler.

// TODO: this class doesn't work anymore due to the import changes. typed to any so rest can build for now

// TODO: have this class take as input a createAccountHandler, createPodHandler, createLoginHandler, etc.
//       have it take the views of those classes to return on GET requests
//       this way it can potentially easily be changed to use a different login method

export interface RegistrationHandlerArgs {
  // TODO:
  accountHandler: JsonInteractionHandler<{ accountId: string }> & JsonView;
  loginHandler: JsonInteractionHandler & JsonView;
  podHandler: JsonInteractionHandler & JsonView;
  webIdHandler: JsonInteractionHandler & JsonView;
}

// TODO: technically these could be arrays but would probably make things more difficult?
const inSchema = object({
  account: object().optional(),
  login: object().optional(),
  pod: object().optional(),
  webId: object().optional(),
});

// TODO:
/**
 * Supports IDP registration and pod creation based on input parameters.
 *
 * The above behaviour is combined in the two class functions.
 * `validateInput` will make sure all incoming data is correct and makes sense.
 * `register` will call all the correct handlers based on the requirements of the validated parameters.
 */
export class RegistrationHandler extends JsonInteractionHandler implements JsonView {
  protected readonly logger = getLoggerFor(this);

  private readonly accountHandler: JsonInteractionHandler<{ accountId: string }> & JsonView;
  private readonly loginHandler: JsonInteractionHandler & JsonView;
  private readonly podHandler: JsonInteractionHandler & JsonView;
  private readonly webIdHandler: JsonInteractionHandler & JsonView;

  public constructor(args: RegistrationHandlerArgs) {
    super();
    this.accountHandler = args.accountHandler;
    this.loginHandler = args.loginHandler;
    this.podHandler = args.podHandler;
    this.webIdHandler = args.webIdHandler;
  }

  public async getView(input: JsonInteractionHandlerInput): Promise<JsonRepresentation> {
    const json = parseSchema(inSchema);
    // TODO: helper function?
    json.fields.account = { ...json.fields.account, ...(await this.accountHandler.getView(input)).json };
    json.fields.login = { ...json.fields.account, ...(await this.loginHandler.getView(input)).json };
    json.fields.pod = { ...json.fields.account, ...(await this.podHandler.getView(input)).json };
    json.fields.webId = { ...json.fields.account, ...(await this.webIdHandler.getView(input)).json };
    return { json };
  }

  public async handle(input: JsonInteractionHandlerInput): Promise<JsonRepresentation> {
    // TODO: will have to indicate which parts were successful so these don't have to be repeated
    // TODO: making assumptions about output typings here, would be nice if some of these were generic for all handlers matching this type
    //       E.g.: LoginHandler is a specific JsonInteractionHandler with specific output

    const validated = await inSchema.validate(input.json);

    const representation: JsonRepresentation = { json: {}, metadata: new RepresentationMetadata(input.target) };
    if (validated.account) {
      const result = await this.accountHandler.handleSafe({ ...input, json: validated.account });
      // Update the account ID in the input
      input.accountId = result.json.accountId;
      representation.json.account = result.json;
      representation.metadata?.addQuads(result.metadata?.quads() ?? []);
    }

    if (!await this.useHandler('login', validated, this.loginHandler, input, representation)) {
      return representation;
    }
    if (!await this.useHandler('pod', validated, this.podHandler, input, representation)) {
      return representation;
    }
    await this.useHandler('webId', validated, this.webIdHandler, input, representation);
    return representation;
  }

  // TODO:
  private async useHandler(key: string, validated: Dict<Json>, handler: JsonInteractionHandler,
    input: JsonInteractionHandlerInput, representation: JsonRepresentation): Promise<boolean> {
    if (validated[key]) {
      try {
        const result = await handler.handleSafe({ ...input, json: validated[key] });
        representation.json[key] = result.json;
        representation.metadata?.addQuads(result.metadata?.quads() ?? []);
      } catch (error: unknown) {
        representation.json[key] = { error: createErrorMessage(error) };
        return false;
      }
    }
    return true;
  }
}


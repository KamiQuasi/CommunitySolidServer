import type { RepresentationMetadata } from '../../http/representation/RepresentationMetadata';
import type { ResourceIdentifier } from '../../http/representation/ResourceIdentifier';
import { AsyncHandler } from '../../util/handlers/AsyncHandler';
import type { Interaction } from './InteractionHandler';
import Dict = NodeJS.Dict;

export type Json = string | number | boolean | Dict<Json> | Json[];

export interface JsonInteractionHandlerInput {
  /**
   * The operation to execute.
   */
  method: string;
  // TODO:
  metadata: RepresentationMetadata;
  // TODO:
  json: unknown;
  // TODO:
  target: ResourceIdentifier;
  /**
   * Will be defined if the OIDC library expects us to resolve an interaction it can't handle itself,
   * such as logging a user in.
   */
  oidcInteraction?: Interaction;
  /**
   * The account id of the agent doing the request if one could be found.
   */
  accountId?: string;
}

// TODO:
export interface JsonRepresentation<T extends Dict<Json> = Dict<Json>> {
  json: T;
  metadata?: RepresentationMetadata;
}

// TODO: search for all extends JsonInteractionHandler and make sure most have output type

// TODO:
export abstract class JsonInteractionHandler<TOut extends Dict<Json> = Dict<Json>> extends AsyncHandler<JsonInteractionHandlerInput, JsonRepresentation<TOut>> { }

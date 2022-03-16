import type { BaseSchema, ObjectSchema } from 'yup';
import type { JsonRepresentation, JsonInteractionHandlerInput, Json } from './JsonInteractionHandler';
import Dict = NodeJS.Dict;

// TODO: check everywhere: yup/lib or yup/es

// TODO:
export interface JsonView {
  getView: (input: JsonInteractionHandlerInput) => Promise<JsonRepresentation>;
}

function isObjectSchema(schema: BaseSchema): schema is ObjectSchema<any> {
  return schema.type === 'object';
}

// TODO:
type FieldTypes<T extends ObjectSchema<any>> = T extends { fields: Record<infer R, any> } ? R : never;
type SchemaType<T extends BaseSchema> = T extends ObjectSchema<any> ? ObjectType<T> : { required: boolean; type: string };
type ObjectType<T extends ObjectSchema<any>> = { required: boolean; type: 'object'; fields: {[ K in FieldTypes<T> ]: SchemaType<T['fields'][K]> }};

function parseSchemaDescription<T extends BaseSchema>(schema: T): SchemaType<T> {
  // TODO: check if this works
  // const required = schema.tests.some((test): boolean => test.name === 'required');
  const required = schema.spec.presence === 'required';
  const result: Dict<Json> = { required, type: schema.type };
  if (isObjectSchema(schema)) {
    result.fields = {};
    for (const [ field, description ] of Object.entries(schema.fields)) {
      // Cast can be wrong in complex cases but we don't have any
      result.fields[field] = parseSchemaDescription(description as BaseSchema);
    }
  }
  return result as SchemaType<T>;
}

// TODO:
export function parseSchema<T extends ObjectSchema<any>>(schema: T): Pick<SchemaType<T>, 'fields'> {
  const result = parseSchemaDescription(schema);
  return { fields: result.fields };
}

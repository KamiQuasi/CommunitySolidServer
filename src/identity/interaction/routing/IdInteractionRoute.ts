import { ensureTrailingSlash, joinUrl } from '../../../util/PathUtil';
import type { InteractionRoute } from './InteractionRoute';

// TODO:
export class IdInteractionRoute<TBase extends string, TId extends string> implements InteractionRoute<TBase | TId> {
  private readonly base: InteractionRoute<TBase>;
  private readonly idName: TId;

  public constructor(base: InteractionRoute<TBase>, idName: TId) {
    this.base = base;
    this.idName = idName;
  }

  public getPath(parameters: Record<TBase | TId, string | undefined>): string | undefined {
    // TODO: in case this is the account ID, do we need to check somewhere that this ID matches that of the account doing the request?
    const id = parameters[this.idName];
    if (!id) {
      return;
    }

    const path = this.base.getPath(parameters);

    if (path) {
      return joinUrl(path, ensureTrailingSlash(id));
    }
  }

  public matchPath(path: string): Record<TBase | TId, string> | undefined {
    const match = /(.*\/)([^/]+)\/$/u.exec(path);

    if (!match) {
      return;
    }

    const id = match[2];
    const head = match[1];

    const baseParameters = this.base.matchPath(head);

    if (!baseParameters) {
      return;
    }

    // Cast needed because TS always assumes type is { [x: string]: string; } when using [] like this
    // https://github.com/microsoft/TypeScript/issues/13948
    return { ...baseParameters, [this.idName]: id } as Record<TBase | TId, string>;
  }
}

import { ensureTrailingSlash, joinUrl, trimLeadingSlashes } from '../../../util/PathUtil';
import type { InteractionRoute } from './InteractionRoute';

// TODO:
/**
 * A route that is relative to another route.
 * The relative path will be joined to the input base,
 * which can either be an absolute URL or an InteractionRoute of which the path will be used.
 */
export class RelativePathInteractionRoute<TBase extends string> implements InteractionRoute<TBase> {
  private readonly base: InteractionRoute<TBase>;
  private readonly relativePath: string;

  public constructor(base: InteractionRoute<TBase>, relativePath: string) {
    this.base = base;
    this.relativePath = trimLeadingSlashes(ensureTrailingSlash(relativePath));
  }

  public getPath(parameters: Record<TBase, string | undefined>): string | undefined {
    const path = this.base.getPath(parameters);

    if (path) {
      return joinUrl(path, this.relativePath);
    }
  }

  public matchPath(path: string): Record<TBase, string> | undefined {
    if (!path.endsWith(this.relativePath)) {
      return;
    }

    const head = path.slice(0, -this.relativePath.length);

    return this.base.matchPath(head);
  }
}

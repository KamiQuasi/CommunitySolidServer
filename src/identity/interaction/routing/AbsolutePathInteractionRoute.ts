import { ensureTrailingSlash } from '../../../util/PathUtil';
import type { InteractionRoute } from './InteractionRoute';
import Dict = NodeJS.Dict;

// TODO:
/**
 * A route that stores a single absolute path.
 */
export class AbsolutePathInteractionRoute implements InteractionRoute {
  private readonly path: string;

  public constructor(path: string) {
    this.path = ensureTrailingSlash(path);
  }

  public getPath(): string {
    return this.path;
  }

  public matchPath(path: string): Dict<string> | undefined {
    if (path === this.path) {
      return {};
    }
  }
}

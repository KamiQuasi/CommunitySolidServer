import { getLoggerFor } from '../logging/LogUtil';
import { concatIterables } from '../util/IterableUtil';
import { ensureTrailingSlash, trimTrailingSlashes } from '../util/PathUtil';
import type { PermissionReaderInput } from './PermissionReader';
import { PermissionReader } from './PermissionReader';
import type { AccessMap, PermissionMap } from './permissions/Permissions';
import { IdentifierMap } from './permissions/Permissions';

/**
 * Redirects requests to specific PermissionReaders based on their identifier.
 * The keys in the input map will be converted to regular expressions.
 * The regular expressions should all start with a slash
 * and will be evaluated relative to the base URL.
 *
 * Will error if no match is found.
 */
export class PathBasedReader extends PermissionReader {
  protected readonly logger = getLoggerFor(this);

  private readonly baseUrl: string;
  private readonly paths: Map<RegExp, PermissionReader>;

  public constructor(baseUrl: string, paths: Record<string, PermissionReader>) {
    super();
    this.baseUrl = ensureTrailingSlash(baseUrl);
    const entries = Object.entries(paths)
      .map(([ key, val ]): [RegExp, PermissionReader] => [ new RegExp(key, 'u'), val ]);
    this.paths = new Map(entries);
  }

  public async handle(input: PermissionReaderInput): Promise<PermissionMap> {
    const results: PermissionMap[] = [];
    for (const [ reader, accessMap ] of this.matchReaders(input.accessMap)) {
      results.push(await reader.handleSafe({ credentials: input.credentials, accessMap }));
    }
    return new IdentifierMap(concatIterables(results));
  }

  /**
   * Returns all readers that match with at least 1 entry from the AccessMap.
   * These readers are mapped to a map containing all relevant resources.
   */
  private matchReaders(accessMap: AccessMap): Map<PermissionReader, AccessMap> {
    const result = new Map<PermissionReader, AccessMap>();
    for (const [ identifier, modes ] of accessMap) {
      const reader = this.findReader(identifier.path);
      if (reader) {
        let matches = result.get(reader);
        if (!matches) {
          matches = new IdentifierMap();
          result.set(reader, matches);
        }
        matches.set(identifier, modes);
      }
    }
    return result;
  }

  /**
   * Find the PermissionReader corresponding to the given path.
   */
  private findReader(path: string): PermissionReader | undefined {
    if (path.startsWith(this.baseUrl)) {
      // We want to keep the leading slash
      const relative = path.slice(trimTrailingSlashes(this.baseUrl).length);
      for (const [ regex, reader ] of this.paths) {
        if (regex.test(relative)) {
          this.logger.debug(`Matched path for ${path}`);
          return reader;
        }
      }
    }
  }
}

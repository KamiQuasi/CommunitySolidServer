import { CredentialGroup } from '../../../src/authentication/Credentials';
import { PathBasedReader } from '../../../src/authorization/PathBasedReader';
import type { PermissionReader, PermissionReaderInput } from '../../../src/authorization/PermissionReader';
import type { PermissionMap, PermissionSet } from '../../../src/authorization/permissions/Permissions';
import { IdentifierMap } from '../../../src/authorization/permissions/Permissions';
import type { ResourceIdentifier } from '../../../src/http/representation/ResourceIdentifier';
import { mapIterable } from '../../../src/util/IterableUtil';
import { joinUrl } from '../../../src/util/PathUtil';
import { compareMaps } from '../../util/Util';

describe('A PathBasedReader', (): void => {
  const baseUrl = 'http://test.com/foo/';
  const permissionSet: PermissionSet = { [CredentialGroup.agent]: { read: true }};
  let readers: jest.Mocked<PermissionReader>[];
  let reader: PathBasedReader;

  function handleSafe({ accessMap }: PermissionReaderInput): PermissionMap {
    return new IdentifierMap(mapIterable(accessMap.keys(), (identifier): [ResourceIdentifier, PermissionSet] =>
      [ identifier, permissionSet ]));
  }

  beforeEach(async(): Promise<void> => {
    readers = [
      { canHandle: jest.fn(), handleSafe: jest.fn(handleSafe) },
      { canHandle: jest.fn(), handleSafe: jest.fn(handleSafe) },
    ] as any;
    const paths = {
      '/first': readers[0],
      '/second': readers[1],
    };
    reader = new PathBasedReader(baseUrl, paths);
  });

  it('passes the handle requests to the matching reader.', async(): Promise<void> => {
    const input: PermissionReaderInput = {
      credentials: {},
      accessMap: new IdentifierMap([
        [{ path: joinUrl(baseUrl, 'first') }, new Set() ],
        [{ path: joinUrl(baseUrl, 'second') }, new Set() ],
        [{ path: joinUrl(baseUrl, 'nothere') }, new Set() ],
        [{ path: 'http://wrongsite' }, new Set() ],
      ]),
    };

    const result = new IdentifierMap([
      [{ path: joinUrl(baseUrl, 'first') }, permissionSet ],
      [{ path: joinUrl(baseUrl, 'second') }, permissionSet ],
    ]);

    await expect(reader.handle(input)).resolves.toEqual(result);
    expect(readers[0].handleSafe).toHaveBeenCalledTimes(1);
    expect(readers[0].handleSafe.mock.calls[0][0].credentials).toEqual({});
    compareMaps(readers[0].handleSafe.mock.calls[0][0].accessMap,
      new IdentifierMap([[{ path: joinUrl(baseUrl, 'first') }, new Set() ]]));

    expect(readers[1].handleSafe).toHaveBeenCalledTimes(1);
    expect(readers[1].handleSafe.mock.calls[0][0].credentials).toEqual({});
    compareMaps(readers[1].handleSafe.mock.calls[0][0].accessMap,
      new IdentifierMap([[{ path: joinUrl(baseUrl, 'second') }, new Set() ]]));
  });
});

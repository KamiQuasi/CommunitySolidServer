import { CredentialGroup } from '../../../src/authentication/Credentials';
import { AuxiliaryReader } from '../../../src/authorization/AuxiliaryReader';
import type { PermissionReaderInput, PermissionReader } from '../../../src/authorization/PermissionReader';
import type { AccessMap, PermissionMap, PermissionSet } from '../../../src/authorization/permissions/Permissions';
import { AccessMode, IdentifierMap } from '../../../src/authorization/permissions/Permissions';
import type { AuxiliaryStrategy } from '../../../src/http/auxiliary/AuxiliaryStrategy';
import type { ResourceIdentifier } from '../../../src/http/representation/ResourceIdentifier';
import { mapIterable } from '../../../src/util/IterableUtil';
import { compareMaps } from '../../util/Util';

describe('An AuxiliaryReader', (): void => {
  const suffix1 = '.dummy1';
  const suffix2 = '.dummy2';
  const credentials = {};
  const modes = new Set<AccessMode>([ AccessMode.delete ]);
  const subjectIdentifier = { path: 'http://test.com/foo' };
  const auxiliaryIdentifier1 = { path: 'http://test.com/foo.dummy1' };
  const auxiliaryIdentifier2 = { path: 'http://test.com/foo.dummy2' };
  const permissionSet: PermissionSet = { [CredentialGroup.agent]: { read: true }};
  let source: jest.Mocked<PermissionReader>;
  let strategy: jest.Mocked<AuxiliaryStrategy>;
  let reader: AuxiliaryReader;

  function handleSafe({ accessMap }: PermissionReaderInput): PermissionMap {
    return new IdentifierMap(mapIterable(accessMap.keys(), (identifier): [ResourceIdentifier, PermissionSet] =>
      [ identifier, permissionSet ]));
  }

  beforeEach(async(): Promise<void> => {
    source = {
      handleSafe: jest.fn(handleSafe),
    } as any;

    strategy = {
      isAuxiliaryIdentifier: jest.fn((identifier: ResourceIdentifier): boolean =>
        identifier.path.endsWith(suffix1) || identifier.path.endsWith(suffix2)),
      getSubjectIdentifier: jest.fn((identifier: ResourceIdentifier): ResourceIdentifier =>
        ({ path: identifier.path.slice(0, -suffix1.length) })),
      usesOwnAuthorization: jest.fn().mockReturnValue(false),
    } as any;
    reader = new AuxiliaryReader(source, strategy);
  });

  it('directly calls the source if no changes are required.', async(): Promise<void> => {
    const accessMap: AccessMap = new IdentifierMap([
      [ subjectIdentifier, modes ],
    ]);
    const permissionMap: PermissionMap = new IdentifierMap([
      [ subjectIdentifier, permissionSet ],
    ]);
    compareMaps(await reader.handle({ credentials, accessMap }), permissionMap);
    expect(source.handleSafe).toHaveBeenLastCalledWith({ credentials, accessMap });
  });

  it('handles resources by sending the updated parameters to the source.', async(): Promise<void> => {
    const accessMap: AccessMap = new IdentifierMap([
      [ auxiliaryIdentifier1, modes ],
      [{ path: 'http://example.com/other' }, new Set() ],
    ]);
    const permissionMap: PermissionMap = new IdentifierMap([
      [ subjectIdentifier, permissionSet ],
      [{ path: 'http://example.com/other' }, permissionSet ],
      [ auxiliaryIdentifier1, permissionSet ],
    ]);
    compareMaps(await reader.handle({ credentials, accessMap }), permissionMap);
    expect(source.handleSafe.mock.calls[0][0].credentials).toBe(credentials);
    expect(source.handleSafe.mock.calls[0][0].accessMap.get(subjectIdentifier)).toBe(modes);
    expect(source.handleSafe.mock.calls[0][0].accessMap.get({ path: 'http://example.com/other' })).toEqual(new Set());
    expect(source.handleSafe.mock.calls[0][0].accessMap.size).toBe(2);
  });

  it('applies an empty PermissionSet if no permissions were found for the subject.', async(): Promise<void> => {
    source.handleSafe.mockResolvedValueOnce(new IdentifierMap());
    const accessMap: AccessMap = new IdentifierMap([
      [ auxiliaryIdentifier1, modes ],
    ]);
    const permissionMap: PermissionMap = new IdentifierMap([
      [ auxiliaryIdentifier1, {}],
    ]);
    compareMaps(await reader.handle({ credentials, accessMap }), permissionMap);
  });

  it('combines modes if multiple different auxiliary resources have the same subject.', async(): Promise<void> => {
    const accessMap: AccessMap = new IdentifierMap([
      [ auxiliaryIdentifier1, new Set<AccessMode>([ AccessMode.write ]) ],
      [ auxiliaryIdentifier2, new Set<AccessMode>([ AccessMode.read ]) ],
      [ subjectIdentifier, new Set<AccessMode>([ AccessMode.delete ]) ],
    ]);
    const resultSet = { [CredentialGroup.agent]: { read: true, write: true, delete: true }};
    source.handleSafe.mockResolvedValueOnce(new IdentifierMap([[ subjectIdentifier, resultSet ]]));
    const permissionMap: PermissionMap = new IdentifierMap([
      [ subjectIdentifier, resultSet ],
      [ auxiliaryIdentifier1, resultSet ],
      [ auxiliaryIdentifier2, resultSet ],
    ]);
    compareMaps(await reader.handle({ credentials, accessMap }), permissionMap);
    expect(source.handleSafe.mock.calls[0][0].accessMap.get(subjectIdentifier))
      .toEqual(new Set([ AccessMode.write, AccessMode.read, AccessMode.delete ]));
  });
});

import type { CredentialSet } from '../../../src/authentication/Credentials';
import type { PermissionReader } from '../../../src/authorization/PermissionReader';
import { AclMode } from '../../../src/authorization/permissions/AclPermission';
import type { AccessMap, PermissionMap, PermissionSet } from '../../../src/authorization/permissions/Permissions';
import { AccessMode, IdentifierMap } from '../../../src/authorization/permissions/Permissions';
import { WebAclAuxiliaryReader } from '../../../src/authorization/WebAclAuxiliaryReader';
import type { AuxiliaryStrategy } from '../../../src/http/auxiliary/AuxiliaryStrategy';
import type { ResourceIdentifier } from '../../../src/http/representation/ResourceIdentifier';
import { joinUrl } from '../../../src/util/PathUtil';
import { compareMaps } from '../../util/Util';

describe('A WebAclAuxiliaryReader', (): void => {
  const baseUrl = 'http://example.com/';
  const subject1 = { path: joinUrl(baseUrl, 'foo/') };
  const acl1 = { path: joinUrl(subject1.path, '.acl') };
  const subject2 = { path: joinUrl(baseUrl, 'bar/') };
  const acl2 = { path: joinUrl(subject2.path, '.acl') };
  const credentials: CredentialSet = { public: {}};
  let accessMap: AccessMap;
  let sourceResult: PermissionMap;
  let aclStrategy: jest.Mocked<AuxiliaryStrategy>;
  let source: jest.Mocked<PermissionReader>;
  let reader: WebAclAuxiliaryReader;

  beforeEach(async(): Promise<void> => {
    accessMap = new IdentifierMap();

    sourceResult = new IdentifierMap();

    aclStrategy = {
      isAuxiliaryIdentifier: jest.fn((identifier): boolean => identifier.path.endsWith('.acl')),
      getSubjectIdentifier: jest.fn((identifier): ResourceIdentifier => ({ path: identifier.path.slice(0, -4) })),
    } as any;

    source = { handleSafe: jest.fn().mockResolvedValue(sourceResult) } as any;
    reader = new WebAclAuxiliaryReader(source, aclStrategy);
  });

  it('calls the source directly if no changes are required.', async(): Promise<void> => {
    await expect(reader.handle({ accessMap, credentials })).resolves.toBe(sourceResult);
    expect(source.handleSafe).toHaveBeenCalledTimes(1);
    expect(source.handleSafe).toHaveBeenLastCalledWith({ accessMap, credentials });
    expect(source.handleSafe.mock.calls[0][0].accessMap).toBe(accessMap);
  });

  it('requires control permissions on the subject resource to do everything.', async(): Promise<void> => {
    accessMap.set(acl1, new Set([ AccessMode.read ]));
    accessMap.set(acl2, new Set([ AccessMode.read ]));
    sourceResult.set(subject1, { public: { control: true }} as PermissionSet);

    const result = await reader.handle({ accessMap, credentials });
    expect(result.get(acl1)).toEqual({ public: { read: true, append: true, write: true, control: true }});
    expect(result.get(acl2)).toEqual({ });

    const updatedMap = new IdentifierMap();
    updatedMap.set(subject1, new Set([ AclMode.control ]));
    updatedMap.set(subject2, new Set([ AclMode.control ]));
    expect(source.handleSafe).toHaveBeenCalledTimes(1);
    expect(source.handleSafe.mock.calls[0][0].credentials).toBe(credentials);
    compareMaps(source.handleSafe.mock.calls[0][0].accessMap, updatedMap);
  });

  it('combines the modes with the subject resource if it is also being requested.', async(): Promise<void> => {
    accessMap.set(acl1, new Set([ AccessMode.read ]));
    accessMap.set(subject1, new Set([ AccessMode.write ]));

    const resultSet = { public: { read: true, write: true, control: true }} as PermissionSet;
    sourceResult.set(subject1, resultSet);
    const resultMap: PermissionMap = new IdentifierMap([
      [ acl1, { public: { read: true, write: true, control: true, append: true }} as PermissionSet ],
      [ subject1, resultSet ],
    ]);
    compareMaps(await reader.handle({ credentials, accessMap }), resultMap);
    expect(source.handleSafe.mock.calls[0][0].accessMap.get(subject1))
      .toEqual(new Set([ AccessMode.write, AclMode.control ]));
  });
});

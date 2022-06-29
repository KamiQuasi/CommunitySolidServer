import type { CredentialSet } from '../../../src/authentication/Credentials';
import { ParentContainerReader } from '../../../src/authorization/ParentContainerReader';
import type { PermissionReader } from '../../../src/authorization/PermissionReader';
import type { AccessMap, PermissionMap } from '../../../src/authorization/permissions/Permissions';
import { AccessMode, IdentifierMap } from '../../../src/authorization/permissions/Permissions';
import { SingleRootIdentifierStrategy } from '../../../src/util/identifiers/SingleRootIdentifierStrategy';
import { joinUrl } from '../../../src/util/PathUtil';
import { compareMaps } from '../../util/Util';

describe('A ParentContainerReader', (): void => {
  const baseUrl = 'http://example.com/';
  const parent1 = { path: joinUrl(baseUrl, 'foo/') };
  const target1 = { path: joinUrl(parent1.path, 'foo') };
  const parent2 = { path: joinUrl(baseUrl, 'bar/') };
  const target2 = { path: joinUrl(parent2.path, 'bar') };
  const parent3 = { path: joinUrl(baseUrl, 'baz/') };
  const target3 = { path: joinUrl(parent3.path, 'baz') };
  const credentials: CredentialSet = { public: {}};
  let accessMap: AccessMap;
  let sourceResult: PermissionMap;
  const identifierStrategy = new SingleRootIdentifierStrategy(baseUrl);
  let source: jest.Mocked<PermissionReader>;
  let reader: ParentContainerReader;

  beforeEach(async(): Promise<void> => {
    accessMap = new IdentifierMap();

    sourceResult = new IdentifierMap([[{ path: joinUrl(baseUrl, 'test') }, { public: { read: true }}]]);

    source = { handleSafe: jest.fn().mockResolvedValue(sourceResult) } as any;
    reader = new ParentContainerReader(source, identifierStrategy);
  });

  it('calls the source directly if no changes are required.', async(): Promise<void> => {
    await expect(reader.handle({ accessMap, credentials })).resolves.toBe(sourceResult);
    expect(source.handleSafe).toHaveBeenCalledTimes(1);
    expect(source.handleSafe).toHaveBeenLastCalledWith({ accessMap, credentials });
    expect(source.handleSafe.mock.calls[0][0].accessMap).toBe(accessMap);
  });

  it('requires parent append permissions to create resources.', async(): Promise<void> => {
    accessMap.set(target1, new Set([ AccessMode.create ]));
    accessMap.set(target2, new Set([ AccessMode.create ]));
    sourceResult.set(parent1, { public: { append: true }});

    const result = await reader.handle({ accessMap, credentials });
    expect(result.get(target1)).toEqual({ public: { create: true }});
    expect(result.get(target2)).toEqual({ });

    const updatedMap = new IdentifierMap(accessMap);
    updatedMap.set(parent1, new Set([ AccessMode.append ]));
    updatedMap.set(parent2, new Set([ AccessMode.append ]));
    expect(source.handleSafe).toHaveBeenCalledTimes(1);
    expect(source.handleSafe.mock.calls[0][0].credentials).toBe(credentials);
    compareMaps(source.handleSafe.mock.calls[0][0].accessMap, updatedMap);
  });

  it('requires write and parent write permissions to delete resources.', async(): Promise<void> => {
    accessMap.set(target1, new Set([ AccessMode.delete ]));
    accessMap.set(target2, new Set([ AccessMode.delete ]));
    accessMap.set(target3, new Set([ AccessMode.delete ]));
    sourceResult.set(parent1, { public: { write: true }});
    sourceResult.set(parent2, { public: { write: true }});
    sourceResult.set(target1, { public: { write: true }});
    sourceResult.set(target3, { public: { write: true }});

    const result = await reader.handle({ accessMap, credentials });
    expect(result.get(target1)).toEqual({ public: { delete: true, write: true }});
    expect(result.get(target2)).toEqual({ public: {}});
    expect(result.get(target3)).toEqual({ public: { write: true }});

    const updatedMap = new IdentifierMap(accessMap);
    updatedMap.set(parent1, new Set([ AccessMode.write ]));
    updatedMap.set(parent2, new Set([ AccessMode.write ]));
    updatedMap.set(parent3, new Set([ AccessMode.write ]));
    expect(source.handleSafe).toHaveBeenCalledTimes(1);
    expect(source.handleSafe.mock.calls[0][0].credentials).toBe(credentials);
    compareMaps(source.handleSafe.mock.calls[0][0].accessMap, updatedMap);
  });

  it('does not allow create/delete if the source explicitly forbids it.', async(): Promise<void> => {
    accessMap.set(target1, new Set([ AccessMode.create, AccessMode.delete ]));
    accessMap.set(target2, new Set([ AccessMode.create, AccessMode.delete ]));
    sourceResult.set(parent1, { public: { write: true, append: true }});
    sourceResult.set(parent2, { public: { write: true, append: true }});
    sourceResult.set(target1, { public: { write: true }});
    sourceResult.set(target2, { public: { write: true, create: false, delete: false }});

    const result = await reader.handle({ accessMap, credentials });
    expect(result.get(target1)).toEqual({ public: { write: true, create: true, delete: true }});
    expect(result.get(target2)).toEqual({ public: { write: true, create: false, delete: false }});

    const updatedMap = new IdentifierMap(accessMap);
    updatedMap.set(parent1, new Set([ AccessMode.write, AccessMode.append ]));
    updatedMap.set(parent2, new Set([ AccessMode.write, AccessMode.append ]));
    expect(source.handleSafe).toHaveBeenCalledTimes(1);
    expect(source.handleSafe.mock.calls[0][0].credentials).toBe(credentials);
    compareMaps(source.handleSafe.mock.calls[0][0].accessMap, updatedMap);
  });

  it('combines the modes with the parent resource if it is also being requested.', async(): Promise<void> => {
    accessMap.set(target1, new Set([ AccessMode.create ]));
    accessMap.set(parent1, new Set([ AccessMode.write ]));
    sourceResult.set(parent1, { public: { write: true, append: true }});
    sourceResult.set(target1, { public: { write: true }});

    const result = await reader.handle({ accessMap, credentials });
    expect(result.get(target1)).toEqual({ public: { write: true, create: true, delete: true }});
    expect(result.get(parent1)).toEqual({ public: { write: true, append: true }});

    const updatedMap = new IdentifierMap(accessMap);
    updatedMap.set(parent1, new Set([ AccessMode.write, AccessMode.append ]));
    expect(source.handleSafe).toHaveBeenCalledTimes(1);
    expect(source.handleSafe.mock.calls[0][0].credentials).toBe(credentials);
    compareMaps(source.handleSafe.mock.calls[0][0].accessMap, updatedMap);
    expect(source.handleSafe.mock.calls[0][0].accessMap.get(parent1))
      .toEqual(new Set([ AccessMode.write, AccessMode.append ]));
  });
});

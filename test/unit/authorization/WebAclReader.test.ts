import { DataFactory } from 'n3';
import type { CredentialSet } from '../../../src/authentication/Credentials';
import { CredentialGroup } from '../../../src/authentication/Credentials';
import type { AccessChecker } from '../../../src/authorization/access/AccessChecker';
import type { PermissionReaderInput } from '../../../src/authorization/PermissionReader';
import { AclMode } from '../../../src/authorization/permissions/AclPermission';
import type { AccessMap, PermissionSet } from '../../../src/authorization/permissions/Permissions';
import { AccessMode, IdentifierMap } from '../../../src/authorization/permissions/Permissions';
import { WebAclReader } from '../../../src/authorization/WebAclReader';
import type { AuxiliaryIdentifierStrategy } from '../../../src/http/auxiliary/AuxiliaryIdentifierStrategy';
import { BasicRepresentation } from '../../../src/http/representation/BasicRepresentation';
import type { Representation } from '../../../src/http/representation/Representation';
import type { ResourceIdentifier } from '../../../src/http/representation/ResourceIdentifier';
import type { ResourceStore } from '../../../src/storage/ResourceStore';
import { INTERNAL_QUADS } from '../../../src/util/ContentTypes';
import { ForbiddenHttpError } from '../../../src/util/errors/ForbiddenHttpError';
import { InternalServerError } from '../../../src/util/errors/InternalServerError';
import { NotFoundHttpError } from '../../../src/util/errors/NotFoundHttpError';
import { SingleRootIdentifierStrategy } from '../../../src/util/identifiers/SingleRootIdentifierStrategy';
import { guardedStreamFrom } from '../../../src/util/StreamUtil';
import { compareMaps } from '../../util/Util';

const { namedNode: nn, quad } = DataFactory;

const acl = 'http://www.w3.org/ns/auth/acl#';
const rdf = 'http://www.w3.org/1999/02/22-rdf-syntax-ns#';

describe('A WebAclReader', (): void => {
  let reader: WebAclReader;
  const aclStrategy: AuxiliaryIdentifierStrategy = {
    getAuxiliaryIdentifier: (id: ResourceIdentifier): ResourceIdentifier => ({ path: `${id.path}.acl` }),
    isAuxiliaryIdentifier: (id: ResourceIdentifier): boolean => id.path.endsWith('.acl'),
    getSubjectIdentifier: (id: ResourceIdentifier): ResourceIdentifier => ({ path: id.path.slice(0, -4) }),
  } as any;
  let store: jest.Mocked<ResourceStore>;
  const identifierStrategy = new SingleRootIdentifierStrategy('http://example.com/');
  let credentials: CredentialSet;
  let identifier: ResourceIdentifier;
  let modes: Set<AccessMode>;
  let accessMap: AccessMap;
  let input: PermissionReaderInput;
  let accessChecker: jest.Mocked<AccessChecker>;

  beforeEach(async(): Promise<void> => {
    credentials = { [CredentialGroup.public]: {}, [CredentialGroup.agent]: {}};
    identifier = { path: 'http://example.com/foo' };

    modes = new Set<AccessMode | AclMode>([
      AccessMode.read, AccessMode.write, AccessMode.append, AclMode.control,
    ]) as Set<AccessMode>;

    accessMap = new IdentifierMap([[ identifier, modes ]]);

    input = { credentials, accessMap };

    store = {
      getRepresentation: jest.fn().mockResolvedValue(new BasicRepresentation([
        quad(nn('auth'), nn(`${rdf}type`), nn(`${acl}Authorization`)),
      ], INTERNAL_QUADS)),
    } as any;

    accessChecker = {
      handleSafe: jest.fn().mockResolvedValue(true),
    } as any;

    reader = new WebAclReader(aclStrategy, store, identifierStrategy, accessChecker);
  });

  it('handles all input.', async(): Promise<void> => {
    await expect(reader.canHandle({ } as any)).resolves.toBeUndefined();
  });

  it('returns undefined permissions for undefined credentials.', async(): Promise<void> => {
    input.credentials = {};
    compareMaps(await reader.handle(input), new IdentifierMap([[ identifier, {
      [CredentialGroup.public]: {},
      [CredentialGroup.agent]: {},
    }]]));
  });

  it('reads the accessTo value of the acl resource.', async(): Promise<void> => {
    credentials.agent = { webId: 'http://test.com/user' };
    store.getRepresentation.mockResolvedValue({ data: guardedStreamFrom([
      quad(nn('auth'), nn(`${rdf}type`), nn(`${acl}Authorization`)),
      quad(nn('auth'), nn(`${acl}accessTo`), nn(identifier.path)),
      quad(nn('auth'), nn(`${acl}mode`), nn(`${acl}Read`)),
    ]) } as Representation);
    compareMaps(await reader.handle(input), new IdentifierMap([[ identifier, {
      [CredentialGroup.public]: { read: true },
      [CredentialGroup.agent]: { read: true },
    }]]));
  });

  it('ignores accessTo fields pointing to different resources.', async(): Promise<void> => {
    credentials.agent = { webId: 'http://test.com/user' };
    store.getRepresentation.mockResolvedValue({ data: guardedStreamFrom([
      quad(nn('auth'), nn(`${rdf}type`), nn(`${acl}Authorization`)),
      quad(nn('auth'), nn(`${acl}accessTo`), nn('somewhereElse')),
      quad(nn('auth'), nn(`${acl}mode`), nn(`${acl}Read`)),
    ]) } as Representation);
    compareMaps(await reader.handle(input), new IdentifierMap([[ identifier, {
      [CredentialGroup.public]: {},
      [CredentialGroup.agent]: {},
    }]]));
  });

  it('handles all valid modes and ignores other ones.', async(): Promise<void> => {
    credentials.agent = { webId: 'http://test.com/user' };
    store.getRepresentation.mockResolvedValue({ data: guardedStreamFrom([
      quad(nn('auth'), nn(`${rdf}type`), nn(`${acl}Authorization`)),
      quad(nn('auth'), nn(`${acl}accessTo`), nn(identifier.path)),
      quad(nn('auth'), nn(`${acl}mode`), nn(`${acl}Read`)),
      quad(nn('auth'), nn(`${acl}mode`), nn(`${acl}fakeMode1`)),
    ]) } as Representation);
    compareMaps(await reader.handle(input), new IdentifierMap([[ identifier, {
      [CredentialGroup.public]: { read: true },
      [CredentialGroup.agent]: { read: true },
    }]]));
  });

  it('reads the default value of a parent if there is no direct acl resource.', async(): Promise<void> => {
    store.getRepresentation.mockImplementation(async(id: ResourceIdentifier): Promise<Representation> => {
      if (id.path.endsWith('foo.acl')) {
        throw new NotFoundHttpError();
      }
      return new BasicRepresentation([
        quad(nn('auth'), nn(`${rdf}type`), nn(`${acl}Authorization`)),
        quad(nn('auth'), nn(`${acl}agentClass`), nn('http://xmlns.com/foaf/0.1/Agent')),
        quad(nn('auth'), nn(`${acl}default`), nn(identifierStrategy.getParentContainer(identifier).path)),
        quad(nn('auth'), nn(`${acl}mode`), nn(`${acl}Read`)),
      ], INTERNAL_QUADS);
    });
    compareMaps(await reader.handle(input), new IdentifierMap([[ identifier, {
      [CredentialGroup.public]: { read: true },
      [CredentialGroup.agent]: { read: true },
    }]]));
  });

  it('does not use default authorizations for the resource itself.', async(): Promise<void> => {
    store.getRepresentation.mockImplementation(async(): Promise<Representation> =>
      new BasicRepresentation([
        quad(nn('auth'), nn(`${rdf}type`), nn(`${acl}Authorization`)),
        quad(nn('auth'), nn(`${acl}agentClass`), nn('http://xmlns.com/foaf/0.1/Agent')),
        quad(nn('auth'), nn(`${acl}default`), nn(identifier.path)),
        quad(nn('auth'), nn(`${acl}mode`), nn(`${acl}Read`)),
        quad(nn('auth2'), nn(`${rdf}type`), nn(`${acl}Authorization`)),
        quad(nn('auth2'), nn(`${acl}agentClass`), nn('http://xmlns.com/foaf/0.1/Agent')),
        quad(nn('auth2'), nn(`${acl}accessTo`), nn(identifier.path)),
        quad(nn('auth2'), nn(`${acl}mode`), nn(`${acl}Append`)),
      ], INTERNAL_QUADS));
    compareMaps(await reader.handle(input), new IdentifierMap([[ identifier, {
      [CredentialGroup.public]: { append: true },
      [CredentialGroup.agent]: { append: true },
    }]]));
  });

  it('re-throws ResourceStore errors as internal errors.', async(): Promise<void> => {
    store.getRepresentation.mockRejectedValue(new Error('TEST!'));
    const promise = reader.handle(input);
    await expect(promise).rejects.toThrow(`Error reading ACL for ${identifier.path}: TEST!`);
    await expect(promise).rejects.toThrow(InternalServerError);
  });

  it('errors if the root container has no corresponding acl document.', async(): Promise<void> => {
    store.getRepresentation.mockRejectedValue(new NotFoundHttpError());
    const promise = reader.handle(input);
    await expect(promise).rejects.toThrow('No ACL document found for root container');
    await expect(promise).rejects.toThrow(ForbiddenHttpError);
  });

  it('ignores rules where no access is granted.', async(): Promise<void> => {
    credentials.agent = { webId: 'http://test.com/user' };
    // CredentialGroup.public gets true on auth1, CredentialGroup.agent on auth2
    accessChecker.handleSafe.mockImplementation(async({ rule, credential: cred }): Promise<boolean> =>
      (rule.value === 'auth1') === !cred.webId);

    store.getRepresentation.mockResolvedValue({ data: guardedStreamFrom([
      quad(nn('auth1'), nn(`${rdf}type`), nn(`${acl}Authorization`)),
      quad(nn('auth1'), nn(`${acl}accessTo`), nn(identifier.path)),
      quad(nn('auth1'), nn(`${acl}mode`), nn(`${acl}Read`)),
      quad(nn('auth2'), nn(`${rdf}type`), nn(`${acl}Authorization`)),
      quad(nn('auth2'), nn(`${acl}accessTo`), nn(identifier.path)),
      quad(nn('auth2'), nn(`${acl}mode`), nn(`${acl}Append`)),
    ]) } as Representation);

    compareMaps(await reader.handle(input), new IdentifierMap<PermissionSet>([[ identifier, {
      [CredentialGroup.public]: { read: true },
      [CredentialGroup.agent]: { append: true },
    }]]));
  });

  it('combines ACL requests for resources when possible.', async(): Promise<void> => {
    const identifier2 = { path: 'http://example.com/bar/' };
    const identifier3 = { path: 'http://example.com/bar/baz' };

    store.getRepresentation.mockImplementation(async(id: ResourceIdentifier): Promise<Representation> => {
      if (id.path === 'http://example.com/.acl') {
        return new BasicRepresentation([
          quad(nn('auth'), nn(`${rdf}type`), nn(`${acl}Authorization`)),
          quad(nn('auth'), nn(`${acl}agentClass`), nn('http://xmlns.com/foaf/0.1/Agent')),
          quad(nn('auth'), nn(`${acl}default`), nn('http://example.com/')),
          quad(nn('auth'), nn(`${acl}mode`), nn(`${acl}Read`)),
        ], INTERNAL_QUADS);
      }
      if (id.path === 'http://example.com/bar/.acl') {
        return new BasicRepresentation([
          quad(nn('auth'), nn(`${rdf}type`), nn(`${acl}Authorization`)),
          quad(nn('auth'), nn(`${acl}agentClass`), nn('http://xmlns.com/foaf/0.1/Agent')),
          quad(nn('auth'), nn(`${acl}default`), nn(identifier2.path)),
          quad(nn('auth'), nn(`${acl}mode`), nn(`${acl}Append`)),
          quad(nn('auth2'), nn(`${rdf}type`), nn(`${acl}Authorization`)),
          quad(nn('auth2'), nn(`${acl}agentClass`), nn('http://xmlns.com/foaf/0.1/Agent')),
          quad(nn('auth2'), nn(`${acl}accessTo`), nn(identifier2.path)),
          quad(nn('auth2'), nn(`${acl}mode`), nn(`${acl}Read`)),
        ], INTERNAL_QUADS);
      }
      throw new NotFoundHttpError();
    });

    // Adding them in this specific order to make sure all cases trigger when looking for the longest identifier
    input.accessMap.set(identifier3, new Set());
    input.accessMap.set(identifier2, new Set());

    compareMaps(await reader.handle(input), new IdentifierMap([
      [ identifier2, { [CredentialGroup.public]: { read: true }, [CredentialGroup.agent]: { read: true }}],
      [ identifier3, { [CredentialGroup.public]: { append: true }, [CredentialGroup.agent]: { append: true }}],
      [ identifier, { [CredentialGroup.public]: { read: true }, [CredentialGroup.agent]: { read: true }}],
    ]));
    // http://example.com/foo.acl (404), http://example.com/.acl (200),
    // http://example.com/bar/baz.acl (404), http://example.com/bar/.acl (200)
    expect(store.getRepresentation).toHaveBeenCalledTimes(4);
  });
});

import { CredentialGroup } from '../../../src/authentication/Credentials';
import type { CredentialsExtractor } from '../../../src/authentication/CredentialsExtractor';
import type { Authorizer } from '../../../src/authorization/Authorizer';
import type { PermissionReader } from '../../../src/authorization/PermissionReader';
import type { ModesExtractor } from '../../../src/authorization/permissions/ModesExtractor';
import type { AccessMap, PermissionMap } from '../../../src/authorization/permissions/Permissions';
import { AccessMode, IdentifierMap } from '../../../src/authorization/permissions/Permissions';
import type { Operation } from '../../../src/http/Operation';
import { BasicRepresentation } from '../../../src/http/representation/BasicRepresentation';
import { AuthorizingHttpHandler } from '../../../src/server/AuthorizingHttpHandler';
import type { HttpRequest } from '../../../src/server/HttpRequest';
import type { HttpResponse } from '../../../src/server/HttpResponse';
import type { OperationHttpHandler } from '../../../src/server/OperationHttpHandler';
import { ForbiddenHttpError } from '../../../src/util/errors/ForbiddenHttpError';

describe('An AuthorizingHttpHandler', (): void => {
  const credentials = { [CredentialGroup.public]: {}};
  const target = { path: 'http://test.com/foo' };
  const accessMap: AccessMap = new IdentifierMap([[ target, new Set([ AccessMode.read ]) ]]);
  const permissionMap: PermissionMap = new IdentifierMap([[ target, { [CredentialGroup.public]: { read: true }}]]);
  const request: HttpRequest = {} as any;
  const response: HttpResponse = {} as any;
  let operation: Operation;
  let credentialsExtractor: jest.Mocked<CredentialsExtractor>;
  let modesExtractor: jest.Mocked<ModesExtractor>;
  let permissionReader: jest.Mocked<PermissionReader>;
  let authorizer: jest.Mocked<Authorizer>;
  let source: jest.Mocked<OperationHttpHandler>;
  let handler: AuthorizingHttpHandler;

  beforeEach(async(): Promise<void> => {
    operation = {
      target,
      method: 'GET',
      preferences: {},
      body: new BasicRepresentation(),
    };

    credentialsExtractor = {
      handleSafe: jest.fn().mockResolvedValue(credentials),
    } as any;
    modesExtractor = {
      handleSafe: jest.fn().mockResolvedValue(accessMap),
    } as any;
    permissionReader = {
      handleSafe: jest.fn().mockResolvedValue(permissionMap),
    } as any;
    authorizer = {
      handleSafe: jest.fn(),
    } as any;
    source = {
      handleSafe: jest.fn(),
    } as any;

    handler = new AuthorizingHttpHandler(
      { credentialsExtractor, modesExtractor, permissionReader, authorizer, operationHandler: source },
    );
  });

  it('goes through all the steps and calls the source.', async(): Promise<void> => {
    await expect(handler.handle({ request, response, operation })).resolves.toBeUndefined();
    expect(credentialsExtractor.handleSafe).toHaveBeenCalledTimes(1);
    expect(credentialsExtractor.handleSafe).toHaveBeenLastCalledWith(request);
    expect(modesExtractor.handleSafe).toHaveBeenCalledTimes(1);
    expect(modesExtractor.handleSafe).toHaveBeenLastCalledWith(operation);
    expect(permissionReader.handleSafe).toHaveBeenCalledTimes(1);
    expect(permissionReader.handleSafe).toHaveBeenLastCalledWith(
      { credentials, accessMap },
    );
    expect(authorizer.handleSafe).toHaveBeenCalledTimes(1);
    expect(authorizer.handleSafe).toHaveBeenLastCalledWith(
      { credentials, accessMap, permissionMap },
    );
    expect(source.handleSafe).toHaveBeenCalledTimes(1);
    expect(source.handleSafe).toHaveBeenLastCalledWith({ request, response, operation });
    expect(operation.permissionMap).toBe(permissionMap);
  });

  it('errors if authorization fails.', async(): Promise<void> => {
    const error = new ForbiddenHttpError();
    authorizer.handleSafe.mockRejectedValueOnce(error);
    await expect(handler.handle({ request, response, operation })).rejects.toThrow(error);
    expect(source.handleSafe).toHaveBeenCalledTimes(0);
  });
});

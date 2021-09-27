import { AsyncHandler } from '../../util/handlers/AsyncHandler';
import type { Operation } from '../operations/Operation';
import type { AccessMode } from './PermissionSet';

export abstract class ModesExtractor extends AsyncHandler<Operation, Set<AccessMode>> {}
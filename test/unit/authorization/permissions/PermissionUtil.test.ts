import { AccessMode, IdentifierMap } from '../../../../src/authorization/permissions/Permissions';
import { addAccessModes, updateAccessMap } from '../../../../src/authorization/permissions/PermissionUtil';
import { compareMaps } from '../../../util/Util';

describe('PermissionUtil', (): void => {
  const identifier1 = { path: 'http://example.com/foo' };
  const identifier2 = { path: 'http://example.com/bar' };
  const identifier3 = { path: 'http://example.com/baz' };

  describe('#addAccessModes', (): void => {
    it('adds the values if there was no entry yet.', async(): Promise<void> => {
      const map = new IdentifierMap([[ identifier1, new Set([ AccessMode.read ]) ]]);
      addAccessModes(identifier2, new Set([ AccessMode.write ]), map);
      compareMaps(map, new IdentifierMap([
        [ identifier1, new Set([ AccessMode.read ]) ],
        [ identifier2, new Set([ AccessMode.write ]) ],
      ]));
    });

    it('merges values if there was an entry.', async(): Promise<void> => {
      const map = new IdentifierMap([[ identifier1, new Set([ AccessMode.read ]) ]]);
      addAccessModes(identifier1, new Set([ AccessMode.write ]), map);
      compareMaps(map, new IdentifierMap([
        [ identifier1, new Set([ AccessMode.read, AccessMode.write ]) ],
      ]));
    });
  });

  describe('#updateAccessMap', (): void => {
    it('updates the map as specified.', async(): Promise<void> => {
      const map = new IdentifierMap([
        [ identifier1, new Set([ AccessMode.read ]) ],
        [ identifier2, new Set([ AccessMode.write ]) ],
      ]);
      const add = new IdentifierMap([
        [ identifier1, new Set([ AccessMode.append ]) ],
        [ identifier3, new Set([ AccessMode.delete ]) ],
      ]);
      const remove = new Set([ identifier2 ]);

      const expected = new IdentifierMap([
        [ identifier1, new Set([ AccessMode.read, AccessMode.append ]) ],
        [ identifier3, new Set([ AccessMode.delete ]) ],
      ]);

      compareMaps(updateAccessMap(add, remove, map), expected);
    });
  });
});

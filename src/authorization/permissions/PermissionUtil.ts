import type { ResourceIdentifier } from '../../http/representation/ResourceIdentifier';
import type { MapEntry } from '../../util/IterableUtil';
import { concatIterables } from '../../util/IterableUtil';
import { IdentifierMap } from './Permissions';
import type { AccessMap, AccessMode } from './Permissions';

/**
 * Adds the provided access `modes` to the given `accessMap` for the given `identifier`.
 * If the map already has modes for the identifier, these will be merged.
 *
 * @param identifier - Identifier to add modes for.
 * @param modes - Modes to add.
 * @param accessMap - Map in which to add the modes.
 */
export function addAccessModes(identifier: ResourceIdentifier, modes: Set<AccessMode>, accessMap: AccessMap): void {
  const storedModes = accessMap.get(identifier);
  if (storedModes) {
    accessMap.set(identifier, new Set(concatIterables([ modes, storedModes ])));
  } else {
    accessMap.set(identifier, modes);
  }
}

/**
 * Creates a new {@link AccessMap} by starting from a list of entries.
 * Calls {@link addAccessModes} when adding entries from the `add` iterable to prevent colissions.
 *
 * @param add - Additional entries to add.
 * @param remove - Entries to remove from the given `mapEntries`.
 * @param mapEntries - Iterable of entries to start from.
 */
export function updateAccessMap(add: Iterable<MapEntry<AccessMap>>, remove: Set<ResourceIdentifier>,
  mapEntries: Iterable<MapEntry<AccessMap>>): AccessMap {
  const result: AccessMap = new IdentifierMap();
  for (const [ identifier, modes ] of mapEntries) {
    if (!remove.has(identifier)) {
      result.set(identifier, modes);
    }
  }
  for (const [ identifier, modes ] of add) {
    addAccessModes(identifier, modes, result);
  }
  return result;
}

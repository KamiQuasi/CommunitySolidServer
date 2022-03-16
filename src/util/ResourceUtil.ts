import arrayifyStream from 'arrayify-stream';
import { DataFactory } from 'n3';
import { BasicRepresentation } from '../http/representation/BasicRepresentation';
import type { Representation } from '../http/representation/Representation';
import { RepresentationMetadata } from '../http/representation/RepresentationMetadata';
import type { ResourceIdentifier } from '../http/representation/ResourceIdentifier';
import type { ResourceStore } from '../storage/ResourceStore';
import type { IdentifierStrategy } from './identifiers/IdentifierStrategy';
import { guardedStreamFrom } from './StreamUtil';
import { toLiteral } from './TermUtil';
import { CONTENT_TYPE_TERM, DC, LDP, PIM, RDF, SOLID_META, XSD } from './Vocabularies';
import namedNode = DataFactory.namedNode;

/**
 * Helper function to generate type quads for a Container or Resource.
 * @param metadata - Metadata to add to.
 * @param isContainer - If the identifier corresponds to a container.
 *
 * @returns The generated quads.
 */
export function addResourceMetadata(metadata: RepresentationMetadata, isContainer: boolean): void {
  if (isContainer) {
    metadata.add(RDF.terms.type, LDP.terms.Container);
    metadata.add(RDF.terms.type, LDP.terms.BasicContainer);
  }
  metadata.add(RDF.terms.type, LDP.terms.Resource);
}

/**
 * Updates the dc:modified time to the given time.
 * @param metadata - Metadata to update.
 * @param date - Last modified date. Defaults to current time.
 */
export function updateModifiedDate(metadata: RepresentationMetadata, date = new Date()): void {
  // Milliseconds get lost in some serializations, potentially causing mismatches
  const lastModified = new Date(date);
  lastModified.setMilliseconds(0);
  metadata.set(DC.terms.modified, toLiteral(lastModified.toISOString(), XSD.terms.dateTime));
}

/**
 * Links a template file with a given content-type to the metadata using the SOLID_META.template predicate.
 * @param metadata - Metadata to update.
 * @param templateFile - Path to the template.
 * @param contentType - Content-type of the template after it is rendered.
 */
export function addTemplateMetadata(metadata: RepresentationMetadata, templateFile: string, contentType: string):
void {
  const templateNode = namedNode(templateFile);
  metadata.add(SOLID_META.terms.template, templateNode);
  metadata.addQuad(templateNode, CONTENT_TYPE_TERM, contentType);
}

/**
 * Helper function to clone a representation, the original representation can still be used.
 * This function loads the entire stream in memory.
 * @param representation - The representation to clone.
 *
 * @returns The cloned representation.
 */
export async function cloneRepresentation(representation: Representation): Promise<BasicRepresentation> {
  const data = await arrayifyStream(representation.data);
  const result = new BasicRepresentation(
    data,
    new RepresentationMetadata(representation.metadata),
    representation.binary,
  );
  representation.data = guardedStreamFrom(data);
  return result;
}

/**
 * Finds the root storage container of the given identifier.
 * Returns undefined if no match was found due to there not being a storage or the identifier not being in scope.
 * @param identifier - Identifier of which to find the containing storage.
 * @param store - Store in which the parent containers can be found.
 * @param strategy - Strategy used to find the parent container of a resource.
 */
export async function findStorage(identifier: ResourceIdentifier, store: ResourceStore, strategy: IdentifierStrategy): Promise<ResourceIdentifier | undefined> {
  try {
    const representation = await store.getRepresentation(identifier, {});
    representation.data.destroy();
    if (representation.metadata.has(RDF.terms.type, PIM.terms.Storage)) {
      return identifier;
    }
    const parent = strategy.getParentContainer(identifier);
    return findStorage(parent, store, strategy);
  } catch {
    // Ignore errors
  }
}

import { parse } from 'cookie';
import { DataFactory } from 'n3';
import type { NamedNode } from 'rdf-js';
import type { HttpRequest } from '../../../server/HttpRequest';
import type { RepresentationMetadata } from '../../representation/RepresentationMetadata';
import { MetadataParser } from './MetadataParser';
import namedNode = DataFactory.namedNode;

// TODO: name/uri
export class CookieParser extends MetadataParser {
  private readonly cookieMap: Record<string, NamedNode>;

  public constructor(cookieMap: Record<string, string>) {
    super();
    // TODO: very similar to LinkRelParser
    this.cookieMap = Object.fromEntries(
      Object.entries(cookieMap).map(([ header, uri ]): [string, NamedNode] => [ header, namedNode(uri) ]),
    );
  }

  public async handle(input: { request: HttpRequest; metadata: RepresentationMetadata }): Promise<void> {
    const cookies = parse(input.request.headers.cookie ?? '');
    for (const [ name, uri ] of Object.entries(this.cookieMap)) {
      const value = cookies[name];
      if (value) {
        input.metadata.add(uri, value);
      }
    }
  }
}

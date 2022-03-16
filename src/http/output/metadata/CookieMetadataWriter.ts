import { serialize } from 'cookie';
import type { NamedNode } from 'n3';
import { DataFactory } from 'n3';
import type { HttpResponse } from '../../../server/HttpResponse';
import { addHeader } from '../../../util/HeaderUtil';
import type { RepresentationMetadata } from '../../representation/RepresentationMetadata';
import { MetadataWriter } from './MetadataWriter';

// TODO: uri/name
export class CookieMetadataWriter extends MetadataWriter {
  private readonly cookieMap: Map<NamedNode, string>;

  public constructor(cookieMap: Record<string, string>) {
    super();
    // TODO: similar to linkrelmetadatawriter
    this.cookieMap = new Map<NamedNode, string>();
    for (const [ key, value ] of Object.entries(cookieMap)) {
      this.cookieMap.set(DataFactory.namedNode(key), value);
    }
  }

  public async handle(input: { response: HttpResponse; metadata: RepresentationMetadata }): Promise<void> {
    const { response, metadata } = input;
    for (const [ uri, name ] of this.cookieMap.entries()) {
      const value = metadata.get(uri)?.value;
      if (value) {
        // Not setting secure flag since not all tools realize those cookies are also valid for http://localhost.
        // Not setting the httpOnly flag as that would make API access more difficult.
        // Setting the path to `/` so it applies to the entire server.
        addHeader(response, 'Set-Cookie', serialize(name, value, { path: '/', sameSite: 'lax' }));
      }
    }
  }
}

export type ReplayableRequest = {
  withMaterial(material: string, target?: URL, methodOverride?: string): Request;
};

type RequestInitWithDuplex = RequestInit & { duplex?: "half" };

function replaceEvery(value: string, sentinel: string, material: string): string {
  return value.split(sentinel).join(material);
}

export async function snapshotRequest(
  input: RequestInfo | URL,
  init: RequestInit | undefined,
  sentinel: string,
): Promise<ReplayableRequest> {
  const source = new Request(input, init);
  const body = source.body ? await source.arrayBuffer() : undefined;
  const method = source.method;
  const signal = source.signal;
  const headers = new Headers(source.headers);
  const duplex = (source as Request & { duplex?: "half" }).duplex;

  return {
    withMaterial(material: string, target?: URL, methodOverride?: string): Request {
      const url = new URL(target ?? source.url);
      const encodedSentinel = encodeURIComponent(sentinel);
      const encodedMaterial = encodeURIComponent(material);
      const query = url.search.slice(1);
      url.search = query
        .split("&")
        .map((part) => part.includes(sentinel)
          ? replaceEvery(part, sentinel, encodedMaterial)
          : replaceEvery(part, encodedSentinel, encodedMaterial))
        .join("&");

      const substitutedHeaders = new Headers();
      for (const [name, value] of headers) {
        substitutedHeaders.set(name, replaceEvery(value, sentinel, material));
      }
      if (methodOverride === "GET") {
        // RFC 9110 representation and payload headers describe a body this replay omits.
        substitutedHeaders.delete("content-length");
        substitutedHeaders.delete("content-type");
        substitutedHeaders.delete("content-encoding");
        substitutedHeaders.delete("transfer-encoding");
        substitutedHeaders.delete("content-language");
        substitutedHeaders.delete("content-location");
      }
      if (url.toString().includes(sentinel) || [...substitutedHeaders.values()].some((value) => value.includes(sentinel))) {
        throw new Error("custody sentinel remains in a forwarded request");
      }

      const requestInit: RequestInitWithDuplex = {
        method: methodOverride ?? method,
        headers: substitutedHeaders,
        redirect: "manual",
        signal,
        cache: source.cache,
        credentials: source.credentials,
        integrity: source.integrity,
        keepalive: source.keepalive,
        mode: source.mode,
        referrer: source.referrer,
        referrerPolicy: source.referrerPolicy,
        ...(body === undefined || methodOverride === "GET" ? {} : { body: body.slice(0) }),
        ...(duplex === undefined ? {} : { duplex }),
      };
      return new Request(url, requestInit);
    },
  };
}

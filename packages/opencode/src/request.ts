export type ReplayableRequest = {
  withMaterial(material: string, target?: URL, methodOverride?: string): Request;
};

type RequestInitWithDuplex = RequestInit & { duplex?: "half" };

function replaceEvery(value: string, sentinel: string, material: string): string {
  return value.split(sentinel).join(material);
}

// A query value can carry the sentinel in a case the encoded form produces: `encodeURIComponent`
// uppercases hex digits, but `decodeURIComponent` is case-insensitive, so a host or proxy that
// re-encodes with lowercase hex (`%3av1` instead of `%3Av1`) would let the tombstone slip
// past the raw substitution. Per-param: decode the value, compare to the sentinel,
// substitute, then re-encode ONLY that value with `encodeURIComponent`. Untouched params
// stay byte-identical (a non-substitution cannot change their bytes).
function substituteQueryValue(value: string, sentinel: string, encodedMaterial: string): string {
  let decoded: string;
  try {
    decoded = decodeURIComponent(value);
  } catch {
    return replaceEvery(value, sentinel, encodedMaterial);
  }
  if (decoded === sentinel) return encodedMaterial;
  return value;
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
      const substitutedQuery = query
        .split("&")
        .map((part) => {
          const separator = part.indexOf("=");
          if (separator === -1) return part;
          const name = part.slice(0, separator);
          const value = part.slice(separator + 1);
          // Per-param substitution: decode, compare to the canonical sentinel,
          // re-encode only when the decoded value matches. Untouched values are
          // returned byte-for-byte; the inner `replaceEvery` defends against the
          // sentinel appearing unencoded inside a value that ALSO matches one of
          // its percent-escaped forms.
          const substituted = substituteQueryValue(value, sentinel, encodedMaterial);
          if (substituted === value) {
            return `${name}=${replaceEvery(replaceEvery(value, sentinel, encodedMaterial), encodedSentinel, encodedMaterial)}`;
          }
          return `${name}=${substituted}`;
        })
        .join("&");
      url.search = substitutedQuery;

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
      if (
        `${url.origin}${url.pathname}${url.hash}`.includes(sentinel) ||
        substitutedQuery.split("&").some((part) => {
          const separator = part.indexOf("=");
          return separator !== -1 && part.slice(separator + 1).includes(sentinel);
        }) ||
        [...substitutedHeaders.values()].some((value) => value.includes(sentinel))
      ) {
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

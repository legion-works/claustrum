import { CustodyRequestError } from "./errors";

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
    return caseInsensitiveReplace(value, sentinel, encodedMaterial);
  }
  if (decoded === sentinel) return encodedMaterial;
  // Even when the decoded form is not the bare sentinel (e.g. the value carries
  // `prefix-<encoded sentinel>-suffix`), a host that unescaped percent-hex would
  // observe the sentinel as a substring. Apply the substitution against the
  // case-insensitive encoded form too, so neither `claustrum-tombstone%3Av1%3A...`
  // nor `claustrum-tombstone%3av1%3a...` survives a round trip.
  return caseInsensitiveReplace(value, sentinel, encodedMaterial);
}

// Replaces occurrences of `sentinel` and a case-insensitively-spelled percent
// encoding of `sentinel` in `value` with `encodedMaterial`. Falls back to a
// `replaceEvery` of the literal sentinel when encoding cannot be computed (e.g.
// the sentinel contains a string that the `encodeURIComponent`-then-lower regex
// disagrees on, which is rare; the literal pass keeps coverage of the by-hand
// substitution path in that case).
function caseInsensitiveReplace(value: string, sentinel: string, encodedMaterial: string): string {
  const substituted = value.split(sentinel).join(encodedMaterial);
  const encodedSentinel = encodeURIComponent(sentinel);
  if (encodedSentinel === sentinel) return substituted;
  // The encoded form MUST survive unescaping to the sentinel; an upstream that
  // matches the decoded form against an allowlist would accept either %3A or %3a.
  // Case-insensitive flag handles both hex casings since ASCII letters case-fold.
  const re = new RegExp(escapeForRegex(encodedSentinel), "gi");
  return substituted.replace(re, encodedMaterial);
}

function escapeForRegex(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
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
      // The pathname and hash branch is checked AFTER `decodeURIComponent` so a host
      // that unescapes percent-hex before matching the URL against its allowlist sees
      // the same refusal that the raw-bytes check would. The substitution step above
      // already covers the bytes; this is the belt-and-braces refusal.
      const decodedPathOrigin = `${url.origin}${decodeURIComponent(url.pathname)}${decodeURIComponent(url.hash)}`;
      if (
        decodedPathOrigin.includes(sentinel) ||
        substitutedQuery.split("&").some((part) => {
          const separator = part.indexOf("=");
          if (separator === -1) return false;
          const raw = part.slice(separator + 1);
          if (raw.includes(sentinel)) return true;
          try {
            if (decodeURIComponent(raw).includes(sentinel)) return true;
          } catch {
            // Already covered by the `raw.includes` arm; fall through.
          }
          return false;
        }) ||
        [...substitutedHeaders.values()].some((value) => value.includes(sentinel))
      ) {
        // The error carries a structured `code` so callers and tests can branch on the
        // refusal without parsing `message`. The string rendered into the operator log
        // (and the wrapper's `message`) is whatever the serve path chose -- NOT this
        // literal -- so a future change that adds context here cannot silently widen
        // what the upstream-fetch catch renders.
        throw new CustodyRequestError("custody sentinel remains in a forwarded request", {
          code: "sentinel_in_request",
        });
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

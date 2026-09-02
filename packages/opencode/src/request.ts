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
// encoding of `sentinel` in `value` with `encodedMaterial`. Only the hex digits inside
// `%XX` may case-fold (an upstream that re-encoded with lowercase hex would otherwise
// let the sentinel slip past raw substitution); the sentinel's own letters must match
// EXACTLY, so an ordinary query value that differs only by letter case is forwarded
// untouched instead of being rewritten with vault material.
function caseInsensitiveReplace(value: string, sentinel: string, encodedMaterial: string): string {
  const substituted = value.split(sentinel).join(encodedMaterial);
  const encodedSentinel = encodeURIComponent(sentinel);
  if (encodedSentinel === sentinel) return substituted;
  return substituted.replace(encodedSentinelHexInsensitiveRegex(encodedSentinel), encodedMaterial);
}

// Builds a regex for `encodedSentinel` that matches the literal sentinel letters
// EXACTLY but accepts either case for the hex digits inside each `%XX` escape.
// Without this, an `i`-flagged regex would also case-fold the sentinel's own
// letters and rewrite an unrelated query value into vault material.
function encodedSentinelHexInsensitiveRegex(encodedSentinel: string): RegExp {
  let pattern = "";
  let i = 0;
  while (i < encodedSentinel.length) {
    if (encodedSentinel[i] === "%" && i + 2 < encodedSentinel.length) {
      const hex = encodedSentinel.slice(i + 1, i + 3);
      if (/^[0-9A-Fa-f]{2}$/.test(hex)) {
        const c1 = hex[0];
        const c2 = hex[1];
        const v1 = /[A-Fa-f]/.test(c1) ? `[${c1.toLowerCase()}${c1.toUpperCase()}]` : c1;
        const v2 = /[A-Fa-f]/.test(c2) ? `[${c2.toLowerCase()}${c2.toUpperCase()}]` : c2;
        pattern += `%${v1}${v2}`;
        i += 3;
        continue;
      }
    }
    pattern += escapeChar(encodedSentinel[i]);
    i += 1;
  }
  return new RegExp(pattern, "g");
}

function escapeChar(value: string): string {
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

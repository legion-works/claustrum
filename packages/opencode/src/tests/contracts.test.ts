import { describe, expect, test } from "bun:test";
import { goldenTombstone } from "../contracts";
import { isProviderTombstone, TOMBSTONE_PREFIX, tombstoneFor } from "../tombstone";
import { parseHandleFile } from "../handles";
import goldenHandles from "../../golden/handles.json";

describe("custody wire contracts", () => {
  test("api golden stays a valid OpenCode ApiAuth entry", () => {
    const fixture = goldenTombstone.fixtures.api;
    expect(fixture.entry.type).toBe("api");
    expect(isProviderTombstone(fixture.entry, fixture.provider)).toBe(true);
  });

  test("oauth golden stays a valid OpenCode OAuth entry", () => {
    const fixture = goldenTombstone.fixtures.oauth;
    expect(fixture.entry.type).toBe("oauth");
    expect(isProviderTombstone(fixture.entry, fixture.provider)).toBe(true);
  });

  test("tombstone rendering is byte-stable for a provider", () => {
    const api = goldenTombstone.fixtures.api;
    const oauth = goldenTombstone.fixtures.oauth;
    expect(tombstoneFor("api", api.provider)).toEqual(api.entry);
    expect(tombstoneFor("oauth", oauth.provider)).toEqual(oauth.entry);
    expect(isProviderTombstone(tombstoneFor("api", "deepseek"), "anthropic")).toBe(false);
  });

  test("tombstone prefix remains pinned to the golden provider key", () => {
    const fixture = goldenTombstone.fixtures.api;
    if (fixture.entry.type !== "api") throw new Error("api golden changed shape");
    expect(TOMBSTONE_PREFIX + fixture.provider).toBe(fixture.entry.key);
  });

  test("handle schema preserves declared provider and account order", () => {
    const source = parseHandleFile(goldenHandles);
    const parsed = parseHandleFile(JSON.parse(JSON.stringify(source)));
    expect(parsed).toEqual(source);
    expect(parsed.providers.map((provider) => provider.provider)).toEqual(["deepseek", "anthropic"]);
    expect(parsed.providers[0]?.accounts.map((account) => account.label)).toEqual(["main", "backup"]);
    expect(parsed.providers[0]?.accounts[0]?.handle).toBe("ckh_deepseek_main");
    expect(parsed.providers[0]?.accounts[1]?.superseded).toEqual(["ckh_deepseek_prior"]);
    expect(() =>
      parseHandleFile({
        version: 1,
        providers: [{ provider: "deepseek", shape: "api", accounts: [] }],
      }),
    ).toThrow("serve");
  });
});

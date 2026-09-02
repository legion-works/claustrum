import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import type { GoldenTombstone } from "../contracts";
import { isProviderTombstone, TOMBSTONE_PREFIX, tombstoneFor } from "../tombstone";
import { parseHandleFile } from "../handles";
import goldenHandles from "../../golden/handles.json";
import goldenTombstoneJson from "../../golden/tombstone.json";

const goldenTombstone = goldenTombstoneJson as GoldenTombstone;

describe("custody wire contracts", () => {
  test("loads the canonical tombstone golden rather than a copied fixture", () => {
    expect(goldenTombstone).toEqual(JSON.parse(readFileSync(join(import.meta.dir, "../../golden/tombstone.json"), "utf8")));
  });
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
    // The golden carries base64url-shaped handles (mixed case, `-`, `_`) on purpose: the vault
    // mints 256 CSPRNG bits as base64url, and a reader that derives its charset from an
    // all-lowercase fixture would reject real handles.
    expect(parsed.providers[0]?.accounts[0]?.handle).toBe("ckh_xOHjn5GYlYiTcwEqIt0DDVGaZR3eTdcwzpOEXuTdvsw");
    expect(parsed.providers[0]?.accounts[1]?.superseded).toEqual(["ckh_MNZO_t_aIvzhQ19mAskh44KtKxJE5NbOm4ul6A1kqpY"]);
    for (const provider of parsed.providers) {
      for (const account of provider.accounts) {
        for (const handle of [account.handle, ...(account.superseded ?? [])]) {
          expect(handle).toMatch(/^ckh_[A-Za-z0-9_-]{43}$/);
        }
      }
    }
    expect(goldenHandles.providers.flatMap((p) => p.accounts.map((a) => a.handle)).join("")).toMatch(/[A-Z]/);
    expect(goldenHandles.providers.flatMap((p) => p.accounts.map((a) => a.handle)).join("")).toMatch(/[-_]/);
    expect(() =>
      parseHandleFile({
        version: 1,
        providers: [{ provider: "deepseek", shape: "api", serve: "opencode-claustrum", accounts: [] }],
      }),
    ).toThrow("accounts");
    expect(() =>
      parseHandleFile({
        version: 1,
        providers: [{
          provider: "deepseek",
          shape: "api",
          serve: "opencode-claustrum",
          accounts: [{ label: "main", handle: `ckh_${"a".repeat(42)}!`, credential_id: "apikey:deepseek:main" }],
        }],
      }),
    ).toThrow("invalid handle");
  });
});

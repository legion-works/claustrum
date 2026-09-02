import { describe, expect, test } from "bun:test";
import { goldenTombstone } from "../contracts";
import { isProviderTombstone, tombstoneFor } from "../tombstone";
import { parseHandleFile, type OpenCodeHandleFileV1 } from "../handles";

describe("custody wire contracts", () => {
  test("api golden stays a valid OpenCode ApiAuth entry", () => {
    const fixture = goldenTombstone.fixtures.api;
    expect(fixture.entry).toEqual({
      type: "api",
      key: "claustrum-tombstone:v1:deepseek",
    });
    expect(isProviderTombstone(fixture.entry, fixture.provider)).toBe(true);
  });

  test("oauth golden stays a valid OpenCode OAuth entry", () => {
    const fixture = goldenTombstone.fixtures.oauth;
    expect(fixture.entry).toEqual({
      type: "oauth",
      refresh: "claustrum-tombstone:v1:anthropic",
      access: "claustrum-tombstone:v1:anthropic",
      expires: 0,
    });
    expect(isProviderTombstone(fixture.entry, fixture.provider)).toBe(true);
  });

  test("tombstone rendering is byte-stable for a provider", () => {
    expect(tombstoneFor("api", "deepseek")).toEqual({
      type: "api",
      key: "claustrum-tombstone:v1:deepseek",
    });
    expect(tombstoneFor("oauth", "anthropic")).toEqual({
      type: "oauth",
      refresh: "claustrum-tombstone:v1:anthropic",
      access: "claustrum-tombstone:v1:anthropic",
      expires: 0,
    });
    expect(isProviderTombstone(tombstoneFor("api", "deepseek"), "anthropic")).toBe(false);
  });

  test("handle schema preserves declared provider and account order", () => {
    const source: OpenCodeHandleFileV1 = {
      version: 1,
      providers: [
        {
          provider: "deepseek",
          shape: "api",
          serve: "opencode-claustrum",
          accounts: [
            { label: "primary", handle: "h-1", credential_id: "c-1" },
            { label: "backup", handle: "h-2", credential_id: "c-2" },
          ],
        },
        {
          provider: "anthropic",
          shape: "oauth",
          serve: "other-plugin",
          accounts: [{ label: "only", handle: "h-3", credential_id: "c-3" }],
        },
      ],
    };
    const parsed = parseHandleFile(JSON.parse(JSON.stringify(source)));
    expect(parsed).toEqual(source);
    expect(() =>
      parseHandleFile({
        version: 1,
        providers: [{ provider: "deepseek", shape: "api", accounts: [] }],
      }),
    ).toThrow("serve");
  });
});

import { describe, expect, test } from "bun:test";
import { existsSync } from "node:fs";
import { join } from "node:path";

// The plugin bundle OpenCode actually loads is `dist/opencode-plugin.js`, produced by
// `bun build` overwriting the tsc output. Every other test imports from `src/`; without
// this test, the bundled artifact is never exercised and a runtime failure (e.g. how
// `@cortexkit/claustrum-client` or its `@cortexkit/subc-client` dependency gets inlined)
// ships green. The `bun run build` step in `bun run test:hermetic` precedes this test;
// it must skip LOUDLY if `dist/` is absent — never silently pass.
const DIST_PATH = join(import.meta.dir, "..", "..", "dist", "opencode-plugin.js");

type ShippedPlugin = { default?: { id?: unknown; server?: unknown } };

async function loadShipped(): Promise<ShippedPlugin> {
  if (!existsSync(DIST_PATH)) {
    throw new Error(
      `shipped plugin bundle missing at ${DIST_PATH}; run 'bun run build' before the hermetic suite. ` +
        `Tests that exercise the built artifact must skip LOUDLY, never silently pass — that is the ` +
        `invariant this file exists to enforce.`,
    );
  }
  return (await import(DIST_PATH)) as ShippedPlugin;
}

describe("shipped OpenCode custody plugin bundle", () => {
  test("imports the built plugin and exposes the OpenCode v1 entrypoint", async () => {
    const module = await loadShipped();
    expect(module.default?.id).toBe("opencode-claustrum");
    expect(typeof module.default?.server).toBe("function");
  });
});

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import type { OpenCodeHandleFileV1 } from "./handles";
import type { OpenCodeAuthEntry } from "./tombstone";

export type GoldenTombstone = {
  version: 1;
  fixtures: {
    api: { provider: string; entry: OpenCodeAuthEntry };
    oauth: { provider: string; entry: OpenCodeAuthEntry };
  };
};

const goldenPath = join(dirname(fileURLToPath(import.meta.url)), "..", "golden", "tombstone.json");
export const goldenTombstone = JSON.parse(readFileSync(goldenPath, "utf8")) as GoldenTombstone;
export type { OpenCodeHandleFileV1 };

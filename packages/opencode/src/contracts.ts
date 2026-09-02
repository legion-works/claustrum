import golden from "../golden/tombstone.json";

import type { OpenCodeHandleFileV1 } from "./handles";
import type { OpenCodeAuthEntry } from "./tombstone";

export type GoldenTombstone = {
  version: 1;
  fixtures: {
    api: { provider: string; entry: OpenCodeAuthEntry };
    oauth: { provider: string; entry: OpenCodeAuthEntry };
  };
};

export const goldenTombstone = golden as unknown as GoldenTombstone;
export type { OpenCodeHandleFileV1 };

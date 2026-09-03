// A bounded descriptor read that closes the TOCTOU window a stat-then-readFile
// pair leaves open. Reads into a `cap + 1` buffer; one byte past the cap is
// rejected before the descriptor is consumed. Real `FileHandle` (node:fs/promises)
// exposes `read()`; tests inject one to simulate a writer that grows the file
// between fstat and read. Used by both plugin.ts (auth) and handles.ts (handle
// file) — the loop body is identical, only the cap differs.
export type BoundedReadResult = { bytesRead: number };
export type BoundedReadDescriptor = {
  read?(buffer: Uint8Array, offset: number, length: number, position: number): BoundedReadResult | Promise<BoundedReadResult>;
};

export async function readBounded(fd: BoundedReadDescriptor, cap: number): Promise<{ buffer: Buffer; bytes: number }> {
  if (!fd.read) throw new Error("readBounded requires a descriptor exposing read()");
  const buffer = Buffer.alloc(cap + 1);
  let total = 0;
  while (total < cap + 1) {
    const chunk = await fd.read(buffer, total, buffer.length - total, total);
    if (chunk.bytesRead === 0) break;
    total += chunk.bytesRead;
  }
  if (total > cap) return { buffer, bytes: -1 };
  return { buffer, bytes: total };
}

export function boundedBytesText(bytes: number, buffer: Buffer): string {
  return buffer.subarray(0, bytes).toString("utf8");
}

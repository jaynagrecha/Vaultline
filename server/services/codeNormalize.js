/**
 * Light text normalize before format:
 * UTF-8 decode, strip BOM/nulls, CRLF → LF.
 */

export function isLikelyBinary(buffer) {
  if (!Buffer.isBuffer(buffer)) return false;
  const sample = buffer.subarray(0, Math.min(buffer.length, 8192));
  let weird = 0;
  for (const b of sample) {
    if (b === 0) return true;
    if (b < 7 || (b > 13 && b < 32 && b !== 27)) weird += 1;
  }
  return weird / sample.length > 0.3;
}

/**
 * @returns {{ text: string | null, binary: boolean, changed: boolean }}
 */
export function normalizeCodeBuffer(buffer) {
  if (!Buffer.isBuffer(buffer)) {
    buffer = Buffer.from(String(buffer ?? ""), "utf8");
  }
  if (isLikelyBinary(buffer)) {
    return { text: null, binary: true, changed: false };
  }
  let text;
  try {
    text = new TextDecoder("utf-8", { fatal: false }).decode(buffer);
  } catch {
    return { text: null, binary: true, changed: false };
  }
  const original = text;
  // Strip UTF-8 BOM
  if (text.charCodeAt(0) === 0xfeff) text = text.slice(1);
  // Strip NUL bytes (platform anomalies)
  if (text.includes("\u0000")) text = text.replace(/\u0000/g, "");
  // Normalize newlines
  text = text.replace(/\r\n/g, "\n").replace(/\r/g, "\n");
  // Strip trailing spaces on lines (light tidy, not a full format)
  text = text
    .split("\n")
    .map((line) => line.replace(/[ \t]+$/g, ""))
    .join("\n");
  // Ensure trailing newline for code files (POSIX)
  if (text.length && !text.endsWith("\n")) text += "\n";
  return { text, binary: false, changed: text !== original };
}

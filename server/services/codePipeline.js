import { detectCodeLanguage } from "./codeDetect.js";
import { normalizeCodeBuffer } from "./codeNormalize.js";
import { formatCode } from "./codeFormat.js";
import { lintCode } from "./codeLint.js";

/**
 * Full pipeline for text-like uploads/saves:
 * detect → normalize → format (if code) → lint.
 *
 * @returns {Promise<{
 *   buffer: Buffer,
 *   binary: boolean,
 *   language: string,
 *   label: string,
 *   isCode: boolean,
 *   formatStatus: string,
 *   formatError: string | null,
 *   diagnostics: import('./codeLint.js').Diagnostic[],
 *   changed: boolean
 * }>}
 */
export async function processCodeContent({ filename, buffer, format = true }) {
  const normalized = normalizeCodeBuffer(buffer);
  if (normalized.binary || normalized.text == null) {
    return {
      buffer,
      binary: true,
      language: "plaintext",
      label: "Binary",
      isCode: false,
      formatStatus: "n/a",
      formatError: null,
      diagnostics: [],
      changed: false,
    };
  }

  const detected = detectCodeLanguage(filename, normalized.text);
  let text = normalized.text;
  let formatStatus = normalized.changed ? "normalized" : "skipped";
  let formatError = null;
  let changed = normalized.changed;

  if (format && detected.isCode) {
    const formatted = await formatCode(text, detected.language);
    if (formatted.status === "formatted" && formatted.text !== text) {
      text = formatted.text;
      formatStatus = "formatted";
      changed = true;
    } else if (formatted.status === "failed") {
      formatStatus = "failed";
      formatError = formatted.error || "format failed";
    } else if (formatted.status === "formatted") {
      formatStatus = "formatted";
    } else if (formatStatus !== "normalized") {
      formatStatus = formatted.status;
    }
  }

  const diagnostics = detected.isCode ? lintCode(text, detected.language) : [];

  return {
    buffer: Buffer.from(text, "utf8"),
    binary: false,
    language: detected.language,
    label: detected.label,
    isCode: detected.isCode,
    formatStatus,
    formatError,
    diagnostics,
    changed,
  };
}

export function lintText(filename, text) {
  const detected = detectCodeLanguage(filename, text);
  return {
    language: detected.language,
    label: detected.label,
    isCode: detected.isCode,
    diagnostics: detected.isCode ? lintCode(text, detected.language) : [],
  };
}

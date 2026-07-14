import prettier from "prettier";
import * as prettierBabel from "prettier/plugins/babel";
import * as prettierEstree from "prettier/plugins/estree";
import * as prettierTypescript from "prettier/plugins/typescript";
import * as prettierHtml from "prettier/plugins/html";
import * as prettierPostcss from "prettier/plugins/postcss";
import * as prettierMarkdown from "prettier/plugins/markdown";
import * as prettierYaml from "prettier/plugins/yaml";
import beautify from "js-beautify";
import { format as formatSql } from "sql-formatter";

/**
 * Brace / indent beautifier for languages without a solid Node formatter.
 * Does not rewrite semantics — only indentation + trim.
 */
function indentByBraces(text, { indent = "  ", hashComments = false } = {}) {
  const lines = text.replace(/\t/g, indent).split("\n");
  let level = 0;
  const out = [];
  for (let raw of lines) {
    let line = raw.replace(/[ \t]+$/g, "");
    const trimmed = line.trim();
    if (!trimmed) {
      out.push("");
      continue;
    }
    // Skip indent changes inside block comments roughly
    const isHash = hashComments && trimmed.startsWith("#");
    const closes = !isHash && /^[}\])]/.test(trimmed);
    if (closes) level = Math.max(0, level - 1);
    out.push(indent.repeat(level) + trimmed);
    const opens = !isHash && /[{[(]\s*$/.test(trimmed);
    const deltaOpen = (trimmed.match(/[{[(]/g) || []).length;
    const deltaClose = (trimmed.match(/[}\])]/g) || []).length;
    if (opens || deltaOpen > deltaClose) {
      level += Math.max(1, deltaOpen - deltaClose);
    } else if (!closes && deltaClose > deltaOpen) {
      level = Math.max(0, level - (deltaClose - deltaOpen));
    }
  }
  return out.join("\n").replace(/\n{3,}/g, "\n\n") + (text.endsWith("\n") ? "\n" : "");
}

function indentPython(text) {
  // Preserve relative indent; only expand tabs and trim trailing space.
  return (
    text
      .replace(/\t/g, "    ")
      .split("\n")
      .map((l) => l.replace(/[ \t]+$/g, ""))
      .join("\n")
      .replace(/\n{3,}/g, "\n\n") + (text.endsWith("\n") ? "" : "\n")
  );
}

async function runPrettier(text, parser, plugins) {
  return prettier.format(text, {
    parser,
    plugins,
    printWidth: 100,
    tabWidth: 2,
    semi: true,
    singleQuote: false,
    trailingComma: "es5",
    endOfLine: "lf",
  });
}

/**
 * @returns {Promise<{ text: string, status: 'formatted'|'skipped'|'failed', error?: string }>}
 */
export async function formatCode(text, language) {
  if (!text || language === "plaintext") {
    return { text, status: "skipped" };
  }
  try {
    switch (language) {
      case "javascript":
        return {
          text: await runPrettier(text, "babel", [prettierBabel, prettierEstree]),
          status: "formatted",
        };
      case "typescript":
        return {
          text: await runPrettier(text, "typescript", [prettierTypescript, prettierEstree]),
          status: "formatted",
        };
      case "json":
        return {
          text: await runPrettier(text, "json", [prettierBabel, prettierEstree]),
          status: "formatted",
        };
      case "html":
        return {
          text: await runPrettier(text, "html", [prettierHtml]),
          status: "formatted",
        };
      case "css":
      case "scss":
      case "less":
        return {
          text: await runPrettier(text, language === "css" ? "css" : language, [prettierPostcss]),
          status: "formatted",
        };
      case "markdown":
        return {
          text: await runPrettier(text, "markdown", [prettierMarkdown]),
          status: "formatted",
        };
      case "yaml":
        return {
          text: await runPrettier(text, "yaml", [prettierYaml]),
          status: "formatted",
        };
      case "sql":
        return {
          text: formatSql(text, { language: "sql", tabWidth: 2, keywordCase: "upper" }) + "\n",
          status: "formatted",
        };
      case "xml":
        return {
          text: beautify.html(text, {
            indent_size: 2,
            preserve_newlines: true,
            max_preserve_newlines: 2,
            end_with_newline: true,
          }),
          status: "formatted",
        };
      case "python":
        return { text: indentPython(text), status: "formatted" };
      case "shell":
      case "powershell":
      case "dockerfile":
        return {
          text: indentByBraces(text, { indent: "  ", hashComments: true }),
          status: "formatted",
        };
      case "c":
      case "cpp":
      case "csharp":
      case "java":
      case "go":
      case "rust":
      case "php":
        return { text: indentByBraces(text, { indent: "  " }), status: "formatted" };
      default:
        return { text, status: "skipped" };
    }
  } catch (e) {
    return { text, status: "failed", error: e.message || String(e) };
  }
}

import * as acorn from "acorn";
import { createRequire } from "node:module";
import YAML from "yaml";
import { XMLParser, XMLValidator } from "fast-xml-parser";

const require = createRequire(import.meta.url);
const ts = require("typescript");

/**
 * @typedef {{ severity: 'error'|'warning'|'info', message: string, line: number, column: number, source?: string }} Diagnostic
 */

const MAX_DIAGS = 80;

function posToLineCol(text, index) {
  const slice = text.slice(0, Math.max(0, index));
  const lines = slice.split("\n");
  return { line: lines.length, column: (lines[lines.length - 1] || "").length + 1 };
}

function diag(severity, message, line, column, source) {
  return {
    severity,
    message,
    line: Math.max(1, line || 1),
    column: Math.max(1, column || 1),
    source,
  };
}

function dedupe(diags) {
  const seen = new Set();
  const out = [];
  for (const d of diags) {
    if (!d || !d.message) continue;
    const key = `${d.severity}:${d.line}:${d.column}:${d.message}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(d);
    if (out.length >= MAX_DIAGS) break;
  }
  return out;
}

/**
 * Comment / string modes by language family.
 * @typedef {'c'|'hash'|'html'|'sql'|'none'} CommentStyle
 */

/**
 * Scan text with string/comment awareness.
 * @param {string} text
 * @param {{
 *   comments?: CommentStyle,
 *   onCodeChar?: (ch: string, i: number, line: number, col: number, ctx: object) => void,
 *   allowTemplate?: boolean,
 *   hashLineComments?: boolean,
 * }} opts
 */
function scanCode(text, opts = {}) {
  const comments = opts.comments || "c";
  const allowTemplate = opts.allowTemplate !== false;
  let line = 1;
  let col = 1;
  let inStr = null;
  let escape = false;
  let inLineComment = false;
  let inBlockComment = false;
  let inHtmlComment = false;
  const ctx = { inStr: () => inStr, inComment: () => inLineComment || inBlockComment || inHtmlComment };

  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    const next = text[i + 1];

    if (ch === "\n") {
      line += 1;
      col = 1;
      inLineComment = false;
      continue;
    }

    if (inHtmlComment) {
      if (ch === "-" && next === "-" && text[i + 2] === ">") {
        inHtmlComment = false;
        i += 2;
        col += 3;
        continue;
      }
      col += 1;
      continue;
    }

    if (inLineComment) {
      col += 1;
      continue;
    }

    if (inBlockComment) {
      if (comments === "sql" && ch === "*" && next === "/") {
        inBlockComment = false;
        i += 1;
        col += 2;
        continue;
      }
      if (comments === "c" && ch === "*" && next === "/") {
        inBlockComment = false;
        i += 1;
        col += 2;
        continue;
      }
      col += 1;
      continue;
    }

    if (inStr) {
      if (escape) {
        escape = false;
      } else if (ch === "\\") {
        escape = true;
      } else if (inStr === "'" && comments === "sql" && ch === "'" && next === "'") {
        i += 1;
        col += 2;
        continue;
      } else if (ch === inStr) {
        inStr = null;
      }
      col += 1;
      continue;
    }

    // Enter comments
    if (comments === "html" && ch === "<" && text.slice(i, i + 4) === "<!--") {
      inHtmlComment = true;
      i += 3;
      col += 4;
      continue;
    }
    if ((comments === "c" || comments === "sql") && ch === "/" && next === "*") {
      inBlockComment = true;
      i += 1;
      col += 2;
      continue;
    }
    if (comments === "c" && ch === "/" && next === "/") {
      inLineComment = true;
      i += 1;
      col += 2;
      continue;
    }
    if ((comments === "hash" || opts.hashLineComments) && ch === "#" && !(comments === "c")) {
      inLineComment = true;
      col += 1;
      continue;
    }
    if (comments === "sql" && ch === "-" && next === "-") {
      inLineComment = true;
      i += 1;
      col += 2;
      continue;
    }

    // Enter strings
    if (ch === '"' || ch === "'" || (allowTemplate && ch === "`")) {
      inStr = ch;
      col += 1;
      continue;
    }

    opts.onCodeChar?.(ch, i, line, col, ctx);
    col += 1;
  }

  return { line, col, inStr, inLineComment, inBlockComment, inHtmlComment };
}

/** Unmatched () [] {} with language-aware comments/strings. */
export function checkBrackets(text, { comments = "c", allowTemplate = true, source = "brackets" } = {}) {
  /** @type {Diagnostic[]} */
  const diags = [];
  const stack = [];
  const pairs = { ")": "(", "]": "[", "}": "{" };
  const opens = new Set(["(", "[", "{"]);

  const end = scanCode(text, {
    comments,
    allowTemplate,
    hashLineComments: comments === "hash",
    onCodeChar(ch, _i, line, col) {
      if (opens.has(ch)) stack.push({ ch, line, column: col });
      else if (pairs[ch]) {
        const top = stack.pop();
        if (!top || top.ch !== pairs[ch]) {
          diags.push(diag("error", `Unmatched '${ch}'`, line, col, source));
        }
      }
    },
  });

  if (end.inStr) {
    diags.push(diag("error", `Unclosed string literal (${end.inStr})`, end.line, end.col, source));
  }
  if (end.inBlockComment) {
    diags.push(diag("error", "Unclosed block comment", end.line, end.col, source));
  }
  if (end.inHtmlComment) {
    diags.push(diag("error", "Unclosed HTML comment <!--", end.line, end.col, source));
  }
  for (const left of stack) {
    diags.push(diag("error", `Unclosed '${left.ch}'`, left.line, left.column, source));
  }
  return diags;
}

function checkUnclosedQuotes(text, { comments = "c", allowTemplate = true } = {}) {
  return checkBrackets(text, { comments, allowTemplate }).filter((d) =>
    /Unclosed string|Unclosed block comment|Unclosed HTML comment/.test(d.message)
  );
}

// ——— JSON ———
function lintJson(text) {
  /** @type {Diagnostic[]} */
  const diags = [];
  const trimmed = text.trim();
  if (!trimmed) return [diag("error", "Empty JSON", 1, 1, "json")];
  try {
    JSON.parse(text);
  } catch (e) {
    const m = /position\s+(\d+)/i.exec(e.message || "");
    const idx = m ? Number(m[1]) : Math.max(0, trimmed.length - 1);
    const { line, column } = posToLineCol(text, idx);
    diags.push(diag("error", e.message || "Invalid JSON", line, column, "json"));
  }
  // Common footguns even when parse might partially succeed in other parsers
  if (/,\s*[}\]]/.test(text)) {
    const m = /,\s*[}\]]/.exec(text);
    const { line, column } = posToLineCol(text, m ? m.index : 0);
    // Only warn if JSON.parse already failed, or always as extra hint when failed
    if (diags.length) {
      diags.push(diag("warning", "Possible trailing comma before } or ]", line, column, "json"));
    }
  }
  if (/^\s*'/.test(trimmed) || /:\s*'/.test(text)) {
    diags.push(diag("warning", "JSON requires double quotes — single quotes are invalid", 1, 1, "json"));
  }
  return diags;
}

// ——— JavaScript ———
function lintJavaScript(text) {
  /** @type {Diagnostic[]} */
  const diags = [];
  const tryParse = (sourceType) => {
    acorn.parse(text, {
      ecmaVersion: "latest",
      sourceType,
      allowAwaitOutsideFunction: true,
      allowReturnOutsideFunction: true,
      allowImportExportEverywhere: true,
      locations: true,
    });
  };
  try {
    tryParse("module");
  } catch (e1) {
    try {
      tryParse("script");
    } catch (e2) {
      const e = e2.loc ? e2 : e1;
      diags.push(
        diag(
          "error",
          e.message || "JavaScript parse error",
          e.loc?.line || 1,
          e.loc?.column != null ? e.loc.column + 1 : 1,
          "acorn"
        )
      );
    }
  }
  // Duplicate bracket noise when acorn already reported — still useful if acorn passed
  if (!diags.length) {
    diags.push(...checkBrackets(text, { comments: "c" }).filter((d) => /Unclosed string|Unclosed block/.test(d.message)));
  } else {
    diags.push(...checkUnclosedQuotes(text));
  }
  return diags;
}

// ——— TypeScript ———
function lintTypeScript(text) {
  const result = ts.transpileModule(text, {
    compilerOptions: {
      target: ts.ScriptTarget.ESNext,
      module: ts.ModuleKind.ESNext,
      jsx: ts.JsxEmit.ReactJSX,
      strict: false,
    },
    reportDiagnostics: true,
    fileName: "file.tsx",
  });
  /** @type {Diagnostic[]} */
  const diags = (result.diagnostics || []).slice(0, MAX_DIAGS).map((d) => {
    const start = d.start ?? 0;
    let line = 1;
    let column = 1;
    if (d.file) {
      const lc = d.file.getLineAndCharacterOfPosition(start);
      line = lc.line + 1;
      column = lc.character + 1;
    } else {
      const lc = posToLineCol(text, start);
      line = lc.line;
      column = lc.column;
    }
    return diag(
      d.category === ts.DiagnosticCategory.Error ? "error" : "warning",
      ts.flattenDiagnosticMessageText(d.messageText, "\n"),
      line,
      column,
      "typescript"
    );
  });
  if (!diags.length) {
    diags.push(...checkUnclosedQuotes(text));
  }
  return diags;
}

// ——— YAML ———
function lintYaml(text) {
  try {
    YAML.parse(text, { strict: true, uniqueKeys: true });
    return [];
  } catch (e) {
    return [
      diag(
        "error",
        e.message || "Invalid YAML",
        e.linePos?.[0]?.line || e.line || 1,
        e.linePos?.[0]?.col || e.column || 1,
        "yaml"
      ),
    ];
  }
}

// ——— XML ———
function lintXml(text) {
  /** @type {Diagnostic[]} */
  const diags = [];
  const trimmed = text.trim();
  if (!trimmed) return [diag("error", "Empty XML", 1, 1, "xml")];

  const validated = XMLValidator.validate(text, {
    allowBooleanAttributes: true,
  });
  if (validated !== true) {
    const err = validated.err || {};
    diags.push(
      diag("error", err.msg || "Invalid XML", err.line || 1, err.col || 1, "xml")
    );
  } else {
    try {
      new XMLParser({
        ignoreAttributes: false,
        allowBooleanAttributes: true,
        processEntities: false,
      }).parse(text);
    } catch (e) {
      diags.push(diag("error", e.message || "Invalid XML", 1, 1, "xml"));
    }
  }
  diags.push(...checkHtmlMarkup(text, { structural: false }));
  return diags;
}

// ——— HTML markup (also used by PHP) ———
function checkHtmlMarkup(text, { structural = true } = {}) {
  /** @type {Diagnostic[]} */
  const diags = [];
  const lines = String(text).split("\n");
  let inPhp = false;
  let inScript = false;
  let inStyle = false;
  /** @type {{ name: string, line: number, column: number }[]} */
  const stack = [];
  const voidTags = new Set([
    "area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta",
    "param", "source", "track", "wbr",
  ]);

  for (let i = 0; i < lines.length; i++) {
    let line = lines[i];
    const lineNo = i + 1;

    // Strip PHP islands for HTML scanning on this line
    const phpParts = [];
    line = line.replace(/<\?(?:php|=)?[\s\S]*?(?:\?>|$)/gi, (m) => {
      phpParts.push(m);
      return " ".repeat(m.length);
    });

    const phpOpen = (lines[i].match(/<\?(?:php|=)?/gi) || []).length;
    const phpClose = (lines[i].match(/\?>/g) || []).length;
    if (phpOpen > phpClose) inPhp = true;
    if (phpClose >= phpOpen && phpClose) inPhp = false;
    // If line is entirely inside unclosed PHP block from before
    if (inPhp && phpOpen === 0) continue;

    if (/<script\b/i.test(lines[i]) && !/<\/script>/i.test(lines[i])) inScript = true;
    if (/<\/script>/i.test(lines[i])) inScript = false;
    if (/<style\b/i.test(lines[i]) && !/<\/style>/i.test(lines[i])) inStyle = true;
    if (/<\/style>/i.test(lines[i])) inStyle = false;
    if (inScript || inStyle) continue;

    if (/^\s*(class|id|style|href|src|name|type|value|width|height|alt|title|rel|target|action|method)\s*=/i.test(lines[i]) && lines[i].includes(">")) {
      diags.push(
        diag("error", "HTML attribute outside a tag — previous tag is likely incomplete", lineNo, 1, "html")
      );
    }

    let idx = 0;
    while (idx < line.length) {
      const start = line.indexOf("<", idx);
      if (start < 0) break;
      if (line.slice(start, start + 4) === "<!--") {
        const endC = line.indexOf("-->", start);
        if (endC < 0) {
          // maybe closes later
          let closed = false;
          for (let j = i + 1; j < Math.min(lines.length, i + 30); j++) {
            if (lines[j].includes("-->")) {
              closed = true;
              break;
            }
          }
          if (!closed) diags.push(diag("error", "Unclosed HTML comment <!--", lineNo, start + 1, "html"));
          break;
        }
        idx = endC + 3;
        continue;
      }
      if (line.slice(start, start + 2) === "<?") {
        idx = start + 2;
        continue;
      }
      if (line.slice(start, start + 2) === "<!") {
        const closeBang = line.indexOf(">", start);
        if (closeBang < 0) {
          diags.push(diag("error", "Incomplete <!…> declaration — missing '>'", lineNo, start + 1, "html"));
          break;
        }
        idx = closeBang + 1;
        continue;
      }

      const close = line.indexOf(">", start);
      if (close < 0) {
        let closedLater = false;
        for (let j = i + 1; j < Math.min(lines.length, i + 8); j++) {
          const next = lines[j];
          const gt = next.indexOf(">");
          const lt = next.indexOf("<");
          if (gt < 0) {
            if (/^\s*</.test(next)) break;
            continue;
          }
          if (lt >= 0 && lt < gt) break;
          // valid continuation: attributes then >
          if (/^\s*[A-Za-z_:][\w:.-]*\s*=/.test(next) || /^\s*[A-Za-z_:][\w:.-]*\s*>/.test(next) || /^\s*>/.test(next) || /^\s*\/\s*>/.test(next)) {
            closedLater = true;
          }
          break;
        }
        if (!closedLater) {
          const tagMatch = /^<\/?([A-Za-z][\w:-]*)/.exec(line.slice(start));
          const tagName = tagMatch?.[1] || "?";
          diags.push(diag("error", `Incomplete HTML tag <${tagName} — missing '>'`, lineNo, start + 1, "html"));
        }
        break;
      }

      const rawTag = line.slice(start, close + 1);
      const m = /^<\/?\s*([A-Za-z][\w:-]*)/.exec(rawTag);
      if (m && structural) {
        const name = m[1].toLowerCase();
        const isClose = rawTag.startsWith("</");
        const selfClosing = /\/\s*>$/.test(rawTag) || voidTags.has(name);
        if (isClose) {
          // pop until match
          let found = false;
          for (let s = stack.length - 1; s >= 0; s--) {
            if (stack[s].name === name) {
              stack.length = s;
              found = true;
              break;
            }
          }
          if (!found && ["html", "body", "head", "div", "span", "p", "ul", "ol", "li", "table", "form", "section", "header", "footer", "main", "nav"].includes(name)) {
            diags.push(diag("warning", `Closing </${name}> without a matching opening tag`, lineNo, start + 1, "html"));
          }
        } else if (!selfClosing) {
          stack.push({ name, line: lineNo, column: start + 1 });
        }
      }
      idx = close + 1;
    }
  }

  if (structural) {
    for (const tag of ["html", "body", "head"]) {
      const openRe = new RegExp(`<${tag}\\b[^>]*>`, "gi");
      const closeRe = new RegExp(`</${tag}\\s*>`, "gi");
      const open = (text.match(openRe) || []).length;
      const close = (text.match(closeRe) || []).length;
      const incomplete = new RegExp(`</${tag}(?![\\w:-])(?![^\\n<]*>)`, "i");
      const im = incomplete.exec(text);
      if (im) {
        const { line, column } = posToLineCol(text, im.index);
        diags.push(diag("error", `Incomplete closing tag </${tag} — missing '>'`, line, column, "html"));
      } else if (open !== close && open + close > 0) {
        diags.push(diag("warning", `Mismatched <${tag}> tags (open ${open}, close ${close})`, 1, 1, "html"));
      }
    }
    // leftover unclosed non-void structural from stack (limit noise)
    const leftovers = stack.filter((t) => ["div", "section", "form", "table", "ul", "ol", "header", "footer", "main", "nav"].includes(t.name));
    for (const t of leftovers.slice(-5)) {
      diags.push(diag("warning", `Unclosed <${t.name}> tag`, t.line, t.column, "html"));
    }
  }

  return diags;
}

// ——— Python ———
function lintPython(text) {
  /** @type {Diagnostic[]} */
  const diags = [...checkBrackets(text, { comments: "hash", allowTemplate: false, source: "python" })];
  const lines = text.split("\n");
  let indentUnit = null;
  /** @type {number[]} */
  const indentStack = [0];
  let expectIndent = false;
  let openTriple = null; // ''' or """

  for (let i = 0; i < lines.length; i++) {
    let line = lines[i];
    const lineNo = i + 1;

    // Triple-quote tracking across lines
    if (openTriple) {
      const idx = line.indexOf(openTriple);
      if (idx >= 0) openTriple = null;
      continue;
    }
    // detect start of triple quote outside continuing string (crude)
    const tq = line.match(/('''|""")/);
    if (tq) {
      const all = line.split(tq[1]);
      if ((all.length - 1) % 2 === 1) {
        openTriple = tq[1];
        continue;
      }
    }

    const raw = line;
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;

    // strip trailing comment carefully
    let code = trimmed;
    const hash = code.indexOf("#");
    if (hash >= 0) {
      // ignore # in strings — approximate
      const before = code.slice(0, hash);
      const sq = (before.match(/'/g) || []).length;
      const dq = (before.match(/"/g) || []).length;
      if (sq % 2 === 0 && dq % 2 === 0) code = before.trimEnd();
    }

    const indentMatch = /^( +|\t*)/.exec(raw);
    const indentStr = indentMatch ? indentMatch[1] : "";
    if (indentStr.includes("\t") && indentStr.includes(" ")) {
      diags.push(diag("error", "Mixed tabs and spaces in indentation", lineNo, 1, "python"));
    }
    const indent = indentStr.includes("\t") ? indentStr.length * 4 : indentStr.length;
    if (indentStr.includes(" ") && !indentStr.includes("\t")) {
      if (!indentUnit && indent > 0) indentUnit = indent;
      else if (indentUnit && indent > 0 && indent % indentUnit !== 0) {
        diags.push(diag("warning", `Inconsistent indent (expected multiple of ${indentUnit} spaces)`, lineNo, 1, "python"));
      }
    }

    if (expectIndent) {
      if (indent <= indentStack[indentStack.length - 1]) {
        diags.push(diag("error", "Expected indented block", lineNo, 1, "python"));
      } else {
        indentStack.push(indent);
      }
      expectIndent = false;
    } else {
      while (indentStack.length > 1 && indent < indentStack[indentStack.length - 1]) {
        indentStack.pop();
      }
      if (indent > indentStack[indentStack.length - 1] && indentStack.length > 1) {
        // allowed only after suite — already handled; sudden jump
        if (indent - indentStack[indentStack.length - 1] !== (indentUnit || 4) && indentUnit) {
          /* soft — skip */
        }
      }
    }

    if (/^(def|class|if|elif|else|for|while|try|except|finally|with|async\s+def|async\s+with|async\s+for)\b/.test(code) && code.endsWith(":")) {
      expectIndent = true;
    } else if (/^(def|class|if|elif|for|while|try|except|with)\b/.test(code) && !code.endsWith(":") && !code.endsWith("\\")) {
      diags.push(diag("error", "Suite header missing ':' at end of line", lineNo, Math.max(1, raw.length), "python"));
    }
  }

  if (openTriple) {
    diags.push(diag("error", `Unclosed triple-quoted string ${openTriple}`, lines.length, 1, "python"));
  }
  if (expectIndent) {
    diags.push(diag("error", "Expected indented block at end of file", lines.length, 1, "python"));
  }
  return diags;
}

// ——— PHP ———
function lintPhp(text) {
  /** @type {Diagnostic[]} */
  const diags = [
    ...checkBrackets(text, { comments: "c", allowTemplate: false, source: "php" }),
    ...checkHtmlMarkup(text, { structural: true }),
  ];

  const openTags = (text.match(/<\?(?:php|=)?/gi) || []).length;
  const closeTags = (text.match(/\?>/g) || []).length;
  if (openTags && closeTags > openTags) {
    diags.push(diag("error", "Extra PHP closing tag(s) ?>", 1, 1, "php"));
  }

  for (const m of text.matchAll(/<<<([A-Za-z_][A-Za-z0-9_]*)/g)) {
    const label = m[1];
    const after = text.slice(m.index + m[0].length);
    const re = new RegExp(`^${label};?\\s*$`, "m");
    if (!re.test(after)) {
      const { line, column } = posToLineCol(text, m.index || 0);
      diags.push(diag("error", `Unclosed heredoc <<<${label}`, line, column, "php"));
    }
  }
  for (const m of text.matchAll(/<<<'([A-Za-z_][A-Za-z0-9_]*)'/g)) {
    const label = m[1];
    const after = text.slice(m.index + m[0].length);
    const re = new RegExp(`^${label};?\\s*$`, "m");
    if (!re.test(after)) {
      const { line, column } = posToLineCol(text, m.index || 0);
      diags.push(diag("error", `Unclosed nowdoc <<<'${label}'`, line, column, "php"));
    }
  }

  return diags;
}

// ——— SQL ———
function lintSql(text) {
  /** @type {Diagnostic[]} */
  const diags = [...checkBrackets(text, { comments: "sql", allowTemplate: false, source: "sql" })];
  const select = (text.match(/\bSELECT\b/gi) || []).length;
  const from = (text.match(/\bFROM\b/gi) || []).length;
  if (select && !from) {
    diags.push(diag("warning", "SELECT without FROM (may be intentional)", 1, 1, "sql"));
  }
  return diags;
}

// ——— CSS family ———
function lintCss(text) {
  return checkBrackets(text, { comments: "c", allowTemplate: false, source: "css" });
}

// ——— Shell / PowerShell ———
function lintShell(text, language) {
  /** @type {Diagnostic[]} */
  const diags = [...checkBrackets(text, { comments: "hash", allowTemplate: false, source: language })];
  // Unclosed quotes with # comments
  let inStr = null;
  let line = 1;
  let col = 1;
  let start = { line: 1, column: 1 };
  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (ch === "\n") {
      line += 1;
      col = 1;
      continue;
    }
    if (!inStr && ch === "#") {
      while (i < text.length && text[i] !== "\n") i += 1;
      line += 1;
      col = 1;
      continue;
    }
    if ((ch === '"' || ch === "'") && (i === 0 || text[i - 1] !== "\\")) {
      if (!inStr) {
        inStr = ch;
        start = { line, column: col };
      } else if (inStr === ch) inStr = null;
    }
    col += 1;
  }
  if (inStr) diags.push(diag("error", `Unclosed ${inStr} string`, start.line, start.column, language));

  if (language === "powershell") {
    // Unclosed @{ or @( already in brackets; check here-strings @" "@ 
    const here = [...text.matchAll(/@("|')/g)];
    for (const m of here) {
      const q = m[1];
      const closer = `${q}@`;
      const after = text.slice(m.index + 2);
      if (!after.includes("\n" + closer) && !after.startsWith(closer)) {
        // multiline here-string must end with quote@ at line start
        const re = new RegExp(`^${q}@`, "m");
        if (!re.test(after)) {
          const { line: l, column: c } = posToLineCol(text, m.index);
          diags.push(diag("error", `Unclosed PowerShell here-string @${q}`, l, c, "powershell"));
        }
      }
    }
  }
  return diags;
}

// ——— C-family / Go / Rust / Java ———
function lintCFamily(text, language) {
  /** @type {Diagnostic[]} */
  const diags = [...checkBrackets(text, { comments: "c", allowTemplate: language === "javascript", source: language })];

  if (language === "c" || language === "cpp") {
    const ifs = (text.match(/^\s*#\s*if(n?def)?\b/gm) || []).length;
    const endifs = (text.match(/^\s*#\s*endif\b/gm) || []).length;
    if (ifs !== endifs) {
      diags.push(diag("error", `Mismatched preprocessor conditionals (#if ${ifs} / #endif ${endifs})`, 1, 1, language));
    }
  }

  if (language === "rust") {
    // raw strings r#"..."#
    for (const m of text.matchAll(/r(#*)"/g)) {
      const hashes = m[1];
      const closer = `"${hashes}`;
      const after = text.slice(m.index + m[0].length);
      if (!after.includes(closer)) {
        const { line, column } = posToLineCol(text, m.index);
        diags.push(diag("error", `Unclosed raw string r${hashes}"`, line, column, "rust"));
      }
    }
  }

  return diags;
}

// ——— Markdown ———
function lintMarkdown(text) {
  /** @type {Diagnostic[]} */
  const diags = [];
  const lines = text.split("\n");
  let fence = null;
  let fenceLine = 1;
  for (let i = 0; i < lines.length; i++) {
    const m = /^(```|~~~)(.*)$/.exec(lines[i]);
    if (!m) continue;
    if (!fence) {
      fence = m[1];
      fenceLine = i + 1;
    } else if (m[1] === fence) {
      fence = null;
    }
  }
  if (fence) diags.push(diag("error", `Unclosed fenced code block (${fence})`, fenceLine, 1, "markdown"));

  // Unclosed link text [text without ]
  let inLink = false;
  let linkStart = { line: 1, column: 1 };
  let line = 1;
  let col = 1;
  let inFence = false;
  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (ch === "\n") {
      line += 1;
      col = 1;
      continue;
    }
    // crude fence skip
    if (col === 1 && (text.startsWith("```", i) || text.startsWith("~~~", i))) {
      inFence = !inFence;
    }
    if (inFence) {
      col += 1;
      continue;
    }
    if (ch === "[" && !inLink) {
      inLink = true;
      linkStart = { line, column: col };
    } else if (ch === "]" && inLink) {
      inLink = false;
    }
    col += 1;
  }
  if (inLink) diags.push(diag("warning", "Unclosed markdown link label '['", linkStart.line, linkStart.column, "markdown"));
  return diags;
}

/**
 * Static diagnostics — parse/syntax only, never executes user code.
 * @returns {Diagnostic[]}
 */
export function lintCode(text, language) {
  if (text == null) return [];
  const src = String(text);
  /** @type {Diagnostic[]} */
  let diags = [];
  switch (language) {
    case "json":
      diags = lintJson(src);
      break;
    case "javascript":
      diags = lintJavaScript(src);
      break;
    case "typescript":
      diags = lintTypeScript(src);
      break;
    case "yaml":
      diags = lintYaml(src);
      break;
    case "xml":
      diags = lintXml(src);
      break;
    case "html":
      diags = [...checkHtmlMarkup(src, { structural: true }), ...checkBrackets(src, { comments: "html", allowTemplate: false })];
      break;
    case "python":
      diags = lintPython(src);
      break;
    case "php":
      diags = lintPhp(src);
      break;
    case "sql":
      diags = lintSql(src);
      break;
    case "css":
    case "scss":
    case "less":
      diags = lintCss(src);
      break;
    case "shell":
    case "dockerfile":
      diags = lintShell(src, "shell");
      break;
    case "powershell":
      diags = lintShell(src, "powershell");
      break;
    case "c":
    case "cpp":
    case "csharp":
    case "java":
    case "go":
    case "rust":
      diags = lintCFamily(src, language);
      break;
    case "markdown":
      diags = lintMarkdown(src);
      break;
    default:
      diags = checkBrackets(src, { comments: "c" });
  }
  return dedupe(diags);
}

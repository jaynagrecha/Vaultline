/** Extension-first language detection with content sniff fallback. */

const EXT_MAP = {
  js: "javascript",
  mjs: "javascript",
  cjs: "javascript",
  jsx: "javascript",
  ts: "typescript",
  tsx: "typescript",
  json: "json",
  jsonc: "json",
  json5: "json",
  geojson: "json",
  webmanifest: "json",
  py: "python",
  pyw: "python",
  yml: "yaml",
  yaml: "yaml",
  xml: "xml",
  svg: "xml",
  html: "html",
  htm: "html",
  css: "css",
  scss: "scss",
  less: "less",
  sql: "sql",
  sh: "shell",
  bash: "shell",
  zsh: "shell",
  fish: "shell",
  ps1: "powershell",
  psm1: "powershell",
  psd1: "powershell",
  c: "c",
  h: "c",
  cpp: "cpp",
  cc: "cpp",
  cxx: "cpp",
  hpp: "cpp",
  hh: "cpp",
  cs: "csharp",
  go: "go",
  rs: "rust",
  java: "java",
  php: "php",
  phtml: "php",
  phar: "php",
  md: "markdown",
  markdown: "markdown",
  mdx: "markdown",
};

const NAME_MAP = {
  dockerfile: "dockerfile",
  makefile: "shell",
  gemfile: "ruby",
  "package.json": "json",
  "tsconfig.json": "json",
  "jsconfig.json": "json",
  "composer.json": "json",
  ".env": "shell",
};

const LABELS = {
  javascript: "JavaScript",
  typescript: "TypeScript",
  json: "JSON",
  python: "Python",
  yaml: "YAML",
  xml: "XML",
  html: "HTML",
  css: "CSS",
  scss: "SCSS",
  less: "Less",
  sql: "SQL",
  shell: "Shell",
  powershell: "PowerShell",
  c: "C",
  cpp: "C++",
  csharp: "C#",
  go: "Go",
  rust: "Rust",
  java: "Java",
  php: "PHP",
  markdown: "Markdown",
  dockerfile: "Docker",
  plaintext: "Text",
};

/** Languages treated as "code" for beautify + IDE. */
export const CODE_LANGUAGES = new Set(Object.keys(LABELS).filter((k) => k !== "plaintext"));

export function languageLabel(id) {
  return LABELS[id] || (id ? id.toUpperCase() : "File");
}

function looksLikeJson(sample) {
  const t = String(sample || "").trim();
  if (!(t.startsWith("{") || t.startsWith("["))) return false;
  try {
    JSON.parse(t);
    return true;
  } catch {
    return t.startsWith("{") || t.startsWith("[");
  }
}

function looksLikeYaml(sample) {
  const lines = String(sample || "")
    .split(/\n/)
    .slice(0, 20)
    .filter((l) => l.trim() && !l.trim().startsWith("#"));
  if (lines.length < 2) return false;
  let hits = 0;
  for (const line of lines) {
    if (/^[A-Za-z0-9_.-]+:\s/.test(line) || /^\s+-\s+\S/.test(line)) hits += 1;
  }
  return hits >= 2;
}

function looksLikeXml(sample) {
  const t = String(sample || "").trim();
  return t.startsWith("<?xml") || /^<[A-Za-z][\w:.-]*[\s>]/.test(t);
}

function looksLikeShell(sample) {
  const t = String(sample || "").trim();
  return t.startsWith("#!") && /bin\/(ba)?sh|powershell|pwsh/i.test(t.split("\n", 1)[0]);
}

function looksLikePhp(sample) {
  const t = String(sample || "").trim();
  return t.startsWith("<?php") || t.startsWith("<?=") || /<\?php\b/i.test(t.slice(0, 200));
}

/**
 * @returns {{ language: string, label: string, isCode: boolean, source: 'extension'|'name'|'content'|'none' }}
 */
export function detectCodeLanguage(filename, sampleText = "") {
  const base = String(filename || "").trim();
  const lower = base.toLowerCase();
  if (NAME_MAP[lower]) {
    const language = NAME_MAP[lower];
    return { language, label: languageLabel(language), isCode: CODE_LANGUAGES.has(language), source: "name" };
  }
  const dot = lower.lastIndexOf(".");
  if (dot > 0) {
    const ext = lower.slice(dot + 1);
    if (EXT_MAP[ext]) {
      const language = EXT_MAP[ext];
      return {
        language,
        label: languageLabel(language),
        isCode: CODE_LANGUAGES.has(language),
        source: "extension",
      };
    }
  }
  if (looksLikePhp(sampleText)) {
    return { language: "php", label: languageLabel("php"), isCode: true, source: "content" };
  }
  if (looksLikeShell(sampleText)) {
    return { language: "shell", label: languageLabel("shell"), isCode: true, source: "content" };
  }
  if (looksLikeJson(sampleText)) {
    return { language: "json", label: languageLabel("json"), isCode: true, source: "content" };
  }
  if (looksLikeXml(sampleText)) {
    return { language: "xml", label: languageLabel("xml"), isCode: true, source: "content" };
  }
  if (looksLikeYaml(sampleText)) {
    return { language: "yaml", label: languageLabel("yaml"), isCode: true, source: "content" };
  }
  return { language: "plaintext", label: languageLabel("plaintext"), isCode: false, source: "none" };
}

/** Monaco language id mapping. */
export function toMonacoLanguage(language) {
  const map = {
    javascript: "javascript",
    typescript: "typescript",
    json: "json",
    python: "python",
    yaml: "yaml",
    xml: "xml",
    html: "html",
    css: "css",
    scss: "scss",
    less: "less",
    sql: "sql",
    shell: "shell",
    powershell: "powershell",
    c: "c",
    cpp: "cpp",
    csharp: "csharp",
    go: "go",
    rust: "rust",
    java: "java",
    php: "php",
    markdown: "markdown",
    dockerfile: "dockerfile",
    plaintext: "plaintext",
  };
  return map[language] || "plaintext";
}

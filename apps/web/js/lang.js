/** Map filename → { hljs language id, display label }. */
const EXT_LANG = {
  py: { id: "python", label: "Python" },
  pyw: { id: "python", label: "Python" },
  js: { id: "javascript", label: "JavaScript" },
  mjs: { id: "javascript", label: "JavaScript" },
  cjs: { id: "javascript", label: "JavaScript" },
  jsx: { id: "javascript", label: "JSX" },
  ts: { id: "typescript", label: "TypeScript" },
  tsx: { id: "typescript", label: "TSX" },
  css: { id: "css", label: "CSS" },
  scss: { id: "scss", label: "SCSS" },
  less: { id: "less", label: "Less" },
  html: { id: "xml", label: "HTML" },
  htm: { id: "xml", label: "HTML" },
  vue: { id: "xml", label: "Vue" },
  svelte: { id: "xml", label: "Svelte" },
  json: { id: "json", label: "JSON" },
  jsonc: { id: "json", label: "JSON" },
  json5: { id: "json", label: "JSON" },
  geojson: { id: "json", label: "JSON" },
  har: { id: "json", label: "JSON" },
  webmanifest: { id: "json", label: "JSON" },
  map: { id: "json", label: "JSON" },
  yml: { id: "yaml", label: "YAML" },
  yaml: { id: "yaml", label: "YAML" },
  xml: { id: "xml", label: "XML" },
  svg: { id: "xml", label: "SVG" },
  php: { id: "php", label: "PHP" },
  cs: { id: "csharp", label: "C#" },
  cshtml: { id: "xml", label: "Razor" },
  fs: { id: "fsharp", label: "F#" },
  vb: { id: "vbnet", label: "VB.NET" },
  java: { id: "java", label: "Java" },
  kt: { id: "kotlin", label: "Kotlin" },
  kts: { id: "kotlin", label: "Kotlin" },
  go: { id: "go", label: "Go" },
  rs: { id: "rust", label: "Rust" },
  rb: { id: "ruby", label: "Ruby" },
  sh: { id: "bash", label: "Shell" },
  bash: { id: "bash", label: "Shell" },
  zsh: { id: "bash", label: "Shell" },
  fish: { id: "bash", label: "Shell" },
  ps1: { id: "powershell", label: "PowerShell" },
  psm1: { id: "powershell", label: "PowerShell" },
  sql: { id: "sql", label: "SQL" },
  md: { id: "markdown", label: "Markdown" },
  markdown: { id: "markdown", label: "Markdown" },
  toml: { id: "ini", label: "TOML" },
  ini: { id: "ini", label: "Config" },
  conf: { id: "ini", label: "Config" },
  cfg: { id: "ini", label: "Config" },
  env: { id: "bash", label: "Env" },
  properties: { id: "properties", label: "Config" },
  txt: { id: "plaintext", label: "Text" },
  log: { id: "plaintext", label: "Log" },
  out: { id: "plaintext", label: "Log" },
  err: { id: "plaintext", label: "Log" },
  syslog: { id: "plaintext", label: "Log" },
  c: { id: "c", label: "C" },
  h: { id: "c", label: "C" },
  cpp: { id: "cpp", label: "C++" },
  cc: { id: "cpp", label: "C++" },
  cxx: { id: "cpp", label: "C++" },
  hpp: { id: "cpp", label: "C++" },
  swift: { id: "swift", label: "Swift" },
  r: { id: "r", label: "R" },
  lua: { id: "lua", label: "Lua" },
  pl: { id: "perl", label: "Perl" },
  pm: { id: "perl", label: "Perl" },
  tf: { id: "plaintext", label: "Terraform" },
  hcl: { id: "plaintext", label: "HCL" },
  graphql: { id: "graphql", label: "GraphQL" },
  gql: { id: "graphql", label: "GraphQL" },
  proto: { id: "protobuf", label: "Protobuf" },
  dart: { id: "dart", label: "Dart" },
  scala: { id: "scala", label: "Scala" },
  groovy: { id: "groovy", label: "Groovy" },
  gradle: { id: "gradle", label: "Gradle" },
  cmake: { id: "cmake", label: "CMake" },
  makefile: { id: "makefile", label: "Make" },
  mk: { id: "makefile", label: "Make" },
};

const NAME_LANG = {
  dockerfile: { id: "dockerfile", label: "Docker" },
  makefile: { id: "makefile", label: "Make" },
  gemfile: { id: "ruby", label: "Ruby" },
  rakefile: { id: "ruby", label: "Ruby" },
  "cmakelists.txt": { id: "cmake", label: "CMake" },
  ".env": { id: "bash", label: "Env" },
  ".gitignore": { id: "plaintext", label: "Git" },
  ".dockerignore": { id: "plaintext", label: "Docker" },
  "composer.json": { id: "json", label: "JSON" },
  "package.json": { id: "json", label: "JSON" },
  "tsconfig.json": { id: "json", label: "JSON" },
  "jsconfig.json": { id: "json", label: "JSON" },
  "npm-debug.log": { id: "plaintext", label: "Log" },
  "yarn-error.log": { id: "plaintext", label: "Log" },
};

function looksLikeJson(sample) {
  if (!sample || typeof sample !== "string") return false;
  const t = sample.trim();
  if (!(t.startsWith("{") || t.startsWith("["))) return false;
  try {
    JSON.parse(t);
    return true;
  } catch {
    return false;
  }
}

function looksLikeLog(sample) {
  if (!sample || typeof sample !== "string") return false;
  const lines = sample.split(/\r?\n/).filter((l) => l.trim()).slice(0, 12);
  if (lines.length < 2) return false;
  let hits = 0;
  for (const line of lines) {
    if (
      /^\d{4}-\d{2}-\d{2}[ T]/.test(line) ||
      /^\[\d{4}-\d{2}-\d{2}/.test(line) ||
      /^\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}/.test(line) ||
      /\b(INFO|WARN|WARNING|ERROR|DEBUG|TRACE|FATAL|CRITICAL)\b/i.test(line) ||
      /^\d{2}:\d{2}:\d{2}/.test(line)
    ) {
      hits += 1;
    }
  }
  return hits >= Math.min(2, lines.length);
}

export function detectLanguage(filename, sampleText = "") {
  const base = String(filename || "").trim();
  const lower = base.toLowerCase();
  if (NAME_LANG[lower]) return NAME_LANG[lower];
  // access.log, error.log.1, app.log.gz names without clean ext already handled via last ext
  if (/\.log(\.\d+)?$/i.test(lower) || lower.endsWith(".log")) {
    return { id: "plaintext", label: "Log" };
  }
  const dot = lower.lastIndexOf(".");
  if (dot > 0) {
    const ext = lower.slice(dot + 1);
    if (EXT_LANG[ext]) return EXT_LANG[ext];
  }
  if (looksLikeJson(sampleText)) return { id: "json", label: "JSON" };
  if (looksLikeLog(sampleText)) return { id: "plaintext", label: "Log" };
  if (dot > 0) {
    const ext = lower.slice(dot + 1);
    return { id: "plaintext", label: ext.toUpperCase() };
  }
  return { id: "plaintext", label: "File" };
}

export function highlightCode(codeEl, text, langId) {
  const hljs = globalThis.hljs;
  codeEl.textContent = text ?? "";
  if (!hljs || !text) return;
  try {
    if (langId && langId !== "plaintext" && hljs.getLanguage?.(langId)) {
      codeEl.className = `language-${langId}`;
      hljs.highlightElement(codeEl);
      return;
    }
    // Ensure JSON still highlights even if language table is thin
    if (langId === "json" || looksLikeJson(text)) {
      codeEl.className = "language-json";
      const result = hljs.highlight(text, { language: "json", ignoreIllegals: true });
      codeEl.innerHTML = result.value;
      codeEl.classList.add("hljs");
      return;
    }
    codeEl.className = "language-plaintext";
    hljs.highlightElement(codeEl);
  } catch {
    codeEl.textContent = text;
  }
}

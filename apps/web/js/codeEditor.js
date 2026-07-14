/**
 * Monaco editor bootstrap + marker helpers for Config Rooms.
 * Loads Monaco from jsDelivr AMD loader (works without a bundler).
 */

const MONACO_VER = "0.52.2";
const MONACO_BASE = `https://cdn.jsdelivr.net/npm/monaco-editor@${MONACO_VER}/min/vs`;

let monacoPromise = null;
let monacoApi = null;

function loadScript(src) {
  return new Promise((resolve, reject) => {
    if (document.querySelector(`script[src="${src}"]`)) {
      resolve();
      return;
    }
    const s = document.createElement("script");
    s.src = src;
    s.async = true;
    s.onload = () => resolve();
    s.onerror = () => reject(new Error("Failed to load Monaco loader"));
    document.head.appendChild(s);
  });
}

export function ensureMonaco() {
  if (monacoApi) return Promise.resolve(monacoApi);
  if (monacoPromise) return monacoPromise;
  monacoPromise = (async () => {
    if (!document.getElementById("monaco-css")) {
      const link = document.createElement("link");
      link.id = "monaco-css";
      link.rel = "stylesheet";
      link.href = `${MONACO_BASE}/editor/editor.main.css`;
      document.head.appendChild(link);
    }
    await loadScript(`${MONACO_BASE}/loader.js`);
    const requirejs = globalThis.require;
    if (!requirejs) throw new Error("Monaco AMD loader missing");
    requirejs.config({ paths: { vs: MONACO_BASE } });
    monacoApi = await new Promise((resolve, reject) => {
      try {
        requirejs(["vs/editor/editor.main"], () => {
          resolve(globalThis.monaco);
        }, reject);
      } catch (e) {
        reject(e);
      }
    });
    return monacoApi;
  })();
  return monacoPromise;
}

export function severityToMonaco(monaco, severity) {
  if (severity === "error") return monaco.MarkerSeverity.Error;
  if (severity === "warning") return monaco.MarkerSeverity.Warning;
  return monaco.MarkerSeverity.Info;
}

export function applyDiagnostics(monaco, editor, owner, diagnostics = []) {
  const model = editor.getModel();
  if (!model) return;
  const markers = (diagnostics || []).map((d) => ({
    severity: severityToMonaco(monaco, d.severity),
    message: d.message,
    startLineNumber: Math.max(1, d.line || 1),
    startColumn: Math.max(1, d.column || 1),
    endLineNumber: Math.max(1, d.line || 1),
    endColumn: Math.max(2, (d.column || 1) + 1),
    source: d.source || "config-rooms",
  }));
  monaco.editor.setModelMarkers(model, owner, markers);
}

/**
 * Create a Monaco instance in containerEl.
 * @returns {Promise<{ monaco, editor, dispose, getValue, setValue, setLanguage }>}
 */
export async function createCodeEditor(containerEl, { value, language, readOnly = false, theme = "vs-dark" }) {
  const monaco = await ensureMonaco();
  const editor = monaco.editor.create(containerEl, {
    value: value ?? "",
    language: language || "plaintext",
    theme,
    readOnly: !!readOnly,
    automaticLayout: true,
    minimap: { enabled: true, maxColumn: 80 },
    fontFamily: "'JetBrains Mono', Consolas, 'Courier New', monospace",
    fontSize: 13,
    lineNumbers: "on",
    tabSize: 2,
    insertSpaces: true,
    wordWrap: "on",
    scrollBeyondLastLine: false,
    renderWhitespace: "selection",
    bracketPairColorization: { enabled: true },
    smoothScrolling: true,
    padding: { top: 8, bottom: 8 },
  });

  return {
    monaco,
    editor,
    getValue: () => editor.getValue(),
    setValue: (v) => editor.setValue(v ?? ""),
    setLanguage: (lang) => {
      const model = editor.getModel();
      if (model) monaco.editor.setModelLanguage(model, lang || "plaintext");
    },
    dispose: () => {
      try {
        editor.dispose();
      } catch {
        /* ignore */
      }
    },
  };
}

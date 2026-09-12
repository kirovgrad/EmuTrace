/* Viewer for angr pseudocode embedded in EMTR v3 metadata. */
"use strict";
function createDecompView({ getState, setStatus }) {
  const el = (id) => document.getElementById(id);
  const MAX_FUNCTIONS = 4096;
  const keywords = new Set([
    "auto",
    "bool",
    "break",
    "case",
    "char",
    "const",
    "continue",
    "default",
    "do",
    "double",
    "else",
    "enum",
    "float",
    "for",
    "goto",
    "if",
    "int",
    "long",
    "return",
    "short",
    "signed",
    "sizeof",
    "static",
    "struct",
    "switch",
    "typedef",
    "union",
    "unsigned",
    "void",
    "volatile",
    "while",
  ]);
  let active = false;
  let trace = null;
  let analysis = null;
  let error = "";
  let functions = new Map();
  let failures = new Map();
  let rendered = null;

  function addressKey(value) {
    if (typeof value !== "string" || !/^0x[0-9a-f]+$/i.test(value))
      throw new Error("invalid function address");
    const address = BigInt(value);
    if (address < 0n || address > 0xffffffffffffffffn)
      throw new Error("function address exceeds 64 bits");
    return address.toString();
  }

  function validateEntry(entry, failure = false) {
    if (!entry || typeof entry !== "object" || Array.isArray(entry))
      throw new Error("invalid function entry");
    if (
      typeof entry.name !== "string" ||
      typeof entry.address !== "string" ||
      !Array.isArray(entry.observed_addresses) ||
      entry.observed_addresses.length > trace.nFrames
    )
      throw new Error("invalid function fields");
    if (failure) {
      if (typeof entry.reason !== "string")
        throw new Error("invalid decompilation failure");
    } else if (typeof entry.pseudocode !== "string") {
      throw new Error("invalid function pseudocode");
    }
    addressKey(entry.address);
    for (const address of entry.observed_addresses) addressKey(address);
    return entry;
  }

  function readAnalysis(nextTrace) {
    const value = nextTrace.metadata?.decompilation;
    if (value === undefined) return null;
    if (
      !value ||
      typeof value !== "object" ||
      Array.isArray(value) ||
      value.version !== 1 ||
      !value.engine ||
      value.engine.name !== "angr" ||
      typeof value.engine.version !== "string" ||
      !value.binary ||
      typeof value.binary.name !== "string" ||
      !Array.isArray(value.functions) ||
      !Array.isArray(value.failures) ||
      value.functions.length + value.failures.length > MAX_FUNCTIONS
    )
      throw new Error("unsupported or malformed angr metadata");
    value.functions.forEach((entry) => validateEntry(entry));
    value.failures.forEach((entry) => validateEntry(entry, true));
    return value;
  }

  function message(title, detail) {
    rendered = null;
    el("decomp-function").textContent = title;
    el("decomp-count").textContent = "";
    el("decomp-code").replaceChildren();
    el("decomp-code").hidden = true;
    el("decomp-message-title").textContent = title;
    el("decomp-message-detail").textContent = detail;
    el("decomp-message").hidden = false;
    el("decomp-copy").disabled = true;
  }

  function appendToken(parent, value, className = "") {
    const span = document.createElement("span");
    if (className) span.className = className;
    span.textContent = value;
    parent.appendChild(span);
  }

  function renderCode(source) {
    const list = el("decomp-code");
    list.replaceChildren();
    for (const line of source.replace(/\n$/, "").split("\n")) {
      const item = document.createElement("li");
      const code = document.createElement("code");
      const pattern =
        /(\/\/.*$|"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|\b0x[0-9a-f]+\b|\b\d+\b|\b[A-Za-z_]\w*\b)/gi;
      let offset = 0;
      for (const match of line.matchAll(pattern)) {
        appendToken(code, line.slice(offset, match.index));
        const token = match[0];
        const className = token.startsWith("//")
          ? "comment"
          : token.startsWith('"') || token.startsWith("'")
            ? "string"
            : /^0x|^\d/i.test(token)
              ? "number"
              : keywords.has(token.toLowerCase())
                ? "keyword"
                : "";
        appendToken(code, token, className);
        offset = match.index + token.length;
      }
      appendToken(code, line.slice(offset));
      item.appendChild(code);
      list.appendChild(item);
    }
  }

  function currentEntry() {
    const frame = getState().trace?.frames[getState().index];
    if (!frame) return {};
    const key = frame.address.toString();
    return { item: functions.get(key), failure: failures.get(key) };
  }

  function render() {
    if (!trace?.nFrames) {
      message("Decompilation", "No instruction frames in this trace.");
      return;
    }
    if (error) {
      message("Decompilation unavailable", error);
      return;
    }
    if (!analysis) {
      message(
        "No embedded decompilation",
        "Run emu_decompiler.py with this trace, then open the generated .emtr file. Supplying the original executable improves recovery.",
      );
      el("decomp-note").textContent =
        "python3 emu_decompiler.py trace.emtr -o trace.decompiled.emtr";
      return;
    }
    const { item, failure } = currentEntry();
    if (!item) {
      message(
        failure
          ? `${failure.name} could not be decompiled`
          : "Function not available",
        failure?.reason ||
          "angr did not map the current instruction to a recovered function.",
      );
      return;
    }
    rendered = item;
    el("decomp-function").textContent = `${item.name} · ${item.address}`;
    const count = item.observed_addresses.length;
    el("decomp-count").textContent =
      `${count.toLocaleString()} traced ${count === 1 ? "instruction" : "instructions"}`;
    el("decomp-message").hidden = true;
    el("decomp-code").hidden = false;
    el("decomp-copy").disabled = false;
    renderCode(item.pseudocode);
  }

  function reset(nextTrace) {
    trace = nextTrace;
    analysis = null;
    error = "";
    functions = new Map();
    failures = new Map();
    rendered = null;
    try {
      analysis = readAnalysis(trace);
      if (analysis) {
        for (const entry of analysis.functions)
          for (const address of entry.observed_addresses)
            functions.set(addressKey(address), entry);
        for (const entry of analysis.failures)
          for (const address of entry.observed_addresses)
            failures.set(addressKey(address), entry);
        el("decomp-note").textContent =
          `${analysis.engine.name} ${analysis.engine.version} · ${analysis.binary.name}`;
      } else {
        el("decomp-note").textContent =
          "Optional local analysis · no server required";
      }
    } catch (reason) {
      error = `The embedded decompilation metadata is invalid: ${reason.message}.`;
      el("decomp-note").textContent = "EMTR metadata rejected";
    }
    render();
  }

  function activate(value) {
    active = value;
    if (active) render();
  }

  function selectionChanged() {
    if (active) render();
  }

  el("decomp-copy").onclick = async () => {
    if (!rendered) return;
    try {
      await navigator.clipboard.writeText(rendered.pseudocode);
      setStatus(`Copied pseudocode for ${rendered.name}.`);
    } catch {
      setStatus("The browser denied clipboard access.", true);
    }
  };

  return { reset, activate, selectionChanged };
}

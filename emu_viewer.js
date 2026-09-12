"use strict";
const $ = (id) => document.getElementById(id);
const escapeHTML = (value) =>
  String(value).replace(
    /[&<>"']/g,
    (c) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[
        c
      ],
  );
const state = {
  trace: null,
  index: 0,
  breakpoints: new Set(),
  onlyBreakpoints: false,
  visible: [],
  matches: [],
  query: "",
  timer: null,
  loadId: 0,
  hits: new Map(),
};
// The CSS metrics are also used by both virtualized tables.
const tableStyle = getComputedStyle(document.documentElement);
const ROW_HEIGHT = parseFloat(tableStyle.getPropertyValue("--data-row-height"));
const HEADER_HEIGHT = parseFloat(
  tableStyle.getPropertyValue("--table-header-height"),
);
let capstonePromise;
let searchTimer;
let scrollRequest;

function status(message, error = false) {
  $("status-msg").textContent = message;
  $("status-msg").classList.toggle("error", error);
}
function setEnabled(enabled) {
  document.querySelectorAll("[data-trace]").forEach((element) => {
    element.disabled = !enabled;
  });
}
setEnabled(false);

// The bundled asm.js runtime initializes itself. Probe its actual API after
// script.onload instead of guessing with a short timeout or replacing Module.
function loadCapstone() {
  if (!capstonePromise)
    capstonePromise = new Promise((resolve) => {
      if (window.cs?.Capstone) {
        resolve(window.cs);
        return;
      }
      const script = document.createElement("script");
      script.src = "capstone.min.js";
      script.onload = () => {
        try {
          window.cs.version();
          resolve(window.cs);
        } catch {
          resolve(null);
        }
      };
      script.onerror = () => resolve(null);
      document.head.appendChild(script);
    });
  return capstonePromise;
}

async function decodeLegacy(trace, loadId) {
  if (trace.frames.every((frame) => frame.mnemonic)) return;
  const cs = await loadCapstone();
  const engines = new Map(),
    cache = new Map();
  try {
    for (let index = 0; index < trace.frames.length; index++) {
      if (state.loadId !== loadId) return;
      const frame = trace.frames[index];
      if (!frame.mnemonic) {
        const key = `${frame.archId}:${frame.address}:${Emtr.opcodeHex(frame.opcode)}`;
        let decoded = cache.get(key);
        if (!decoded) {
          decoded = { mnemonic: "", operands: "" };
          // This older JS binding passes a zero high word for the instruction
          // address. Refuse to produce incorrect branch targets above 32 bits.
          if (cs && frame.address <= 0xffffffffn) {
            if (!engines.has(frame.archId)) {
              const spec = Emtr.architectures[frame.archId];
              const arch = cs["ARCH_" + spec.csArch];
              const modes = spec.csModes.map((name) => cs["MODE_" + name]);
              let engine = null;
              try {
                if (
                  arch !== undefined &&
                  modes.every((mode) => mode !== undefined)
                )
                  engine = new cs.Capstone(
                    arch,
                    modes.reduce((mode, bit) => mode | bit, 0),
                  );
              } catch {
                /* Not compiled into the legacy browser library. */
              }
              engines.set(frame.archId, engine);
            }
            try {
              const instruction = engines
                .get(frame.archId)
                ?.disasm(Array.from(frame.opcode), Number(frame.address), 1)[0];
              if (instruction)
                decoded = {
                  mnemonic: instruction.mnemonic,
                  operands: instruction.op_str,
                };
            } catch {
              /* Raw bytes are retained for unsupported instructions. */
            }
          }
          cache.set(key, decoded);
        }
        Object.assign(frame, decoded);
      }
      if (index % 500 === 0) {
        status(
          `Decoding instructions… ${Math.round((index / trace.nFrames) * 100)}%`,
        );
        await new Promise((resolve) => setTimeout(resolve, 0));
      }
    }
  } finally {
    for (const engine of engines.values()) if (engine) engine.close();
  }
}

async function loadBuffer(buffer, name, loadId = ++state.loadId) {
  stopPlayback();
  status("Reading trace…");
  try {
    const trace = await Emtr.parse(buffer);
    if (loadId !== state.loadId) return;
    status("Preparing execution view…");
    await decodeLegacy(trace, loadId);
    if (loadId !== state.loadId) return;
    const hits = new Map();
    for (const frame of trace.frames)
      hits.set(frame.address, (hits.get(frame.address) || 0) + 1);
    Object.assign(state, {
      trace,
      index: 0,
      breakpoints: new Set(),
      onlyBreakpoints: false,
      visible: [],
      matches: [],
      query: "",
      hits,
      changeHistory: Emtr.createChangeHistory(trace.frames),
    });
    clearTimeout(searchTimer);
    $("search-input").value = "";
    $("search-info").textContent = "";
    $("changed-only").checked = false;
    $("trace-name").textContent = name;
    $("arch-name").textContent = trace.archName;
    $("trace-count").textContent =
      `${trace.nFrames.toLocaleString()} frames${trace.truncated ? " · capture limit reached" : ""}`;
    $("trace-unique").textContent =
      `${hits.size.toLocaleString()} unique addresses`;
    $("trace-size").textContent =
      buffer.byteLength < 1024
        ? `${buffer.byteLength} B`
        : `${(buffer.byteLength / 1024).toFixed(1)} KB`;
    $("frame-total").textContent = `/ ${trace.nFrames.toLocaleString()}`;
    $("frame-input").max = Math.max(1, trace.nFrames);
    $("frame-slider").max = Math.max(0, trace.nFrames - 1);
    $("watch-register").replaceChildren(new Option("Choose…", ""));
    const names = new Set();
    for (const frame of trace.frames)
      for (const name of Object.keys(frame.regs)) names.add(name);
    for (const register of names)
      $("watch-register").add(new Option(register, register));
    $("welcome").hidden = true;
    $("workspace").hidden = false;
    $("disasm-table").classList.toggle(
      "wide",
      Emtr.architectures[trace.archId].bits === 64,
    );
    $("disasm-scroll").scrollTop = 0;
    $("reg-scroll").scrollTop = 0;
    $("stack-scroll").scrollTop = 0;
    setEnabled(trace.nFrames > 0);
    rebuildVisible();
    if (trace.nFrames) selectFrame(0);
    else clearPanels();
    const rawCount = trace.frames.filter((frame) => !frame.mnemonic).length;
    status(
      trace.truncated
        ? "Capture stopped at the configured limit. This is a partial trace."
        : trace.nFrames
          ? rawCount
            ? `Loaded ${trace.nFrames.toLocaleString()} frames · ${rawCount.toLocaleString()} instructions shown as raw bytes (decoder unavailable).`
            : `Loaded ${trace.nFrames.toLocaleString()} frames. All processing stays on this device.`
          : "This trace contains no frames.",
    );
  } catch (error) {
    if (loadId === state.loadId)
      status(`Could not open trace: ${error.message}`, true);
  }
}

async function handleFile(file) {
  if (!file) return;
  const loadId = ++state.loadId;
  stopPlayback();
  if (file.size > Emtr.MAX_BYTES + 16) {
    status("File exceeds the 256 MiB size limit.", true);
    return;
  }
  status(`Opening ${file.name}…`);
  try {
    const buffer = await file.arrayBuffer();
    if (state.loadId === loadId) await loadBuffer(buffer, file.name, loadId);
  } catch (error) {
    if (loadId === state.loadId)
      status(`Could not read file: ${error.message}`, true);
  }
}

function rebuildVisible() {
  state.visible = state.onlyBreakpoints
    ? Array.from(state.breakpoints).sort((a, b) => a - b)
    : Array.from({ length: state.trace.nFrames }, (_, i) => i);
  $("show-all").classList.toggle("active", !state.onlyBreakpoints);
  $("show-breakpoints").classList.toggle("active", state.onlyBreakpoints);
  $("show-all").setAttribute("aria-pressed", String(!state.onlyBreakpoints));
  $("show-breakpoints").setAttribute(
    "aria-pressed",
    String(state.onlyBreakpoints),
  );
  $("breakpoint-count").textContent = state.breakpoints.size;
  $("empty-list").hidden = state.visible.length > 0;
  $("empty-list").textContent = state.onlyBreakpoints
    ? "No breakpoints. Press B to set one on the selected frame."
    : "No instruction frames in this trace.";
  renderInstructions();
}

function renderInstructions() {
  if (!state.trace) return;
  const scroll = $("disasm-scroll");
  const start = Math.min(
    Math.max(0, state.visible.length - 1),
    Math.max(
      0,
      Math.floor(Math.max(0, scroll.scrollTop - HEADER_HEIGHT) / ROW_HEIGHT) -
        8,
    ),
  );
  const end = Math.min(
    state.visible.length,
    start + Math.ceil(scroll.clientHeight / ROW_HEIGHT) + 18,
  );
  const rows = [];
  const spacer = (height) =>
    `<tr class="spacer-row" aria-hidden="true"><td colspan="5" style="height:${height}px"></td></tr>`;
  if (start) rows.push(spacer(start * ROW_HEIGHT));
  for (let position = start; position < end; position++) {
    const index = state.visible[position],
      frame = state.trace.frames[index];
    const marked = state.breakpoints.has(index);
    const instruction = frame.mnemonic || ".byte";
    const operands = frame.mnemonic
      ? frame.operands
      : Emtr.opcodeHex(frame.opcode);
    rows.push(`<tr data-index="${index}" class="${index === state.index ? "selected" : ""}" aria-selected="${index === state.index}">
      <td><button class="breakpoint-toggle ${marked ? "marked" : ""}" data-breakpoint="${index}" aria-label="${marked ? "Remove breakpoint from" : "Set breakpoint on"} frame ${index + 1}" aria-pressed="${marked}" title="Breakpoint frame">${marked ? "◆" : "◇"}</button></td>
      <td>${index + 1}</td><td>${Emtr.hex(frame.address, frame.archId)}</td><td class="opcode" title="${Emtr.opcodeHex(frame.opcode)}">${Emtr.opcodeHex(frame.opcode)}</td>
      <td class="instruction" title="${escapeHTML(instruction + " " + operands)}"><b>${escapeHTML(instruction)}</b> ${escapeHTML(operands)}</td></tr>`);
  }
  if (end < state.visible.length)
    rows.push(spacer((state.visible.length - end) * ROW_HEIGHT));
  $("disasm-body").innerHTML = rows.join("");
}

function selectFrame(index, { reveal = true } = {}) {
  if (
    !state.trace ||
    !Number.isInteger(index) ||
    index < 0 ||
    index >= state.trace.nFrames
  )
    return;
  state.index = index;
  const frame = state.trace.frames[index];
  $("frame-input").value = index + 1;
  $("frame-slider").value = index;
  $("status-detail").textContent =
    `${Emtr.hex(frame.address, frame.archId)} · ${Emtr.architectures[frame.archId].name}`;
  const visits = state.hits.get(frame.address);
  $("execution-caption").textContent =
    `${Emtr.hex(frame.address, frame.archId)} · executed ${visits.toLocaleString()} ${visits === 1 ? "time" : "times"}`;
  if (reveal) {
    if (state.onlyBreakpoints && !state.breakpoints.has(index)) {
      state.onlyBreakpoints = false;
      rebuildVisible();
    }
    const position = state.onlyBreakpoints
      ? state.visible.indexOf(index)
      : index;
    const scroll = $("disasm-scroll"),
      top = position * ROW_HEIGHT;
    if (top < scroll.scrollTop) scroll.scrollTop = top;
    else if (
      top + ROW_HEIGHT >
      scroll.scrollTop + scroll.clientHeight - HEADER_HEIGHT
    )
      scroll.scrollTop = top + ROW_HEIGHT - scroll.clientHeight + HEADER_HEIGHT;
  }
  renderInstructions();
  state.highlights = state.changeHistory(index);
  renderRegisters();
  renderStack();
  updateSearchInfo();
  $("pb-first").disabled = $("pb-prev").disabled = index === 0;
  $("pb-next").disabled = $("pb-last").disabled =
    index === state.trace.nFrames - 1;
  if (index === state.trace.nFrames - 1) stopPlayback();
}

function renderRegisters() {
  if (!state.trace?.nFrames) return;
  const frame = state.trace.frames[state.index],
    previous = state.trace.frames[state.index - 1];
  const spec = Emtr.architectures[frame.archId];
  const changes = state.highlights.registers;
  $("reg-count").textContent = Object.keys(frame.regs).length;
  $("register-summary").textContent = previous
    ? `${changes.size} highlighted · ${state.highlights.registerFrame >= 0 ? `last register update at frame ${state.highlights.registerFrame + 1}` : "instruction pointer only"}`
    : "Initial captured state";
  const entries = Object.entries(frame.regs).filter(
    ([name]) => !$("changed-only").checked || changes.has(name),
  );
  $("reg-body").innerHTML =
    entries
      .map(([name, value]) => {
        const role = name === spec.sp ? "SP" : name === spec.pc ? "PC" : "";
        return `<tr class="${changes.has(name) ? "changed" : ""}"><td>${escapeHTML(name)}${role && role !== name ? `<span class="reg-role">${role}</span>` : ""}</td><td>${Emtr.hex(value, frame.archId)}</td><td>${changes.has(name) ? Emtr.hex(changes.get(name), frame.archId) : "—"}</td></tr>`;
      })
      .join("") ||
    '<tr><td colspan="3" class="panel-empty">No register changes in this frame.</td></tr>';
  const flagValue = frame.regs[spec.flags];
  let flags = [];
  if (spec.flags === "EFLAGS")
    flags = [
      ["CF", 0],
      ["PF", 2],
      ["AF", 4],
      ["ZF", 6],
      ["SF", 7],
      ["TF", 8],
      ["IF", 9],
      ["DF", 10],
      ["OF", 11],
    ];
  if (["CPSR", "NZCV", "XPSR"].includes(spec.flags))
    flags = [
      ["N", 31],
      ["Z", 30],
      ["C", 29],
      ["V", 28],
      ...(spec.flags === "CPSR"
        ? [["T", 5]]
        : spec.flags === "XPSR"
          ? [["T", 24]]
          : []),
    ];
  if (spec.flags === "SR")
    flags = [
      ["X", 4],
      ["N", 3],
      ["Z", 2],
      ["V", 1],
      ["C", 0],
    ];
  $("flags-area").innerHTML =
    flagValue === undefined
      ? ""
      : flags
          .map(
            ([name, bit]) =>
              `<span class="flag ${flagValue & (1n << BigInt(bit)) ? "on" : ""}" title="${name}: ${Number((flagValue >> BigInt(bit)) & 1n)}">${name} ${Number((flagValue >> BigInt(bit)) & 1n)}</span>`,
          )
          .join("");
}

function renderStack() {
  const frame = state.trace.frames[state.index],
    previous = state.trace.frames[state.index - 1];
  const changes = Emtr.stackChanges(frame, previous);
  $("stack-address").textContent = `SP ${Emtr.hex(frame.sp, frame.archId)}`;
  $("stack-size").textContent = `${frame.stack.length} bytes`;
  $("byte-order").textContent =
    `${Emtr.architectures[frame.archId].endian === "big" ? "Big" : "Little"} endian`;
  state.stackChanges = changes;
  renderStackRows();
  $("stack-summary").textContent = previous
    ? `${changes.filter((c) => c === "changed").length} changed · ${changes.filter((c) => c === "new").length} newly visible${state.highlights.stackFrame >= 0 ? ` · red: frame ${state.highlights.stackFrame + 1}` : ""}`
    : "Initial memory snapshot";
}

function renderStackRows() {
  if (!state.trace?.nFrames) return;
  const frame = state.trace.frames[state.index],
    changes = state.stackChanges;
  const scroll = $("stack-scroll"),
    rowHeight = ROW_HEIGHT;
  const asValues = $("stack-format").value === "values";
  const wordSize = Emtr.architectures[frame.archId].bits / 8;
  const rowBytes = asValues ? wordSize : 8;
  $("stack-value-heading").textContent = asValues
    ? `Value · ${wordSize * 8}-bit`
    : "Bytes · address order";
  const count = Math.ceil(frame.stack.length / rowBytes);
  const start = Math.min(
    Math.max(0, count - 1),
    Math.max(
      0,
      Math.floor(Math.max(0, scroll.scrollTop - HEADER_HEIGHT) / rowHeight) - 4,
    ),
  );
  const end = Math.min(
    count,
    start + Math.ceil(scroll.clientHeight / rowHeight) + 10,
  );
  const rows = [];
  const spacer = (height) =>
    `<tr class="spacer-row" aria-hidden="true"><td colspan="3" style="height:${height}px"></td></tr>`;
  if (start) rows.push(spacer(start * rowHeight));
  for (
    let offset = start * rowBytes;
    offset < end * rowBytes;
    offset += rowBytes
  ) {
    const chunk = frame.stack.subarray(offset, offset + rowBytes);
    const ordered = asValues
      ? Emtr.stackWord(chunk, frame.archId).bytes
      : Array.from(chunk, (value, offset) => ({ value, offset }));
    const bytes = ordered
      .map(({ value, offset: byteOffset }) => {
        if (value === undefined)
          return '<span class="byte unknown" title="Byte not captured">??</span>';
        const index = offset + byteOffset;
        return `<span class="byte ${changes[index]} ${state.highlights.stack.has(index) ? "highlighted" : ""}" data-stack-offset="${index}" title="${Emtr.hex(frame.sp + BigInt(index), frame.archId)} · ${changes[index] === "new" ? "Not captured in preceding frame" : changes[index]}">${Emtr.hexByte(value)}</span>`;
      })
      .join(asValues ? "" : " ");
    const ascii = Array.from(chunk, (value) =>
      value >= 32 && value < 127 ? String.fromCharCode(value) : ".",
    ).join("");
    rows.push(
      `<tr data-stack-row="${offset}"><td>${Emtr.hex(frame.sp + BigInt(offset), frame.archId)}</td><td class="stack-value ${asValues && Array.from(chunk, (_, i) => state.highlights.stack.has(offset + i)).some(Boolean) ? "highlighted" : ""}">${bytes}</td><td>${escapeHTML(ascii)}</td></tr>`,
    );
  }
  if (end < count) rows.push(spacer((count - end) * rowHeight));
  $("stack-body").innerHTML =
    rows.join("") ||
    '<tr><td colspan="3" class="panel-empty">No stack bytes captured at this address.<br>The stack may be unmapped or capture disabled.</td></tr>';
}

function clearPanels() {
  $("reg-body").innerHTML =
    '<tr><td class="panel-empty">No register state captured.</td></tr>';
  $("stack-body").innerHTML =
    '<tr><td class="panel-empty">No stack snapshot captured.</td></tr>';
  for (const id of [
    "reg-count",
    "flags-area",
    "register-summary",
    "stack-address",
    "stack-size",
    "stack-summary",
    "byte-order",
  ])
    $(id).textContent = "";
  $("execution-caption").textContent = "No instruction frames";
  $("status-detail").textContent = "Empty trace";
  $("frame-input").value = 1;
  $("frame-slider").value = 0;
}

function toggleBreakpoint(index) {
  if (!state.trace?.frames[index]) return;
  if (state.breakpoints.has(index)) state.breakpoints.delete(index);
  else state.breakpoints.add(index);
  rebuildVisible();
}
function stopPlayback() {
  if (state.timer !== null) clearInterval(state.timer);
  state.timer = null;
  $("pb-play").textContent = "▶";
  $("pb-play").setAttribute("aria-label", "Play");
  $("pb-play").setAttribute("aria-pressed", "false");
}
function togglePlay() {
  if (state.timer !== null) {
    stopPlayback();
    return;
  }
  if (!state.trace?.nFrames) return;
  if (state.index === state.trace.nFrames - 1) selectFrame(0);
  $("pb-play").textContent = "Ⅱ";
  $("pb-play").setAttribute("aria-label", "Pause");
  $("pb-play").setAttribute("aria-pressed", "true");
  state.timer = setInterval(
    () => {
      selectFrame(state.index + 1);
      if (
        state.breakpoints.has(state.index) ||
        state.index >= state.trace.nFrames - 1
      )
        stopPlayback();
    },
    Number($("play-speed").value),
  );
}
function navigate(index) {
  stopPlayback();
  selectFrame(index);
}

function search() {
  const query = $("search-input").value.trim().toLowerCase();
  state.query = query;
  state.matches = [];
  if (!query || !state.trace) {
    $("search-info").textContent = "";
    return;
  }
  state.trace.frames.forEach((frame, index) => {
    if (
      `${Emtr.hex(frame.address, frame.archId)} ${frame.mnemonic} ${frame.operands} ${Emtr.opcodeHex(frame.opcode)}`
        .toLowerCase()
        .includes(query)
    )
      state.matches.push(index);
  });
  if (state.matches.length) {
    const match =
      state.matches.find((index) => index >= state.index) ?? state.matches[0];
    navigate(match);
  }
  updateSearchInfo();
}
function updateSearchInfo() {
  const position = state.matches.indexOf(state.index);
  $("search-info").textContent = !state.query
    ? ""
    : state.matches.length
      ? `${position < 0 ? "—" : position + 1} / ${state.matches.length}`
      : "No matches";
}
function searchNext(direction = 1) {
  clearTimeout(searchTimer);
  if (state.query !== $("search-input").value.trim().toLowerCase()) {
    search();
    return;
  }
  if (!state.matches.length) return;
  const matches = state.matches;
  const target =
    direction > 0
      ? (matches.find((index) => index > state.index) ?? matches[0])
      : (matches
          .slice()
          .reverse()
          .find((index) => index < state.index) ?? matches[matches.length - 1]);
  navigate(target);
  updateSearchInfo();
}
function followRegister(direction) {
  const name = $("watch-register").value;
  if (!name || !state.trace) return;
  for (
    let index = state.index + direction;
    index > 0 && index < state.trace.nFrames;
    index += direction
  ) {
    if (
      Emtr.registerChanges(
        state.trace.frames[index],
        state.trace.frames[index - 1],
      ).includes(name)
    ) {
      navigate(index);
      status(`${name} changed at frame ${index + 1}.`);
      return;
    }
  }
  status(`No ${direction > 0 ? "later" : "earlier"} changes to ${name}.`);
}

$("open-file").onclick = $("welcome-open").onclick = () =>
  $("file-input").click();
$("file-input").onchange = (event) => {
  handleFile(event.target.files[0]);
  event.target.value = "";
};
$("load-demo").onclick = () => {
  if (typeof DEMO_TRACE_BASE64 === "undefined") {
    status("Example trace is unavailable.", true);
    return;
  }
  loadBuffer(
    Uint8Array.from(atob(DEMO_TRACE_BASE64), (c) => c.charCodeAt(0)).buffer,
    "example_x86_64.emtr",
  );
};
$("disasm-scroll").addEventListener("scroll", () => {
  if (!scrollRequest)
    scrollRequest = requestAnimationFrame(() => {
      scrollRequest = null;
      renderInstructions();
    });
});
new ResizeObserver(renderInstructions).observe($("disasm-scroll"));
let stackScrollRequest;
$("stack-scroll").addEventListener("scroll", () => {
  if (!stackScrollRequest)
    stackScrollRequest = requestAnimationFrame(() => {
      stackScrollRequest = null;
      renderStackRows();
    });
});
new ResizeObserver(renderStackRows).observe($("stack-scroll"));
$("disasm-body").onclick = (event) => {
  const breakpoint = event.target.closest("[data-breakpoint]");
  if (breakpoint) {
    toggleBreakpoint(Number(breakpoint.dataset.breakpoint));
    return;
  }
  const row = event.target.closest("[data-index]");
  if (row) navigate(Number(row.dataset.index));
};
$("disasm-body").ondblclick = (event) => {
  if (event.target.closest("button")) return;
  const row = event.target.closest("[data-index]");
  if (row) toggleBreakpoint(Number(row.dataset.index));
};
$("show-all").onclick = () => {
  if (state.trace) {
    state.onlyBreakpoints = false;
    $("disasm-scroll").scrollTop = 0;
    rebuildVisible();
  }
};
$("show-breakpoints").onclick = () => {
  if (state.trace) {
    stopPlayback();
    state.onlyBreakpoints = true;
    $("disasm-scroll").scrollTop = 0;
    rebuildVisible();
  }
};
$("pb-first").onclick = () => navigate(0);
$("pb-prev").onclick = () => navigate(state.index - 1);
$("pb-next").onclick = () => navigate(state.index + 1);
$("pb-last").onclick = () => navigate(state.trace.nFrames - 1);
$("pb-play").onclick = togglePlay;
$("play-speed").onchange = () => {
  if (state.timer !== null) {
    stopPlayback();
    togglePlay();
  }
};
$("frame-slider").oninput = (event) => navigate(Number(event.target.value));
$("frame-input").onchange = (event) => {
  const index = Number(event.target.value) - 1;
  if (state.trace?.nFrames)
    navigate(Math.max(0, Math.min(state.trace.nFrames - 1, Math.trunc(index))));
  event.target.value = state.index + 1;
};
$("changed-only").onchange = renderRegisters;
$("stack-format").onchange = () => {
  $("stack-scroll").scrollTop = 0;
  renderStackRows();
};
$("watch-prev").onclick = () => followRegister(-1);
$("watch-next").onclick = () => followRegister(1);
$("search-input").oninput = () => {
  clearTimeout(searchTimer);
  searchTimer = setTimeout(search, 120);
};
$("search-input").onkeydown = (event) => {
  if (event.key === "Enter") {
    event.preventDefault();
    searchNext(event.shiftKey ? -1 : 1);
  }
};
$("search-prev").onclick = () => searchNext(-1);
$("search-next").onclick = () => searchNext(1);
$("export-frame").onclick = () => {
  if (!state.trace?.nFrames) return;
  const blob = new Blob(
    [Emtr.frameJSON(state.trace.frames[state.index], state.index) + "\n"],
    { type: "application/json" },
  );
  const url = URL.createObjectURL(blob),
    anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = `emutrace-frame-${state.index + 1}.json`;
  anchor.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
  status(`Exported frame ${state.index + 1} as JSON.`);
};
$("help-open").onclick = () => {
  stopPlayback();
  $("help-dialog").showModal();
};
$("help-close").onclick = () => $("help-dialog").close();
let theme = window.matchMedia("(prefers-color-scheme: dark)").matches
  ? "dark"
  : "light";
try {
  theme = localStorage.getItem("emutrace-theme") || theme;
} catch {
  /* Storage may be disabled for local files. */
}
document.documentElement.dataset.theme = theme;
$("theme-toggle").onclick = () => {
  theme = theme === "dark" ? "light" : "dark";
  document.documentElement.dataset.theme = theme;
  try {
    localStorage.setItem("emutrace-theme", theme);
  } catch {
    /* Optional preference. */
  }
};
document.addEventListener("keydown", (event) => {
  if (
    event.ctrlKey ||
    event.metaKey ||
    event.altKey ||
    event.target.closest(
      "input,select,textarea,button,[contenteditable=true]",
    ) ||
    $("help-dialog").open
  )
    return;
  const actions = {
    ArrowRight: () => navigate(state.index + 1),
    n: () => navigate(state.index + 1),
    ArrowLeft: () => navigate(state.index - 1),
    p: () => navigate(state.index - 1),
    " ": togglePlay,
    Home: () => navigate(0),
    End: () => navigate((state.trace?.nFrames || 0) - 1),
    b: () => toggleBreakpoint(state.index),
    F2: () => toggleBreakpoint(state.index),
    "/": () => $("search-input").focus(),
  };
  if (actions[event.key]) {
    event.preventDefault();
    actions[event.key]();
  }
});
let dragDepth = 0;
document.addEventListener("dragenter", (event) => {
  if (Array.from(event.dataTransfer?.types || []).includes("Files")) {
    event.preventDefault();
    dragDepth++;
    $("drop-overlay").hidden = false;
  }
});
document.addEventListener("dragover", (event) => {
  if (Array.from(event.dataTransfer?.types || []).includes("Files"))
    event.preventDefault();
});
document.addEventListener("dragleave", () => {
  dragDepth = Math.max(0, dragDepth - 1);
  if (!dragDepth) $("drop-overlay").hidden = true;
});
document.addEventListener("drop", (event) => {
  event.preventDefault();
  dragDepth = 0;
  $("drop-overlay").hidden = true;
  handleFile(event.dataTransfer?.files[0]);
});
document.addEventListener("visibilitychange", () => {
  if (document.hidden) stopPlayback();
});

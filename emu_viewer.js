// ════════════════════════════════════════════════════════════════════════════
//  Binary parser for .emtr format
// ════════════════════════════════════════════════════════════════════════════

const MAGIC   = 0x52544D45;   // "EMTR" LE
const VERSION = 1;

const ARCH_NAMES = {
  0: "ARM16 (Thumb)", 1: "ARM32", 2: "ARM64",
  3: "x86",           4: "x86-64",
  5: "MIPS (BE)",     6: "MIPS (LE)",
  7: "MIPS64 (BE)",   8: "MIPS64 (LE)",
};

// SP register names per arch
const SP_NAMES = {
  0:"SP", 1:"SP", 2:"SP",
  3:"ESP", 4:"RSP",
  5:"sp",  6:"sp", 7:"sp", 8:"sp",
};
// PC/IP register names per arch
const PC_NAMES = {
  0:"PC", 1:"PC", 2:"PC",
  3:"EIP", 4:"RIP",
  5:"PC", 6:"PC", 7:"PC", 8:"PC",
};
// FLAGS register name per arch
const FLAGS_NAMES = {
  3:"EFLAGS", 4:"EFLAGS",
};

// x86 EFLAGS bit definitions
const EFLAGS_BITS = [
  {bit:0, name:"CF"}, {bit:2, name:"PF"}, {bit:4, name:"AF"},
  {bit:6, name:"ZF"}, {bit:7, name:"SF"}, {bit:8, name:"TF"},
  {bit:9, name:"IF"}, {bit:10,name:"DF"}, {bit:11,name:"OF"},
];

// ── inflate via DecompressionStream (modern browsers) ─────────────────────
async function inflate(compressed) {
  const ds = new DecompressionStream("deflate");
  const writer = ds.writable.getWriter();
  writer.write(compressed);
  writer.close();
  const chunks = [];
  const reader = ds.readable.getReader();
  while (true) {
    const { value, done } = await reader.read();
    if (done) break;
    chunks.push(value);
  }
  let total = chunks.reduce((s, c) => s + c.length, 0);
  const out = new Uint8Array(total);
  let pos = 0;
  for (const c of chunks) { out.set(c, pos); pos += c.length; }
  return out;
}

async function parseEmtr(buffer) {
  const dv = new DataView(buffer);
  const magic = dv.getUint32(0, true);
  if (magic !== MAGIC) throw new Error("Bad magic – not a .emtr file");
  const version = dv.getUint32(4, true);
  if (version !== VERSION) throw new Error("Unsupported version " + version);
  const archId  = dv.getUint32(8,  true);
  const nFrames = dv.getUint32(12, true);

  // decompress the rest
  const compressed = new Uint8Array(buffer, 16);
  const payload = await inflate(compressed);

  // parse frames
  const frames = [];
  let off = 0;
  const pdv = new DataView(payload.buffer);

  function readU8()  { return payload[off++]; }
  function readU16() { const v = pdv.getUint16(off, true); off += 2; return v; }
  function readU32() { const v = pdv.getUint32(off, true); off += 4; return v; }
  function readU64() {
    const lo = pdv.getUint32(off, true);
    const hi = pdv.getUint32(off+4, true);
    off += 8;
    return hi * 0x100000000 + lo;
  }
  function readBytes(n) { const b = payload.slice(off, off+n); off += n; return b; }
  function readStr(n)   { return new TextDecoder().decode(readBytes(n)); }

  for (let i = 0; i < nFrames; i++) {
    const address   = readU64();
    const opcodeLen = readU16();
    const opcode    = readBytes(opcodeLen);

    const nRegs = readU16();
    const regs = {};
    for (let r = 0; r < nRegs; r++) {
      const nameLen = readU8();
      const name    = readStr(nameLen);
      const val     = readU64();
      regs[name] = val;
    }

    const sp      = readU64();
    const nStack  = readU32();
    const stack   = readBytes(nStack);

    frames.push({ address, opcode, regs, sp, stack });
  }

  return { archId, archName: ARCH_NAMES[archId] || "Unknown", nFrames, frames };
}

// ════════════════════════════════════════════════════════════════════════════
//  Disassembly  – using Capstone.js (wasm) if available, else hex-only
// ════════════════════════════════════════════════════════════════════════════

// Capstone architecture / mode per arch id
const CS_ARCH_MODE = {
  0: [0, 1 << 4],             // ARM16
  1: [0, 0],                  // ARM32
  2: [1, 0],                  // ARM64
  3: [3, 1 << 2],             // X86 
  4: [3, 1 << 3],             // X86_64
  5: [2, (1 << 2)|(1 << 31)], // MIPS
  6: [2, 1 << 2],             // MIPSEL
  7: [2, (1 << 3)|(1 << 31)], // MIPS64
  8: [2, 1 << 3],             // MIPS64EL
};

// Resolves to true once window.cs is fully initialised, false on failure.
function loadCapstone() {
  return new Promise((resolve) => {

    // Already initialised from a previous call – nothing to do.
    if (window.cs && window.cs.Capstone) { resolve(true); return; }

    // Module exists but hasn't finished init yet – hook the callback.
    if (window.cs && !window.cs.Capstone) {
      const orig = window.cs.onRuntimeInitialized;
      window.cs.onRuntimeInitialized = function() {
        if (orig) orig.call(this);
        resolve(!!window.cs.Capstone);
      };
      return;
    }
    
    window.Module = window.Module || {};
    window.Module.onRuntimeInitialized = function() {
      resolve(!!(window.cs && window.cs.Capstone));
    };

    const s = document.createElement('script');
    s.src = './capstone.min.js';
    s.onerror = () => resolve(false);
    document.head.appendChild(s);
    setTimeout(() => resolve(!!(window.cs && window.cs.Capstone)), 300);
  });
}

async function disassemble(archId, address, opcodeBytes) {
  if (window.cs && window.cs.Capstone) {
    try {
      const [arch, mode] = CS_ARCH_MODE[archId] || [3, 1 << 3];
      const ud = new cs.Capstone(arch, mode);
      const insns = ud.disasm(Array.from(opcodeBytes), address);
      ud.close();
      if (insns && insns.length > 0) {
        return { mnem: insns[0].mnemonic, ops: insns[0].op_str };
      }
    } catch (e) { console.log(e); }
  }
  // Fallback when Capstone is unavailable or fails
  return {
    mnem: "db",
    ops: Array.from(opcodeBytes)
           .map(b => `0x${b.toString(16).padStart(2, '0')}`)
           .join(', '),
  };
}

// ════════════════════════════════════════════════════════════════════════════
//  State
// ════════════════════════════════════════════════════════════════════════════
let trace     = null;   // parsed trace object
let curFrame  = 0;      // currently selected frame index
let disasmCache = [];   // { address, opcodeHex, mnem, ops } per frame
let breakpoints = new Set();
let searchResults = [];
let searchIdx = 0;
let playInterval = null;
let prevRegs = null;

// ════════════════════════════════════════════════════════════════════════════
//  UI helpers
// ════════════════════════════════════════════════════════════════════════════

function hexByte(b) { return b.toString(16).padStart(2,'0'); }
function hexWord(v, w=8) {
  if (v > Number.MAX_SAFE_INTEGER) {
    // BigInt path not needed here since we already split to JS number
    return v.toString(16).padStart(w,'0');
  }
  return v.toString(16).padStart(w,'0');
}

function formatAddr(v, archId) {
  const w = (archId === 2 || archId === 4 || archId === 7 || archId === 8) ? 16 : 8;
  return '0x' + hexWord(v, w);
}

function formatOpcodeColored(bytes) {
  const colors = ['ob0','ob1','ob2','ob3','ob4','ob5'];
  return Array.from(bytes)
    .map((b,i) => `<span class="${colors[i % colors.length]}">${hexByte(b)}</span>`)
    .join(' ');
}

function setStatus(msg, cls='') {
  const el = document.getElementById('status-msg');
  el.textContent = msg;
  el.className = cls;
}

// ════════════════════════════════════════════════════════════════════════════
//  Load & initialise
// ════════════════════════════════════════════════════════════════════════════

async function loadTrace(buffer) {
  setStatus("Parsing …");
  try {
    trace = await parseEmtr(buffer);
  } catch(e) {
    setStatus("❌ " + e.message, 'status-err');
    return;
  }

  // Try to load capstone
  const ok = await loadCapstone();
  setStatus(ok ? "Capstone loaded – disassembling …" : "Capstone unavailable – raw bytes mode");

  // Pre-disassemble all frames
  disasmCache = [];
  for (const f of trace.frames) {
    const d = await disassemble(trace.archId, f.address, f.opcode);
    const opcHex = Array.from(f.opcode).map(hexByte).join(' ');
    disasmCache.push({ address: f.address, opcodeHex: opcHex, ...d });
  }

  // Populate disassembly table (all rows, virtual)
  buildDisasmTable();

  // Update UI chrome
  document.getElementById('arch-badge').textContent = trace.archName;
  document.getElementById('frame-counter').textContent = `${trace.nFrames} frames`;
  document.getElementById('disasm-badge').textContent = `${trace.nFrames} insns`;

  const slider = document.getElementById('frame-slider');
  slider.max   = trace.nFrames - 1;
  slider.value = 0;

  document.getElementById('drop-overlay').classList.add('hidden');
  prevRegs = null;
  selectFrame(0);
  setStatus(`Loaded ${trace.nFrames.toLocaleString()} frames · ${ARCH_NAMES[trace.archId]}`, 'status-ok');
}

// ════════════════════════════════════════════════════════════════════════════
//  Disassembly table
// ════════════════════════════════════════════════════════════════════════════

function buildDisasmTable() {
  const tbody = document.getElementById('disasm-body');
  const frag  = document.createDocumentFragment();
  for (let i = 0; i < disasmCache.length; i++) {
    const d = disasmCache[i];
    const tr = document.createElement('tr');
    tr.className = 'disasm-row';
    tr.dataset.idx = i;
    tr.innerHTML = `
      <td class="row-idx">${i}</td>
      <td class="row-addr">${formatAddr(d.address, trace.archId)}</td>
      <td class="row-opcode">${formatOpcodeColored(trace.frames[i].opcode)}</td>
      <td class="row-mnem">${escHtml(d.mnem)}</td>
      <td class="row-ops">${escHtml(d.ops)}</td>
    `;
    tr.addEventListener('click', () => {
      selectFrame(i);
    });
    tr.addEventListener('dblclick', () => toggleBreakpoint(i));
    frag.appendChild(tr);
  }
  tbody.innerHTML = '';
  tbody.appendChild(frag);
}

function escHtml(s) {
  return String(s)
    .replace(/&/g,'&amp;')
    .replace(/</g,'&lt;')
    .replace(/>/g,'&gt;');
}

function highlightRow(idx) {
  const tbody = document.getElementById('disasm-body');
  // remove old
  const prev = tbody.querySelector('.selected');
  if (prev) prev.classList.remove('selected');
  const row = tbody.querySelector(`tr[data-idx="${idx}"]`);
  if (!row) return;
  row.classList.add('selected');
  // scroll into view
  row.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
}

function toggleBreakpoint(idx) {
  if (breakpoints.has(idx)) {
    breakpoints.delete(idx);
  } else {
    breakpoints.add(idx);
  }
  const row = document.getElementById('disasm-body').querySelector(`tr[data-idx="${idx}"]`);
  if (row) row.classList.toggle('breakpoint', breakpoints.has(idx));
}

// ════════════════════════════════════════════════════════════════════════════
//  Frame selection
// ════════════════════════════════════════════════════════════════════════════

function selectFrame(idx) {
  if (!trace || idx < 0 || idx >= trace.nFrames) return;
  const oldFrame = curFrame;
  curFrame = idx;

  const frame = trace.frames[idx];
  const d     = disasmCache[idx];

  // slider
  document.getElementById('frame-slider').value = idx;
  document.getElementById('slider-label').textContent = `${idx} / ${trace.nFrames - 1}`;

  // status
  document.getElementById('status-addr').textContent = formatAddr(frame.address, trace.archId);
  document.getElementById('status-opcode').textContent = d.mnem + ' ' + d.ops;

  // highlight row
  highlightRow(idx);

  // registers
  updateRegs(frame, prevRegs);
  prevRegs = { ...frame.regs };

  // stack
  updateStack(frame);
}

// ════════════════════════════════════════════════════════════════════════════
//  Register panel
// ════════════════════════════════════════════════════════════════════════════

function updateRegs(frame, prev) {
  const tbody    = document.getElementById('reg-body');
  const flagsDiv = document.getElementById('flags-area');
  const spName   = SP_NAMES[trace.archId]  || 'SP';
  const pcName   = PC_NAMES[trace.archId]  || 'PC';
  const flgName  = FLAGS_NAMES[trace.archId];
  const archId   = trace.archId;

  const rows = [];
  for (const [name, val] of Object.entries(frame.regs)) {
    const changed = prev && prev[name] !== val;
    const addrStr = formatAddr(val, archId);
    let cls = 'reg-val';
    if (name === spName)  cls += ' reg-sp';
    if (name === pcName)  cls += ' reg-pc';
    if (name === flgName) cls += ' reg-flags';
    if (changed)          cls += ' changed';

    const diff = (changed && prev)
      ? ` <span style="font-size:10px;color:var(--text-dim)">← ${formatAddr(prev[name], archId)}</span>`
      : '';

    rows.push(`<tr>
      <td class="reg-name">${escHtml(name)}</td>
      <td class="${cls}">${addrStr}${diff}</td>
    </tr>`);
  }
  tbody.innerHTML = rows.join('');

  // Flags
  if (flgName && frame.regs[flgName] !== undefined) {
    const f = frame.regs[flgName];
    flagsDiv.innerHTML = EFLAGS_BITS.map(fb => {
      const on = (f >> fb.bit) & 1;
      return `<span class="flag-bit ${on?'on':''}">${fb.name}</span>`;
    }).join('');
  } else {
    flagsDiv.innerHTML = '';
  }
}

// ════════════════════════════════════════════════════════════════════════════
//  Stack panel
// ════════════════════════════════════════════════════════════════════════════

function updateStack(frame) {
  const tbody  = document.getElementById('stack-body');
  const badge  = document.getElementById('stack-badge');
  const archId = trace.archId;
  const sp     = frame.sp;
  const data   = frame.stack;

  badge.textContent = 'SP: ' + formatAddr(sp, archId);

  const wordSize = (archId === 2 || archId === 4 || archId === 7 || archId === 8) ? 8 : 4;
  const rowBytes = wordSize * 2;   // show 2 words per row for readability
  const rows = [];

  for (let off = 0; off < data.length; off += rowBytes) {
    const addr   = sp + off;
    const chunk  = data.slice(off, off + rowBytes);
    const hexStr = Array.from(chunk).map(hexByte).join(' ');
    const ascii  = Array.from(chunk).map(b =>
      (b >= 0x20 && b < 0x7f) ? String.fromCharCode(b) : '.'
    ).join('');
    const isSP = off === 0;
    rows.push(`<tr class="${isSP ? 'stk-sp-row' : ''}">
      <td class="stk-addr">${formatAddr(addr, archId)}</td>
      <td class="stk-hex">${escHtml(hexStr)}</td>
      <td class="stk-ascii">${escHtml(ascii)}</td>
    </tr>`);
  }
  tbody.innerHTML = rows.join('');
}

// ════════════════════════════════════════════════════════════════════════════
//  Playback controls
// ════════════════════════════════════════════════════════════════════════════

function stepNext() {
  if (!trace) return;
  if (curFrame + 1 < trace.nFrames) {
    selectFrame(curFrame + 1);
    // stop at breakpoint
    if (breakpoints.has(curFrame) && playInterval) togglePlay();
  } else {
    if (playInterval) togglePlay();
  }
}
function stepPrev()  { if (trace) selectFrame(curFrame - 1); }
function gotoFirst() { if (trace) selectFrame(0); }
function gotoLast()  { if (trace) selectFrame(trace.nFrames - 1); }

function togglePlay() {
  const btn = document.getElementById('pb-play');
  if (playInterval) {
    clearInterval(playInterval);
    playInterval = null;
    btn.textContent = '▶';
    btn.classList.remove('active');
  } else {
    btn.textContent = '⏸';
    btn.classList.add('active');
    playInterval = setInterval(stepNext, 80);
  }
}

document.getElementById('pb-first').onclick = gotoFirst;
document.getElementById('pb-prev').onclick  = stepPrev;
document.getElementById('pb-play').onclick  = togglePlay;
document.getElementById('pb-next').onclick  = stepNext;
document.getElementById('pb-last').onclick  = gotoLast;

// ════════════════════════════════════════════════════════════════════════════
//  Keyboard
// ════════════════════════════════════════════════════════════════════════════

document.addEventListener('keydown', e => {
  if (e.target.tagName === 'INPUT') return;
  if (e.key === 'ArrowRight' || e.key === 'n') { stepNext(); e.preventDefault(); }
  if (e.key === 'ArrowLeft'  || e.key === 'p') { stepPrev(); e.preventDefault(); }
  if (e.key === ' ') { togglePlay(); e.preventDefault(); }
  if (e.key === 'Home') { gotoFirst(); e.preventDefault(); }
  if (e.key === 'End')  { gotoLast();  e.preventDefault(); }
  if (e.key === 'b' || e.key === 'F2') { toggleBreakpoint(curFrame); e.preventDefault(); }
});

// ════════════════════════════════════════════════════════════════════════════
//  Slider
// ════════════════════════════════════════════════════════════════════════════

document.getElementById('frame-slider').addEventListener('input', function() {
  selectFrame(parseInt(this.value));
});

// ════════════════════════════════════════════════════════════════════════════
//  Search
// ════════════════════════════════════════════════════════════════════════════

function runSearch(query) {
  if (!trace || !query.trim()) {
    searchResults = [];
    document.getElementById('search-info').textContent = '';
    return;
  }
  const q = query.toLowerCase().trim();
  searchResults = [];
  for (let i = 0; i < disasmCache.length; i++) {
    const d = disasmCache[i];
    if (
      formatAddr(d.address, trace.archId).includes(q) ||
      d.mnem.toLowerCase().includes(q) ||
      d.ops.toLowerCase().includes(q) ||
      d.opcodeHex.includes(q)
    ) {
      searchResults.push(i);
    }
  }
  searchIdx = 0;
  updateSearchInfo();
  if (searchResults.length) selectFrame(searchResults[0]);
}

function updateSearchInfo() {
  const el = document.getElementById('search-info');
  if (!searchResults.length) {
    el.textContent = 'No matches';
    el.style.color = 'var(--red)';
  } else {
    el.textContent = `${searchIdx + 1} / ${searchResults.length}`;
    el.style.color = 'var(--green)';
  }
}

document.getElementById('search-input').addEventListener('keydown', e => {
  if (e.key === 'Enter') {
    if (!searchResults.length) {
      runSearch(e.target.value);
    } else {
      searchIdx = (searchIdx + (e.shiftKey ? -1 : 1) + searchResults.length) % searchResults.length;
      updateSearchInfo();
      selectFrame(searchResults[searchIdx]);
    }
    e.preventDefault();
  }
});
document.getElementById('search-input').addEventListener('input', e => {
  runSearch(e.target.value);
});

// ════════════════════════════════════════════════════════════════════════════
//  File loading
// ════════════════════════════════════════════════════════════════════════════

async function handleFile(file) {
  if (!file) return;
  const buf = await file.arrayBuffer();
  await loadTrace(buf);
}

document.getElementById('file-input').addEventListener('change', e => {
  handleFile(e.target.files[0]);
});

// Drag & drop
const overlay = document.getElementById('drop-overlay');
const dropBox = document.getElementById('drop-box');

document.addEventListener('dragover', e => {
  e.preventDefault();
  overlay.classList.remove('hidden');
  dropBox.classList.add('drag-over');
});
document.addEventListener('dragleave', e => {
  if (!e.relatedTarget || e.relatedTarget === document.documentElement) {
    overlay.classList.add('hidden');
    dropBox.classList.remove('drag-over');
  }
});
document.addEventListener('drop', e => {
  e.preventDefault();
  overlay.classList.add('hidden');
  dropBox.classList.remove('drag-over');
  const file = e.dataTransfer.files[0];
  if (file) handleFile(file);
});

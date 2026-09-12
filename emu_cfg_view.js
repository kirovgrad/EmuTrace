/* Offline HTML/SVG graph renderer. Dagre only determines geometry. */
"use strict";
function createCFGView({
  getState,
  navigate,
  openDisassembly,
  toggleBreakpoint,
}) {
  const el = (id) => document.getElementById(id);
  const escape = (value) =>
    String(value).replace(
      /[&<>"']/g,
      (c) =>
        ({
          "&": "&amp;",
          "<": "&lt;",
          ">": "&gt;",
          '"': "&quot;",
          "'": "&#39;",
        })[c],
    );
  const viewport = el("cfg-viewport"),
    stage = el("cfg-stage"),
    scene = el("cfg-scene");
  let trace = null,
    index = null,
    graph = null,
    layout = null;
  let active = false,
    generation = 0,
    building = null,
    zoom = 1;
  let cache = new Map(),
    instructionNodes = new Map(),
    expanded = new Set(),
    renderedSelection = null;
  const labels = {
    flow: "Flow",
    taken: "Taken",
    "not-taken": "Not taken",
    jump: "Jump",
    continuation: "Continue",
    call: "Call",
    return: "Return",
    observed: "Observed",
  };

  function message(text) {
    el("cfg-message").textContent = text;
    el("cfg-message").hidden = false;
    stage.hidden = true;
    for (const button of document.querySelectorAll(".cfg-controls button"))
      button.disabled = true;
  }
  function reset(nextTrace) {
    generation++;
    trace = nextTrace;
    index = null;
    graph = null;
    layout = null;
    building = null;
    cache = new Map();
    instructionNodes = new Map();
    expanded = new Set();
    renderedSelection = null;
    zoom = 1;
    el("cfg-zoom").textContent = "100%";
    el("cfg-note").textContent =
      "Trace-based CFG · function boundaries inferred from calls and returns";
    el("cfg-note").title = el("cfg-note").textContent;
    scene.style.transform = "";
    el("cfg-blocks").replaceChildren();
    el("cfg-edges").replaceChildren();
    el("cfg-function").textContent = "Current function";
    el("cfg-count").textContent = "";
    message(
      trace?.nFrames
        ? "Select CFG to build a graph from the trace."
        : "No instruction frames in this trace.",
    );
  }
  async function ensureIndex() {
    if (index?.done) return true;
    if (building) return building;
    const token = generation;
    const next = EmtrCFG.createIndex(trace.frames);
    building = (async () => {
      while (token === generation) {
        const done = next.advance();
        if (active)
          message(
            `Finding function scopes… ${Math.round(next.progress * 100)}%`,
          );
        // Allow repainting and file replacements during long trace scans.
        await new Promise((resolve) => setTimeout(resolve, 0));
        if (done) break;
      }
      if (token !== generation) return false;
      index = next;
      building = null;
      return true;
    })();
    return building;
  }
  function currentBlock() {
    const frame = getState().trace?.frames[getState().index];
    return frame && graph?.membership?.get(EmtrCFG.instructionKey(frame));
  }
  function visibleInstructions(block) {
    const items = block.instructions;
    if (expanded.has(block.id) || items.length <= 14)
      return { items, start: 0, end: items.length };
    const selected = items.findIndex(
      (item) =>
        item.key === EmtrCFG.instructionKey(trace.frames[getState().index]),
    );
    const start = Math.max(0, Math.min(items.length - 12, selected - 5));
    return { items: items.slice(start, start + 12), start, end: start + 12 };
  }
  function edgeLabel(edge) {
    return `${labels[edge.type]} · ${edge.count ? `${edge.count}×` : "not observed"}`;
  }
  function draw() {
    if (!graph || graph.error) return;
    const g = new dagre.graphlib.Graph({ multigraph: true });
    g.setGraph({
      rankdir: "TB",
      nodesep: 38,
      ranksep: 55,
      edgesep: 16,
      marginx: 20,
      marginy: 16,
    });
    g.setDefaultEdgeLabel(() => ({}));
    const rows = new Map();
    for (const block of graph.blocks) {
      const visible = block.external ? null : visibleInstructions(block);
      if (visible) rows.set(block.id, visible);
      const skips = visible
        ? Number(visible.start > 0) +
          Number(visible.end < block.instructions.length)
        : 0;
      g.setNode(block.id, {
        width: block.external ? 280 : 400,
        height: block.external ? 76 : 56 + 18 * (visible.items.length + skips),
      });
    }
    for (const edge of graph.edges)
      g.setEdge(
        edge.from,
        edge.to,
        { width: edgeLabel(edge).length * 5.4, height: 14, labelpos: "c" },
        edge.id,
      );
    dagre.layout(g);
    layout = g;
    const markup = [];
    for (const block of graph.blocks) {
      const node = g.node(block.id);
      const position = `left:${node.x - node.width / 2}px;top:${node.y - node.height / 2}px;width:${node.width}px;height:${node.height}px`;
      if (block.external) {
        const title =
          block.type === "call"
            ? "Called function"
            : block.type === "return"
              ? "Return to caller"
              : "Code not captured";
        const address =
          block.address === null
            ? "Indirect / unresolved target"
            : Emtr.hex(block.address, block.archId);
        markup.push(
          `<section class="cfg-block external" data-block="${block.id}" style="${position}"><button class="cfg-external-link" data-external="${block.id}" ${block.visits.length ? "" : "disabled"}><span>${title}</span><strong>${address}</strong><span>${block.visits.length ? "Open this execution context ↗" : "No captured instructions at this destination"}</span></button></section>`,
        );
        continue;
      }
      const visible = rows.get(block.id);
      const instructions = visible.items
        .map(
          (item) =>
            `<button class="cfg-instruction" data-instruction="${escape(item.key)}" data-frame="${item.visits[0]}" title="${escape(`${Emtr.hex(item.frame.address, item.frame.archId)} ${item.frame.mnemonic || ".byte"} ${item.frame.operands}`)}"><span>${Emtr.hex(item.frame.address, item.frame.archId)}</span><span><b>${escape(item.frame.mnemonic || ".byte")}</b> ${escape(item.frame.mnemonic ? item.frame.operands : Emtr.opcodeHex(item.frame.opcode))}</span></button>`,
        )
        .join("");
      const footer = block.flow
        ? `${block.flow.kind === "conditional" ? "Conditional branch" : block.flow.kind === "call" ? "Function call" : block.flow.kind === "return" ? "Return" : block.flow.kind === "jump" ? "Jump" : "Execution stops"}${block.flow.delay ? " · includes delay slot" : ""}`
        : "Basic block";
      markup.push(
        `<section class="cfg-block" data-block="${block.id}" style="${position}" aria-label="Basic block at ${Emtr.hex(block.address, block.archId)}"><div class="cfg-block-heading"><strong>${Emtr.hex(block.address, block.archId)}</strong><span>${block.visits.length.toLocaleString()} ${block.visits.length === 1 ? "visit" : "visits"}</span></div>${visible.start ? `<div class="cfg-skipped">${visible.start} earlier instructions</div>` : ""}${instructions}${visible.end < block.instructions.length ? `<div class="cfg-skipped">${block.instructions.length - visible.end} more instructions</div>` : ""}<div class="cfg-block-footer"><span>${footer}</span>${block.instructions.length > 14 ? `<button class="cfg-expand" data-expand="${block.id}">${expanded.has(block.id) ? "Collapse" : "Show all"}</button>` : ""}</div></section>`,
      );
    }
    el("cfg-blocks").innerHTML = markup.join("");
    const svg = el("cfg-edges");
    svg.setAttribute("width", g.graph().width);
    svg.setAttribute("height", g.graph().height);
    svg.innerHTML =
      '<defs><marker id="cfg-arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M 0 0 L 10 5 L 0 10 z"/></marker><marker id="cfg-arrow-taken" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M 0 0 L 10 5 L 0 10 z"/></marker></defs>' +
      graph.edges
        .map((edge) => {
          const geometry = g.edge({ v: edge.from, w: edge.to, name: edge.id });
          const d = geometry.points
            .map((point, i) => `${i ? "L" : "M"} ${point.x} ${point.y}`)
            .join(" ");
          return `<g class="cfg-edge ${edge.count ? "observed" : "inferred"} ${edge.type}" data-edge="${edge.type}" data-count="${edge.count}"><path d="${d}" marker-end="url(#${edge.type === "taken" ? "cfg-arrow-taken" : "cfg-arrow"})"/><text x="${geometry.x}" y="${geometry.y + 3}" text-anchor="middle">${edgeLabel(edge)}</text></g>`;
        })
        .join("");
    el("cfg-message").hidden = true;
    stage.hidden = false;
    for (const button of document.querySelectorAll(".cfg-controls button"))
      button.disabled = false;
    updateGeometry();
    updateSelection();
  }
  function updateGeometry() {
    if (!layout) return;
    const width = layout.graph().width * zoom,
      height = layout.graph().height * zoom;
    const stageWidth = Math.max(viewport.clientWidth, width + 32);
    stage.style.width = `${stageWidth}px`;
    stage.style.height = `${Math.max(viewport.clientHeight, height + 32)}px`;
    scene.style.left = `${(stageWidth - width) / 2}px`;
    scene.style.top = "16px";
    scene.style.width = `${layout.graph().width}px`;
    scene.style.height = `${layout.graph().height}px`;
    scene.style.transform = `scale(${zoom})`;
    el("cfg-zoom").textContent = `${Math.round(zoom * 100)}%`;
  }
  function fit() {
    if (!layout) return;
    zoom = Math.max(
      0.15,
      Math.min(
        1.25,
        (viewport.clientWidth - 40) / layout.graph().width,
        (viewport.clientHeight - 40) / layout.graph().height,
      ),
    );
    updateGeometry();
    viewport.scrollTop = 0;
    viewport.scrollLeft = 0;
  }
  function locate() {
    const node = layout?.node(currentBlock());
    if (!node) return;
    viewport.scrollLeft =
      parseFloat(scene.style.left) + node.x * zoom - viewport.clientWidth / 2;
    viewport.scrollTop = 16 + node.y * zoom - viewport.clientHeight / 2;
  }
  function setZoom(value) {
    if (!layout) return;
    const x =
      (viewport.scrollLeft +
        viewport.clientWidth / 2 -
        parseFloat(scene.style.left)) /
      zoom;
    const y = (viewport.scrollTop + viewport.clientHeight / 2 - 16) / zoom;
    zoom = Math.max(0.15, Math.min(2, value));
    updateGeometry();
    viewport.scrollLeft =
      parseFloat(scene.style.left) + x * zoom - viewport.clientWidth / 2;
    viewport.scrollTop = 16 + y * zoom - viewport.clientHeight / 2;
  }
  function updateSelection() {
    if (!graph?.membership) return;
    const state = getState(),
      key = EmtrCFG.instructionKey(state.trace.frames[state.index]);
    const breakpointKeys = new Set(
      Array.from(state.breakpoints, (i) =>
        EmtrCFG.instructionKey(state.trace.frames[i]),
      ),
    );
    for (const block of el("cfg-blocks").querySelectorAll(".cfg-block"))
      block.classList.toggle("current", block.dataset.block === currentBlock());
    for (const row of el("cfg-blocks").querySelectorAll(".cfg-instruction")) {
      row.classList.toggle("selected", row.dataset.instruction === key);
      row.setAttribute("aria-current", String(row.dataset.instruction === key));
      // Breakpoints are frame occurrences; graph nodes aggregate addresses.
      row.classList.toggle(
        "has-bp",
        breakpointKeys.has(row.dataset.instruction),
      );
    }
  }
  async function selectionChanged() {
    if (!active || !trace?.nFrames) return;
    const token = generation;
    try {
      if (!(await ensureIndex()) || !active || token !== generation) return;
      const state = getState(),
        owner = index.owners[state.index];
      if (!cache.has(owner)) {
        cache.set(owner, EmtrCFG.buildGraph(index, state.index));
        if (cache.size > 8) cache.delete(cache.keys().next().value);
      }
      const nextGraph = cache.get(owner),
        changed = graph !== nextGraph;
      graph = nextGraph;
      el("cfg-function").textContent =
        `${graph.scope.inferred ? "Function" : "Trace region"} · ${Emtr.hex(graph.scope.entry, graph.scope.archId)}`;
      if (graph.error) {
        el("cfg-count").textContent = "";
        message(graph.error);
        return;
      }
      el("cfg-count").textContent =
        `${graph.blocks.filter((block) => !block.external).length} blocks · ${graph.edges.length} edges`;
      const notes = [
        "Trace-based CFG; function boundaries inferred from calls / returns.",
      ];
      if (!graph.scope.inferred)
        notes.push("The function entry may precede this trace region.");
      if (graph.raw)
        notes.push(
          `${graph.raw} undecoded instructions: only observed transitions are available.`,
        );
      if (graph.variants)
        notes.push(
          "Multiple byte versions at the same address are shown separately.",
        );
      el("cfg-note").textContent = notes.join(" ");
      el("cfg-note").title = notes.join(" ");
      const key = EmtrCFG.instructionKey(trace.frames[state.index]);
      const block = graph.blocks.find((block) => block.id === currentBlock());
      const needsRows =
        block?.instructions.length > 14 &&
        !expanded.has(block.id) &&
        key !== renderedSelection;
      if (changed) {
        expanded.clear();
        instructionNodes = new Map(
          graph.blocks.flatMap((block) =>
            block.instructions.map((item) => [item.key, item]),
          ),
        );
        draw();
        fit();
      } else if (needsRows) draw();
      else updateSelection();
      renderedSelection = key;
    } catch (error) {
      if (token === generation)
        message(`Could not build this CFG: ${error.message}`);
    }
  }
  function activate(value) {
    active = value;
    if (value) {
      selectionChanged();
      updateGeometry();
    }
  }
  el("cfg-fit").onclick = fit;
  el("cfg-locate").onclick = locate;
  el("cfg-zoom-in").onclick = () => setZoom(zoom * 1.2);
  el("cfg-zoom-out").onclick = () => setZoom(zoom / 1.2);
  el("cfg-blocks").onclick = (event) => {
    const expand = event.target.closest("[data-expand]");
    if (expand) {
      if (expanded.has(expand.dataset.expand))
        expanded.delete(expand.dataset.expand);
      else expanded.add(expand.dataset.expand);
      draw();
      return;
    }
    const external = event.target.closest("[data-external]");
    if (external) {
      const block = graph.blocks.find(
        (block) => block.id === external.dataset.external,
      );
      const target = EmtrCFG.nearestVisit(block.visits, getState().index);
      if (target !== null) navigate(target);
      return;
    }
    const row = event.target.closest("[data-instruction]");
    if (!row) return;
    const instruction = instructionNodes.get(row.dataset.instruction);
    const target = EmtrCFG.nearestVisit(instruction.visits, getState().index);
    if (target !== null) navigate(target);
  };
  el("cfg-blocks").ondblclick = (event) => {
    if (event.target.closest("[data-instruction]")) openDisassembly();
  };
  el("cfg-blocks").onkeydown = (event) => {
    if (event.ctrlKey || event.metaKey || event.altKey) return;
    if (
      (event.key.toLowerCase() === "b" || event.key === "F2") &&
      event.target.closest("[data-instruction]")
    ) {
      event.preventDefault();
      const row = event.target.closest("[data-instruction]");
      const target = EmtrCFG.nearestVisit(
        instructionNodes.get(row.dataset.instruction).visits,
        getState().index,
      );
      if (target === null) return;
      navigate(target);
      toggleBreakpoint(target);
      updateSelection();
    }
  };
  let dragging = null;
  viewport.addEventListener("pointerdown", (event) => {
    if (event.button !== 0 || event.target.closest(".cfg-block")) return;
    dragging = {
      x: event.clientX,
      y: event.clientY,
      left: viewport.scrollLeft,
      top: viewport.scrollTop,
    };
    viewport.setPointerCapture(event.pointerId);
    viewport.classList.add("dragging");
  });
  viewport.addEventListener("pointermove", (event) => {
    if (dragging) {
      viewport.scrollLeft = dragging.left + dragging.x - event.clientX;
      viewport.scrollTop = dragging.top + dragging.y - event.clientY;
    }
  });
  const endDrag = () => {
    dragging = null;
    viewport.classList.remove("dragging");
  };
  viewport.addEventListener("pointerup", endDrag);
  viewport.addEventListener("pointercancel", endDrag);
  new ResizeObserver(() => {
    if (active) updateGeometry();
  }).observe(viewport);
  return {
    reset,
    activate,
    selectionChanged,
    refreshBreakpoints: updateSelection,
  };
}

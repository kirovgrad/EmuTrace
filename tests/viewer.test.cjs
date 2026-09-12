/* Run with npm run test:ui after npx playwright install chromium.
 * EMUTRACE_BROWSER may point to an existing Chrome/Chromium executable.
 */
const { chromium } = require("playwright");
const assert = require("node:assert/strict");
const path = require("node:path");
const fs = require("node:fs/promises");
const { pathToFileURL } = require("node:url");
const { deflateSync } = require("node:zlib");
const root = path.resolve(__dirname, "..");
function syntheticTrace(count, stackSize = 0) {
  const header = Buffer.alloc(16);
  header.write("EMTR");
  header.writeUInt32LE(2, 4);
  header.writeUInt32LE(4, 8);
  header.writeUInt32LE(count, 12);
  const frame = Buffer.alloc(36 + stackSize);
  frame.writeBigUInt64LE(0xfffffffffffffff0n);
  frame.writeUInt16LE(1, 8);
  frame[10] = 0x90;
  // No registers; empty stack; v2 frame extension starts at byte 25.
  frame.writeUInt32LE(stackSize, 21);
  frame.writeUInt32LE(4, 25 + stackSize);
  frame.writeUInt16LE(3, 29 + stackSize);
  frame.write("nop", 33 + stackSize);
  return Buffer.concat([
    header,
    deflateSync(Buffer.concat([Buffer.alloc(4), ...Array(count).fill(frame)])),
  ]);
}
(async () => {
  const browser = await chromium.launch({
    headless: true,
    ...(process.env.EMUTRACE_BROWSER
      ? { executablePath: process.env.EMUTRACE_BROWSER }
      : {}),
  });
  let checks = 0;
  try {
    const page = await browser.newPage({
      viewport: { width: 1440, height: 1000 },
    });
    const errors = [];
    page.on("pageerror", (error) => errors.push(error.message));
    const remoteRequests = [];
    page.on("request", (request) => {
      if (/^https?:/.test(request.url())) remoteRequests.push(request.url());
    });
    await page.goto(pathToFileURL(path.join(root, "emu_viewer.html")).href);
    await page.keyboard.press("Space");
    assert.equal(await page.evaluate(() => state.timer), null);
    await page.getByRole("button", { name: "Explore an example" }).click();
    await page.waitForFunction(() => state.trace?.nFrames === 37);
    assert.match(await page.locator("#status-msg").textContent(), /Loaded/);
    await page.getByRole("tab", { name: "Decompilation", exact: true }).click();
    assert.match(
      await page.locator("#decomp-message-title").textContent(),
      /No embedded decompilation/,
    );
    assert.match(
      await page.locator("#decomp-note").textContent(),
      /emu_decompiler\.py/,
    );
    await page.getByRole("tab", { name: "Disassembly", exact: true }).click();
    checks++;
    const go = async (number) => {
      await page.locator("#frame-input").fill(String(number));
      await page.locator("#frame-input").press("Enter");
    };
    await go(4);
    const rax = () =>
      page
        .locator("#reg-body tr")
        .filter({ has: page.locator("td:first-child", { hasText: /^RAX$/ }) });
    assert.match(await rax().getAttribute("class"), /changed/);
    assert.match(await rax().textContent(), /0000000000000008/);
    const comparison = await rax().textContent();
    await go(37);
    await go(4);
    assert.equal(await rax().textContent(), comparison);
    checks++;
    await page.locator("#changed-only").check();
    await go(1);
    assert.match(
      await page.locator("#reg-body").textContent(),
      /No register changes/,
    );
    await page.locator("#changed-only").uncheck();
    await page.locator("#watch-register").selectOption("RAX");
    await page
      .getByRole("button", { name: "Next register change", exact: true })
      .click();
    assert.equal(await page.locator("#frame-input").inputValue(), "4");
    checks++;
    await page.locator("#search-input").fill("push");
    await page.waitForFunction(() => state.matches.length === 8);
    const match = await page.locator("#frame-input").inputValue();
    await page.locator("#search-input").press("Enter");
    assert.notEqual(await page.locator("#frame-input").inputValue(), match);
    await page.locator("#search-input").press("Shift+Enter");
    assert.equal(await page.locator("#frame-input").inputValue(), match);
    await page.locator("#search-input").fill("");
    await page.waitForFunction(() => state.query === "");
    checks++;
    await go(5);
    await page.locator("#frame-input").blur();
    await page.keyboard.press("b");
    await page.getByRole("button", { name: /Breakpoints/ }).click();
    assert.equal(await page.locator("#disasm-body tr[data-index]").count(), 1);
    await page.getByRole("button", { name: "All frames", exact: true }).click();
    await go(1);
    await page.locator("#play-speed").selectOption("33");
    await page.getByRole("button", { name: "Play", exact: true }).click();
    await page.waitForFunction(() => state.index === 4 && state.timer === null);
    checks++;
    const firstStackValue = page.locator(
      '#stack-body tr[data-stack-row="0"] .stack-value',
    );
    assert.equal(await firstStackValue.textContent(), "0000000000000008");
    assert.match(
      await page.locator("#stack-value-heading").textContent(),
      /64-bit/,
    );
    // Numeric display reverses byte positions, not addresses or highlight ownership.
    assert.equal(
      await firstStackValue
        .locator("[data-stack-offset]")
        .first()
        .getAttribute("data-stack-offset"),
      "7",
    );
    assert.equal(
      await firstStackValue.locator('[data-stack-offset="0"]').textContent(),
      "08",
    );
    await page.getByLabel("Stack display format").selectOption("bytes");
    assert.equal(
      await firstStackValue.textContent(),
      "08 00 00 00 00 00 00 00",
    );
    await page.getByLabel("Stack display format").selectOption("values");
    for (const selector of [
      "#disasm-body tr[data-index]",
      "#reg-body tr",
      "#stack-body tr[data-stack-row]",
    ]) {
      const metrics = await page
        .locator(selector)
        .first()
        .evaluate((row) => ({
          height: row.getBoundingClientRect().height,
          borders: Array.from(
            row.cells,
            (cell) => getComputedStyle(cell).borderBottomWidth,
          ),
        }));
      assert.equal(metrics.height, 18, selector);
      assert.ok(
        metrics.borders.every((width) => width === "0px"),
        selector,
      );
    }
    checks++;
    const red = await page.evaluate(() =>
      getComputedStyle(document.documentElement)
        .getPropertyValue("--change-text")
        .trim(),
    );
    const redRGB = await page.evaluate((color) => {
      const el = document.createElement("span");
      el.style.color = color;
      document.body.append(el);
      const result = getComputedStyle(el).color;
      el.remove();
      return result;
    }, red);
    await go(4);
    assert.equal(
      await rax()
        .locator(".register-value")
        .evaluate((el) => getComputedStyle(el).color),
      redRGB,
    );
    assert.equal(
      await rax()
        .locator(".register-value")
        .evaluate((el) => getComputedStyle(el).backgroundColor),
      "rgba(70, 70, 70, 0.09)",
    );
    await go(5);
    assert.notEqual(
      await rax()
        .locator(".register-value")
        .evaluate((el) => getComputedStyle(el).color),
      redRGB,
    );
    assert.equal(
      await firstStackValue
        .locator(".byte")
        .first()
        .evaluate((el) => getComputedStyle(el).color),
      redRGB,
    );
    assert.equal(
      await firstStackValue
        .locator(".stack-value-content")
        .evaluate((el) => getComputedStyle(el).backgroundColor),
      "rgba(70, 70, 70, 0.09)",
    );
    await go(7); // A branch does not write stack memory; the previous stack highlight remains.
    assert.equal(
      await firstStackValue
        .locator(".byte")
        .first()
        .evaluate((el) => getComputedStyle(el).color),
      redRGB,
    );
    await go(9); // The next push replaces the highlight with the new top-of-stack word.
    assert.equal(await firstStackValue.textContent(), "000000000000000f");
    assert.equal(
      await firstStackValue
        .locator(".byte")
        .first()
        .evaluate((el) => getComputedStyle(el).color),
      redRGB,
    );
    assert.equal(
      (await page
        .locator('#stack-body tr[data-stack-row="8"] .stack-value .byte')
        .first()
        .evaluate((el) => getComputedStyle(el).color)) === redRGB,
      false,
    );
    await go(7); // Backtracking restores the earlier memory-change event.
    assert.equal(await firstStackValue.textContent(), "0000000000000008");
    assert.equal(
      await firstStackValue
        .locator(".byte")
        .first()
        .evaluate((el) => getComputedStyle(el).color),
      redRGB,
    );
    await go(5);
    checks++;
    const downloadPromise = page.waitForEvent("download");
    await page.getByRole("button", { name: "Export frame" }).click();
    const download = await downloadPromise;
    const exported = JSON.parse(
      await fs.readFile(await download.path(), "utf8"),
    );
    assert.equal(exported.frame, 5);
    assert.equal(typeof exported.registers.RAX, "string");
    checks++;
    // Both existing binary traces use the bundled legacy Capstone runtime.
    for (const filename of ["trace_arm32.emtr", "trace_mipsel.emtr"]) {
      await page
        .locator("#file-input")
        .setInputFiles(path.join(root, "examples", filename));
      await page.waitForFunction(
        (name) => document.getElementById("trace-name").textContent === name,
        filename,
      );
      assert.equal(await page.locator("#breakpoint-count").textContent(), "0");
      assert.equal(
        await page.evaluate(
          () => state.trace.frames.filter((f) => !f.mnemonic).length,
        ),
        0,
      );
    }
    checks++;
    const bad = {
      name: "broken.emtr",
      mimeType: "application/octet-stream",
      buffer: Buffer.from("bad"),
    };
    await page.locator("#file-input").setInputFiles(bad);
    await page.waitForFunction(() =>
      document.getElementById("status-msg").classList.contains("error"),
    );
    assert.equal(
      await page.locator("#trace-name").textContent(),
      "trace_mipsel.emtr",
    );
    checks++;
    await page.locator("#file-input").setInputFiles({
      name: "large.emtr",
      mimeType: "application/octet-stream",
      buffer: syntheticTrace(30000),
    });
    await page.waitForFunction(() => state.trace?.nFrames === 30000);
    assert.ok(
      (await page.locator("#disasm-body tr[data-index]").count()) < 100,
    );
    await page.getByRole("button", { name: "Last frame", exact: true }).click();
    assert.equal(await page.locator("#frame-input").inputValue(), "30000");
    assert.ok(
      (await page.locator("#disasm-body tr[data-index]").count()) < 100,
    );
    assert.equal(
      await page.locator("tr.selected").getAttribute("data-index"),
      "29999",
    );
    assert.match(
      await page.locator("#status-detail").textContent(),
      /fffffffffffffff0/,
    );
    checks++;
    await page.locator("#file-input").setInputFiles({
      name: "large-stack.emtr",
      mimeType: "application/octet-stream",
      buffer: syntheticTrace(1, 65536),
    });
    await page.waitForFunction(() => state.trace?.nFrames === 1);
    assert.ok((await page.locator("#stack-body tr").count()) < 100);
    await page.locator("#stack-scroll").evaluate((element) => {
      element.scrollTop = element.scrollHeight;
    });
    await page.waitForFunction(() =>
      document
        .getElementById("stack-body")
        .textContent.includes("0x000000000000fff8"),
    );
    assert.ok((await page.locator("#stack-body tr").count()) < 100);
    checks++;
    // Exercise stale-load protection by starting two loads together.
    await page.evaluate(async () => {
      const buffer = Uint8Array.from(atob(DEMO_TRACE_BASE64), (c) =>
        c.charCodeAt(0),
      ).buffer;
      await Promise.all([
        loadBuffer(buffer, "first.emtr"),
        loadBuffer(buffer, "second.emtr"),
      ]);
    });
    assert.equal(
      await page.locator("#trace-name").textContent(),
      "second.emtr",
    );
    checks++;
    await page.locator("#file-input").setInputFiles({
      name: "empty.emtr",
      mimeType: "application/octet-stream",
      buffer: syntheticTrace(0),
    });
    await page.waitForFunction(() => state.trace?.nFrames === 0);
    assert.equal(await page.locator("#pb-play").isDisabled(), true);
    assert.match(
      await page.locator("#reg-body").textContent(),
      /No register state/,
    );
    checks++;
    // Restore the real demo for screenshots and verify responsive layouts.
    await page.evaluate(() =>
      loadBuffer(
        Uint8Array.from(atob(DEMO_TRACE_BASE64), (c) => c.charCodeAt(0)).buffer,
        "example_x86_64.emtr",
      ),
    );
    await go(5);
    await fs.mkdir(path.join(root, "test-results"), { recursive: true });
    await page.screenshot({
      path: path.join(root, "test-results/viewer-light.png"),
    });
    await page.getByRole("button", { name: "Switch appearance" }).click();
    await page.screenshot({
      path: path.join(root, "test-results/viewer-dark.png"),
    });
    await page
      .getByRole("button", { name: "Keyboard shortcuts", exact: true })
      .click();
    assert.equal(
      await page.locator("#help-dialog").evaluate((d) => d.open),
      true,
    );
    await page.getByRole("button", { name: "Close shortcuts" }).click();
    await page.setViewportSize({ width: 390, height: 844 });
    assert.equal(
      await page.evaluate(
        () => document.documentElement.scrollWidth <= innerWidth,
      ),
      true,
    );
    await page.screenshot({
      path: path.join(root, "test-results/viewer-mobile.png"),
      fullPage: true,
    });
    checks++;
    assert.deepEqual(errors, []);
    assert.deepEqual(remoteRequests, []);
    console.log(
      `${checks} browser checks passed; no page errors or network requests. Screenshots: test-results/.`,
    );
  } finally {
    await browser.close();
  }
})().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});

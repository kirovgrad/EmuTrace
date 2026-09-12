/* CFG integration checks, including direct file:// use and shared state panels. */
const { chromium } = require("playwright");
const assert = require("node:assert/strict");
const path = require("node:path");
const fs = require("node:fs/promises");
const { pathToFileURL } = require("node:url");
const { frame, calls, encode } = require("./cfg-fixtures.cjs");
const root = path.resolve(__dirname, "..");
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
    const errors = [],
      remote = [];
    page.on("pageerror", (error) => errors.push(error.message));
    page.on("request", (request) => {
      if (/^https?:/.test(request.url())) remote.push(request.url());
    });
    await fs.mkdir(path.join(root, "test-results"), { recursive: true });
    await page.goto(pathToFileURL(path.join(root, "emu_viewer.html")).href);
    await page.getByRole("button", { name: "Explore an example" }).click();
    await page.waitForFunction(() => state.trace?.nFrames === 37);
    await page.getByRole("tab", { name: "CFG", exact: true }).click();
    await page.locator(".cfg-instruction").first().waitFor();
    assert.equal(
      await page
        .getByRole("tab", { name: "CFG", exact: true })
        .getAttribute("aria-selected"),
      "true",
    );
    assert.equal(await page.locator("#disassembly-view").isVisible(), false);
    assert.equal(await page.locator(".cfg-block:not(.external)").count(), 3);
    assert.equal(await page.locator(".cfg-block-footer").count(), 0);
    assert.equal(
      await page
        .locator(".cfg-block-heading")
        .first()
        .evaluate((el) => el.offsetHeight),
      23,
    );
    assert.deepEqual(
      await page
        .locator(
          ".execution-panel > .panel-heading, .register-panel > .panel-heading, .stack-panel > .panel-heading",
        )
        .evaluateAll((nodes) => nodes.map((node) => node.offsetHeight)),
      [35, 35, 35],
    );
    assert.equal(
      await page.evaluate(
        () => getComputedStyle(document.body).backgroundColor,
      ),
      "rgb(254, 248, 240)",
    );
    assert.equal(
      await page
        .locator(".panel")
        .first()
        .evaluate((el) => getComputedStyle(el).backgroundColor),
      "rgb(246, 239, 231)",
    );
    assert.equal(
      await page
        .locator(".cfg-instruction b")
        .first()
        .evaluate((el) => getComputedStyle(el).color),
      "rgb(23, 99, 170)",
    );
    assert.equal(
      await page
        .locator("#reg-table td:first-child")
        .first()
        .evaluate((el) => getComputedStyle(el).color),
      "rgb(23, 99, 170)",
    );
    assert.equal(
      await page.locator(".cfg-edge.taken").getAttribute("data-count"),
      "7",
    );
    assert.equal(
      await page.locator(".cfg-edge.not-taken").getAttribute("data-count"),
      "1",
    );
    assert.match(
      await page.locator("#cfg-note").textContent(),
      /entry may precede/,
    );
    checks++;
    await page.locator('.cfg-instruction[data-frame="3"]').click();
    assert.equal(await page.locator("#frame-input").inputValue(), "4");
    assert.equal(
      await page
        .locator(".cfg-instruction.selected")
        .getAttribute("data-frame"),
      "3",
    );
    const rax = page
      .locator("#reg-body tr")
      .filter({ has: page.locator("td:first-child", { hasText: /^RAX$/ }) });
    assert.match(await rax.textContent(), /0000000000000008/);
    await page.getByRole("tab", { name: "Disassembly", exact: true }).click();
    assert.equal(await page.locator("#frame-input").inputValue(), "4");
    await page
      .getByRole("tab", { name: "Disassembly", exact: true })
      .press("ArrowRight");
    assert.equal(
      await page
        .getByRole("tab", { name: "CFG", exact: true })
        .getAttribute("aria-selected"),
      "true",
    );
    assert.equal(await page.locator("#frame-input").inputValue(), "4");
    checks++;
    // Keyboard breakpoints act on the focused instruction's nearest occurrence.
    await page.locator('.cfg-instruction[data-frame="4"]').focus();
    await page.keyboard.press("b");
    assert.equal(await page.locator("#frame-input").inputValue(), "5");
    assert.match(
      await page
        .locator('.cfg-instruction[data-frame="4"]')
        .getAttribute("class"),
      /has-bp/,
    );
    assert.deepEqual(await page.evaluate(() => [...state.breakpoints]), [4]);
    await page.locator('.cfg-instruction[data-frame="4"]').dblclick();
    assert.equal(await page.locator("#disassembly-view").isVisible(), true);
    assert.equal(await page.locator("#frame-input").inputValue(), "5");
    await page.getByRole("tab", { name: "CFG", exact: true }).click();
    checks++;
    const zoom = await page.locator("#cfg-zoom").textContent();
    await page.locator("#cfg-zoom-in").click();
    assert.notEqual(await page.locator("#cfg-zoom").textContent(), zoom);
    await page.locator("#cfg-fit").click();
    assert.equal(await page.locator("#cfg-zoom").textContent(), zoom);
    for (let i = 0; i < 4; i++) await page.locator("#cfg-zoom-in").click();
    await page.locator("#cfg-viewport").evaluate((el) => {
      el.scrollTop = 0;
    });
    const background = await page.locator("#cfg-viewport").evaluate((el) => {
      const rect = el.getBoundingClientRect();
      for (let y = rect.y + 120; y < rect.bottom - 20; y += 30)
        for (let x = rect.x + 5; x < rect.right - 20; x += 30)
          if (!document.elementFromPoint(x, y)?.closest(".cfg-block"))
            return { x, y };
    });
    assert.ok(background, "zoomed graph has draggable background");
    await page.mouse.move(background.x, background.y);
    await page.mouse.down();
    await page.mouse.move(background.x, background.y - 100, { steps: 5 });
    await page.mouse.up();
    assert.ok(
      await page.locator("#cfg-viewport").evaluate((el) => el.scrollTop > 50),
    );
    await page.locator("#cfg-fit").click();
    await page.locator("#pb-last").click();
    await page.waitForFunction(
      () =>
        document.querySelector(".cfg-instruction.selected")?.dataset.frame ===
        "36",
    );
    await page.locator("#cfg-locate").click();
    const geometry = await page.locator(".cfg-block").evaluateAll((nodes) =>
      nodes.map((node) => ({
        x: node.offsetLeft,
        y: node.offsetTop,
        w: node.offsetWidth,
        h: node.offsetHeight,
        contentHeight: [...node.children].reduce(
          (h, child) => h + child.offsetHeight,
          2,
        ),
      })),
    );
    for (let i = 0; i < geometry.length; i++) {
      const a = geometry[i];
      assert.ok(a.contentHeight <= a.h, "block content fits");
      for (const b of geometry.slice(i + 1))
        assert.ok(
          a.x + a.w <= b.x ||
            b.x + b.w <= a.x ||
            a.y + a.h <= b.y ||
            b.y + b.h <= a.y,
          "blocks do not overlap",
        );
    }
    await page.screenshot({
      path: path.join(root, "test-results/cfg-light.png"),
      fullPage: true,
    });
    checks++;
    const load = async (frames, name = "cfg-fixture.emtr") => {
      await page.locator("#file-input").setInputFiles({
        name,
        mimeType: "application/octet-stream",
        buffer: encode(frames),
      });
      await page.waitForFunction(
        (name) => document.getElementById("trace-name").textContent === name,
        name,
      );
    };
    await load(calls(), "calls.emtr");
    await page.waitForFunction(() =>
      document
        .querySelector(".cfg-external-link")
        ?.textContent.includes("Called function"),
    );
    await page.getByRole("button", { name: /Called function/ }).click();
    await page.waitForFunction(
      () =>
        document.getElementById("cfg-function").textContent ===
        "Function · 0x0000000000000200",
    );
    assert.equal(await page.locator("#frame-input").inputValue(), "2");
    assert.equal(await page.locator(".cfg-edge.inferred.not-taken").count(), 1);
    assert.equal(
      await page
        .getByRole("button", { name: /Code not captured/ })
        .isDisabled(),
      true,
    );
    await page.getByRole("button", { name: /Called function/ }).click();
    await page.waitForFunction(() =>
      document.getElementById("cfg-function").textContent.endsWith("0300"),
    );
    assert.equal(await page.locator("#frame-input").inputValue(), "5");
    await page.getByRole("button", { name: /Return to caller/ }).click();
    await page.waitForFunction(() =>
      document.getElementById("cfg-function").textContent.endsWith("0200"),
    );
    assert.equal(await page.locator("#frame-input").inputValue(), "7");
    await page.screenshot({
      path: path.join(root, "test-results/cfg-calls.png"),
      fullPage: true,
    });
    checks++;
    await page.locator("#theme-toggle").click();
    assert.equal(
      await page.evaluate(
        () => getComputedStyle(document.body).backgroundColor,
      ),
      "rgb(36, 37, 47)",
    );
    assert.equal(
      await page
        .locator(".panel")
        .first()
        .evaluate((el) => getComputedStyle(el).backgroundColor),
      "rgb(29, 30, 39)",
    );
    assert.equal(
      await page
        .locator(".cfg-instruction b")
        .first()
        .evaluate((el) => getComputedStyle(el).color),
      "rgb(195, 155, 255)",
    );
    assert.equal(
      await page
        .locator("#reg-table td:first-child")
        .first()
        .evaluate((el) => getComputedStyle(el).color),
      "rgb(195, 155, 255)",
    );
    assert.equal(
      await page
        .locator("#reg-table tr.changed .register-value")
        .evaluate((el) => getComputedStyle(el).backgroundColor),
      "rgba(210, 210, 220, 0.12)",
    );
    await page.screenshot({
      path: path.join(root, "test-results/cfg-dark.png"),
      fullPage: true,
    });
    await page.setViewportSize({ width: 390, height: 844 });
    await page.locator("#cfg-fit").click();
    assert.ok(
      await page.evaluate(
        () => document.documentElement.scrollWidth <= innerWidth,
      ),
    );
    assert.ok((await page.locator("#cfg-viewport").boundingBox()).height > 150);
    await page.screenshot({
      path: path.join(root, "test-results/cfg-mobile.png"),
      fullPage: true,
    });
    await page.setViewportSize({ width: 1440, height: 1000 });
    checks++;
    // Long blocks reveal a window around the current instruction and can expand.
    await load(
      Array.from({ length: 40 }, (_, i) => frame(0x100 + i)),
      "long-block.emtr",
    );
    await page.getByRole("button", { name: "Show all", exact: true }).waitFor();
    assert.ok(
      await page
        .getByRole("button", { name: "Show all", exact: true })
        .evaluate((button) => Boolean(button.closest(".cfg-block-heading"))),
    );
    assert.equal(await page.locator(".cfg-instruction").count(), 12);
    await page.locator("#pb-last").click();
    await page.waitForFunction(
      () =>
        document.querySelector(".cfg-instruction.selected")?.dataset.frame ===
        "39",
    );
    await page.getByRole("button", { name: "Show all", exact: true }).click();
    assert.equal(await page.locator(".cfg-instruction").count(), 40);
    await page.getByRole("button", { name: "Collapse", exact: true }).click();
    assert.equal(await page.locator(".cfg-instruction").count(), 12);
    checks++;
    await load(
      Array.from({ length: 5001 }, (_, i) => frame(0x100 + i)),
      "large-function.emtr",
    );
    await page.waitForFunction(() =>
      document
        .getElementById("cfg-message")
        .textContent.includes("5,000-instruction"),
    );
    assert.equal(await page.locator("#cfg-stage").isVisible(), false);
    await page.getByRole("tab", { name: "Disassembly", exact: true }).click();
    assert.ok((await page.locator("#disasm-body tr[data-index]").count()) > 0);
    await page.getByRole("tab", { name: "CFG", exact: true }).click();
    await load([], "empty-cfg.emtr");
    assert.equal(await page.locator(".cfg-block").count(), 0);
    assert.match(
      await page.locator("#cfg-message").textContent(),
      /No instruction frames/,
    );
    checks++;
    await load(calls(), "reloaded.emtr");
    await page.locator(".cfg-instruction").first().waitFor();
    await page.locator("#file-input").setInputFiles({
      name: "invalid.emtr",
      mimeType: "application/octet-stream",
      buffer: Buffer.from("bad"),
    });
    await page.waitForFunction(() =>
      document
        .getElementById("status-msg")
        .textContent.startsWith("Could not open trace"),
    );
    assert.equal(
      await page.locator("#trace-name").textContent(),
      "reloaded.emtr",
    );
    assert.ok((await page.locator(".cfg-instruction").count()) > 0);
    assert.deepEqual(errors, []);
    assert.deepEqual(remote, []);
    checks++;
    console.log(`CFG browser checks: ${checks} passed`);
  } finally {
    await browser.close();
  }
})().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});

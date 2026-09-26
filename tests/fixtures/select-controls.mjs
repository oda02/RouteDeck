import assert from "node:assert/strict";

export async function chooseSelect(page, control, value) {
  if (await control.getAttribute("aria-expanded") !== "true") await control.click();
  await page.locator(`.select-popover [role="option"][data-value="${value}"]`).click();
}

export async function verifySelectControls(browser, base, fixtureModule) {
  const page = await browser.newPage({ viewport: { width: 440, height: 760 } });
  const errors = [];
  page.on("pageerror", (error) => errors.push(error.message));
  await page.route("**/*", (route) => {
    const url = new URL(route.request().url());
    if (url.origin !== new URL(base).origin) return route.abort();
    if (url.pathname === "/src/controller.ts") return route.fulfill({ contentType: "application/javascript", body: fixtureModule });
    return route.continue();
  });
  const nav = (name) => page.locator("nav:visible .navigation-item").filter({ hasText: name }).click();
  const popup = page.getByRole("listbox");
  const settledPopup = async () => {
    await popup.waitFor();
    await popup.evaluate((element) => Promise.all(element.getAnimations().map((animation) => animation.finished)));
  };
  const route = page.getByRole("combobox", { name: "Остальной трафик", exact: true });
  const bounds = async () => {
    const box = await popup.boundingBox();
    const viewport = page.viewportSize();
    assert.ok(box && box.x >= 0 && box.y >= 0 && box.x + box.width <= viewport.width && box.y + box.height <= viewport.height, "popup clipped by window bounds");
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth), false);
  };
  try {
    await page.goto(base);
    await page.waitForFunction(() => window.__routeDeckFixture?.snapshot().backendAvailable);
    await nav("Правила");
    await route.click();
    await settledPopup();
    assert.equal(await route.evaluate((element) => getComputedStyle(element).outlineStyle), "none", "pointer click retained focus ring");
    assert.equal(await route.getAttribute("aria-controls"), await popup.getAttribute("id"));
    await page.screenshot({ path: ".cache/ux-qa/select-dark-440.png" });
    await route.press("Escape");
    await route.press("Tab"); await page.keyboard.press("Shift+Tab");
    assert.equal(await route.evaluate((element) => getComputedStyle(element).outlineStyle), "solid", "keyboard ring missing");
    assert.equal(await route.evaluate((element) => getComputedStyle(element).outlineColor), "rgb(116, 224, 154)");

    const original = await route.getAttribute("data-value");
    await route.press("ArrowDown"); await route.press("Home");
    assert.equal(await route.getAttribute("data-value"), original, "provisional keyboard highlight changed routing");
    await route.press("End");
    assert.equal(await page.locator('.select-option[data-active="true"]').getAttribute("data-value"), "direct");
    await route.press("ArrowUp");
    assert.equal(await page.locator('.select-option[data-active="true"]').getAttribute("data-value"), "vpn");
    await route.press("Escape");
    assert.equal(await route.getAttribute("data-value"), original);
    await route.press(" "); await route.press("Home"); await route.press("Enter");
    assert.equal(await route.getAttribute("data-value"), "vpn");
    // Playwright's key names do not expose a Cyrillic hardware layout.
    await route.dispatchEvent("keydown", { key: "н" });
    assert.equal(await page.locator('.select-option[data-active="true"]').getAttribute("data-value"), "direct", "typeahead missed matching label");
    await route.press("Tab"); await popup.waitFor({ state: "hidden" });
    assert.equal(await route.evaluate((element) => element === document.activeElement), false, "Tab trapped focus");
    await route.click();
    await page.locator("main").evaluate((element) => { element.scrollTop += 20; });
    await popup.waitFor({ state: "hidden" });
    await route.click(); await nav("Настройки");
    await popup.waitFor({ state: "hidden" });

    for (const theme of ["dark", "light"]) {
      await nav("Настройки");
      await chooseSelect(page, page.getByRole("combobox", { name: "Тема", exact: true }), theme);
      await page.waitForFunction((theme) => document.documentElement.dataset.theme === theme, theme);
      for (const width of [360, 1000]) {
        await page.setViewportSize({ width, height: 760 });
        await nav("Правила");
        await route.click(); await settledPopup(); await bounds();
        await page.screenshot({ path: `.cache/ux-qa/select-${theme}-${width}.png` });
        const colors = await popup.evaluate((element) => ({ text: getComputedStyle(element).color, background: getComputedStyle(element).backgroundColor }));
        assert.notEqual(colors.text, colors.background, `${theme} popup text disappeared`);
        await route.press("Escape");
        await page.locator(".traffic-rules > summary").click();
        await page.getByRole("button", { name: "Добавить правило", exact: true }).click();
        const network = page.getByRole("combobox", { name: "Сеть", exact: true });
        await network.press("ArrowDown");
        await settledPopup(); await bounds();
        await page.screenshot({ path: `.cache/ux-qa/select-dialog-${theme}-${width}.png` });
        await network.press("Escape");
        assert.equal(await page.getByRole("dialog").count(), 1, "Escape dismissed dialog instead of its select");
        await network.press("ArrowDown"); await network.press("End"); await network.press("Enter");
        assert.equal(await network.getAttribute("data-value"), "tcp");
        assert.equal(await network.evaluate((element) => element === document.activeElement), true, "dialog lost combobox focus");
        const close = page.getByRole("button", { name: "Закрыть окно", exact: true });
        const box = await close.boundingBox();
        const hoverColors = [];
        for (const offset of [6, 21, 37]) {
          await page.mouse.move(box.x + offset, box.y + box.height / 2);
          await page.waitForTimeout(150);
          hoverColors.push(await close.evaluate((element) => ({ color: getComputedStyle(element).backgroundColor, width: element.getBoundingClientRect().width })));
        }
        assert.deepEqual(hoverColors[1], hoverColors[0], "close hover changed over icon");
        assert.deepEqual(hoverColors[2], hoverColors[0], "close hover changed over edge");
        await page.screenshot({ path: `.cache/ux-qa/close-hover-${theme}-${width}.png` });
        await close.click();
        await page.locator(".traffic-rules > summary").click();
      }
    }
    await page.emulateMedia({ reducedMotion: "reduce" });
    await route.click();
    assert.equal(await popup.evaluate((element) => getComputedStyle(element).animationName), "none");
    await route.press("Escape");
    assert.equal(await page.evaluate(() => window.__routeDeckFixture.calls.some((entry) => /^(start|stop)_/.test(entry.command))), false, "UI-only inspection changed fixture connection");
    assert.deepEqual(errors, []);
    return 12;
  } catch (error) {
    await page.screenshot({ path: ".cache/ux-qa/select-controls-failure.png" });
    throw error;
  } finally { await page.close(); }
}

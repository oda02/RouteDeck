import assert from "node:assert/strict";
import { chooseSelect } from "./select-controls.mjs";

// The actual rendered app and controller, with only IPC replaced by fixture data.
export async function verifyApplicationPicker(browser, base, fixtureModule) {
  const page = await browser.newPage({ viewport: { width: 1000, height: 600 } });
  const errors = [];
  page.on("pageerror", (error) => errors.push(error.message));
  await page.route("**/*", (route) => {
    const url = new URL(route.request().url());
    if (url.origin !== new URL(base).origin) return route.abort();
    if (url.pathname === "/src/controller.ts") return route.fulfill({ contentType: "application/javascript", body: fixtureModule + "\nfixture.applicationCount = 80;" });
    return route.continue();
  });
  let scenarios = 0;
  const open = async () => {
    await page.getByRole("button", { name: "Добавить", exact: true }).click();
    await page.locator(".application-picker-row").nth(79).waitFor();
  };
  const search = () => page.getByLabel("Поиск приложений", { exact: true });
  const app = (index) => page.locator(".application-picker-row").filter({ hasText: `Приложение ${String(index).padStart(2, "0")}` });
  const geometry = () => page.evaluate(() => {
    const rect = (selector) => {
      const element = document.querySelector(selector), r = element.getBoundingClientRect();
      return { top: r.top, bottom: r.bottom, left: r.left, right: r.right, height: r.height, scrollTop: element.scrollTop, clientHeight: element.clientHeight, scrollHeight: element.scrollHeight };
    };
    const field = document.querySelector(".application-search"), style = getComputedStyle(field);
    return { dialog: rect(".application-picker-dialog"), content: rect(".application-picker-dialog .dialog-content"), list: rect(".application-picker-list"), footer: rect(".application-picker-dialog .dialog-actions"), search: rect(".application-search"), refresh: rect(".picker-refresh"), outlineWidth: parseFloat(style.outlineWidth), outlineOffset: parseFloat(style.outlineOffset), horizontal: document.documentElement.scrollWidth > innerWidth, height: innerHeight };
  });
  try {
    await page.goto(base);
    await page.waitForFunction(() => window.__routeDeckFixture?.snapshot().backendAvailable);
    await page.locator("nav:visible .navigation-item").filter({ hasText: "Правила" }).click();
    await page.evaluate(() => {
      window.pickerWrites = 0;
      const original = Storage.prototype.setItem;
      Storage.prototype.setItem = function (key, value) {
        if (key === "routedeck.routing.v1") window.pickerWrites++;
        return original.call(this, key, value);
      };
    });
    await open();
    for (const [width, height, label] of [[1000,600,"1000x600"], [800,500,"800x500"], [360,640,"360x640"], [667,400,"150-percent"], [640,400,"125-percent"]]) {
      await page.setViewportSize({ width, height });
      await search().focus();
      const frame = await geometry();
      assert.ok(frame.dialog.top >= 0 && frame.dialog.bottom <= height, `${label}: dialog outside viewport`);
      assert.ok(frame.footer.bottom <= frame.dialog.bottom && frame.footer.top > frame.list.top, `${label}: footer clipped`);
      assert.ok(frame.list.clientHeight >= 70 && frame.list.scrollHeight > frame.list.clientHeight, `${label}: list has no bounded scrolling viewport`);
      assert.equal(frame.horizontal, false, `${label}: horizontal document overflow`);
      assert.ok(frame.outlineWidth >= 2 && frame.outlineOffset <= -frame.outlineWidth, `${label}: search focus ring must fit inside field`);
      assert.ok(frame.search.top >= frame.content.top && frame.search.bottom <= frame.content.bottom, `${label}: search ring clipped by content`);
      await page.locator(".application-picker-list").evaluate((element) => { element.scrollTop = 0; });
      await page.mouse.move((frame.list.left + frame.list.right) / 2, (frame.list.top + frame.list.bottom) / 2);
      await page.mouse.wheel(0, 800);
      await page.waitForFunction(() => document.querySelector(".application-picker-list").scrollTop > 200);
      assert.equal((await geometry()).content.scrollTop, 0, `${label}: search/footer moved instead of list`);
      await app(75).scrollIntoViewIfNeeded();
      await app(75).click();
      assert.equal(await app(75).getAttribute("aria-pressed"), "true");
      await app(75).click();
      await search().focus();
      await page.screenshot({ path: `.cache/ux-qa/picker-dark-${label}.png` });
      scenarios++;
    }
    await page.setViewportSize({ width: 800, height: 500 });
    for (const zoom of [1.25, 1.5]) {
      await page.evaluate((zoom) => { document.documentElement.style.zoom = String(zoom); }, zoom);
      await search().focus();
      const frame = await geometry();
      assert.ok(frame.dialog.top >= 0 && frame.dialog.bottom <= 500, `${zoom}: scaled dialog outside window`);
      assert.ok(frame.footer.bottom <= frame.dialog.bottom && frame.list.clientHeight > 60, `${zoom}: scaled footer/list clipped`);
      await page.screenshot({ path: `.cache/ux-qa/picker-dark-zoom-${zoom}.png` });
      scenarios++;
    }
    await page.evaluate(() => { document.documentElement.style.zoom = "1"; });
    await search().fill("Приложение 01"); await app(1).click();
    await search().fill("Приложение 02"); await app(2).click();
    await search().fill("");
    await page.locator(".application-picker-row").nth(79).waitFor();
    assert.equal(await page.locator('.application-picker-row[aria-pressed="true"]').count(), 2);
    await search().focus();
    await page.screenshot({ path: ".cache/ux-qa/picker-selected-dark-800x500.png" });
    await page.getByRole("button", { name: "Закрыть окно", exact: true }).click();
    assert.equal(await page.locator(".compact-rule").count(), 2, "X lost shared picks across search");
    await page.locator("main").evaluate((element) => { element.scrollTop = 0; });
    await page.screenshot({ path: ".cache/ux-qa/picker-apply-dark-800x500.png" });
    await open(); await search().fill("Приложение 03"); await app(3).click(); await page.keyboard.press("Escape");
    assert.equal(await page.locator(".compact-rule").count(), 3, "Escape discarded picker choices");
    await open(); await search().fill("Приложение 03"); await app(3).click();
    await page.locator(".dialog-scrim").click({ position: { x: 2, y: 2 } });
    assert.equal(await page.locator(".compact-rule").count(), 2, "backdrop lost a draft removal");
    assert.equal(await page.getByRole("button", { name: /Добавить в правила|Отмена/ }).count(), 0);
    await page.waitForTimeout(650);
    assert.equal(await page.evaluate(() => window.pickerWrites), 0, "picker wrote before page Apply");
    assert.equal(await page.evaluate(() => window.__routeDeckFixture.snapshot().routing.apps.length), 0);
    assert.equal(await page.evaluate(() => window.__routeDeckFixture.calls.filter((call) => /^(start|stop)_/.test(call.command)).length), 0);
    scenarios += 3;
    // Existing name rules are represented as selected, never added twice.
    await page.getByRole("button", { name: "Сопоставление для Приложение 01", exact: true }).click();
    await chooseSelect(page, page.getByRole("combobox", { name: "Сопоставление приложения", exact: true }), "name");
    await page.getByRole("button", { name: "Добавить в черновик", exact: true }).click();
    await open(); await search().fill("Приложение 01");
    assert.equal(await app(1).getAttribute("aria-pressed"), "true");
    assert.match(await app(1).innerText(), /По имени/);
    await page.getByRole("button", { name: "Готово", exact: true }).click();
    assert.equal(await page.locator(".compact-rule").count(), 2);
    await page.getByRole("button", { name: "Применить правила", exact: true }).click();
    await page.waitForFunction(() => window.__routeDeckFixture.snapshot().routing.apps.length === 2);
    assert.equal(await page.evaluate(() => window.pickerWrites), 1);
    assert.equal(await page.evaluate(() => window.__routeDeckFixture.snapshot().routing.apps.filter((app) => app.matchBy === "name").length), 1);
    await page.evaluate(() => { window.__routeDeckFixture.applicationVersion = "2026.10.01"; });
    await open(); await search().fill("Приложение 01");
    assert.equal(await app(1).getAttribute("aria-pressed"), "true", "name rule coverage disappeared after executable folder changed");
    await app(1).click();
    await page.getByRole("button", { name: "Готово", exact: true }).click();
    assert.equal(await page.locator(".compact-rule").count(), 1, "existing name selection could not be removed");
    await page.getByRole("button", { name: "Отменить изменения", exact: true }).click();
    assert.equal(await page.locator(".compact-rule").count(), 2);
    scenarios += 2;
    // Refresh retains the list, scroll, search, selected state, count and button geometry.
    await open(); await search().fill("Приложение");
    await page.locator(".application-picker-list").evaluate((element) => { element.scrollTop = 660; });
    await page.evaluate(() => { window.__routeDeckFixture.applicationsDelay = 350; });
    const before = await geometry();
    const count = await page.locator(".picker-list-count").innerText();
    await page.getByRole("button", { name: "Обновить список", exact: true }).click();
    assert.equal(await page.getByRole("button", { name: "Обновить список", exact: true }).isDisabled(), true);
    assert.equal(await page.locator(".application-picker-row").count(), 80);
    assert.equal(await page.locator(".picker-list-count").innerText(), count);
    const during = await geometry();
    for (const selector of ["dialog", "footer", "list", "refresh"]) assert.deepEqual(during[selector], before[selector], `${selector} moved during refresh`);
    await page.waitForFunction(() => !document.querySelector(".picker-refresh").disabled);
    assert.equal(await search().inputValue(), "Приложение");
    assert.equal((await geometry()).list.scrollTop, before.list.scrollTop);
    await page.evaluate(() => { window.__routeDeckFixture.failApplications = true; });
    await page.getByRole("button", { name: "Обновить список", exact: true }).click();
    await page.getByRole("alert").waitFor();
    assert.equal(await page.locator(".application-picker-row").count(), 80, "failed refresh hid previous results");
    await page.getByRole("button", { name: "Закрыть окно", exact: true }).click();
    scenarios += 2;
    // Pair the actual light-mode render with short and narrow windows.
    await page.locator("nav:visible .navigation-item").filter({ hasText: "Настройки" }).click();
    await chooseSelect(page, page.getByLabel("Тема", { exact: true }), "light");
    await page.locator("nav:visible .navigation-item").filter({ hasText: "Правила" }).click();
    await page.evaluate(() => { window.__routeDeckFixture.failApplications = false; window.__routeDeckFixture.applicationsDelay = 0; });
    for (const [width, height] of [[800,500], [360,640]]) {
      await page.setViewportSize({ width, height }); await open(); await search().focus();
      await page.screenshot({ path: `.cache/ux-qa/picker-light-${width}x${height}.png` });
      await page.getByRole("button", { name: "Готово", exact: true }).click();
      await page.locator("main").evaluate((element) => { element.scrollTop = 0; });
      await page.screenshot({ path: `.cache/ux-qa/picker-apply-light-${width}x${height}.png` });
      const bar = await page.locator(".routing-apply-bar").boundingBox();
      assert.ok(bar.height <= (width > 520 ? 95 : 115), "Apply bar expanded into a large banner");
      scenarios++;
    }
    assert.deepEqual(errors, []);
    return scenarios;
  } catch (error) {
    await page.screenshot({ path: ".cache/ux-qa/picker-failure.png" });
    throw error;
  } finally { await page.close(); }
}

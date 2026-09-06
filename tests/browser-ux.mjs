// Run against `npm run dev`. No native app, engines or Windows networking APIs.
import assert from "node:assert/strict";
import { readFile, mkdir, writeFile } from "node:fs/promises";
import { createRequire } from "node:module";
const require = createRequire(import.meta.url);
const { chromium } = require(process.env.ROUTEDECK_PLAYWRIGHT_PATH || "playwright");
const base = process.env.ROUTEDECK_UI_URL || "http://127.0.0.1:1421";
const fixtureModule = await readFile(new URL("./fixtures/ui-runtime.mjs", import.meta.url), "utf8");
await mkdir(new URL("../.cache/ux-qa/", import.meta.url), { recursive: true });
const browser = await chromium.launch({ headless: true });
let scenarios = 0;
let page;
try {
  page = await browser.newPage({ viewport: { width: 440, height: 760 } });
  if (process.env.ROUTEDECK_TEST_CPU_RATE) {
    const session = await page.context().newCDPSession(page);
    await session.send("Emulation.setCPUThrottlingRate", { rate: Number(process.env.ROUTEDECK_TEST_CPU_RATE) });
  }
  await page.clock.install();
  const errors = [];
  page.on("pageerror", (error) => errors.push(error.message));
  await page.route("**/*", (route) => {
    const url = new URL(route.request().url());
    if (url.origin !== new URL(base).origin) return route.abort();
    if (url.pathname === "/src/controller.ts") return route.fulfill({ contentType: "application/javascript", body: fixtureModule });
    return route.continue();
  });
  const nav = async (name) => {
    const link = page.locator("nav:visible .navigation-item").filter({ hasText: name });
    const alreadyCurrent = await link.getAttribute("aria-current") === "page";
    await link.click();
    await page.waitForFunction(({ label, requireHeadingFocus }) => {
      const current = document.querySelector('nav:where(:not([hidden])) [aria-current="page"]');
      const heading = document.querySelector('.page-slot:not([hidden]) h1');
      return current?.textContent?.trim() === label && (!requireHeadingFocus || heading === document.activeElement);
    }, { label: name, requireHeadingFocus: !alreadyCurrent });
  };
  const settle = () => page.waitForFunction(() => !window.__routeDeckFixture.snapshot().switching);
  const connected = () => page.waitForFunction(() => window.__routeDeckFixture.snapshot().phase === "connected" && !window.__routeDeckFixture.snapshot().switching);
  const checkFrame = async () => {
    const frame = await page.evaluate(() => ({
      main: document.querySelector("main").getBoundingClientRect().top,
      header: document.querySelector(".app-header").getBoundingClientRect().top,
      scrolls: [document.documentElement, document.body, document.querySelector("#root"), document.querySelector(".app-shell"), document.querySelector(".workspace")].map((element) => element.scrollTop),
      horizontal: document.documentElement.scrollWidth > innerWidth,
    }));
    assert.equal(frame.header, 0, "header left the window");
    assert.ok(frame.main >= 0 && frame.main < 180, "main viewport left the window");
    assert.deepEqual(frame.scrolls, [0, 0, 0, 0, 0], "an outer frame scrolled");
    assert.equal(frame.horizontal, false);
  };
  await page.goto(base);
  await page.waitForFunction(() => window.__routeDeckFixture?.snapshot().backendAvailable);
  await page.screenshot({ path: ".cache/ux-qa/home-disconnected.png" });
  await nav("Серверы");
  await page.locator(".server-row").nth(85).click();
  await settle(); await checkFrame();
  assert.equal(await page.locator(".server-row").nth(85).evaluate((element) => getComputedStyle(element).outlineStyle), "none", "pointer selection must not paint a clipped focus stripe");
  assert.equal(await page.locator(".page-slot:not([hidden]) h1").innerText(), "Серверы");
  const position = await page.locator("main").evaluate((element) => element.scrollTop);
  await nav("Главная"); await nav("Серверы");
  await page.waitForFunction((position) => Math.abs(document.querySelector("main").scrollTop - position) < 2, position);
  await checkFrame(); scenarios += 2;

  await nav("Главная");
  await page.locator(".server-choice").click();
  await page.locator(".server-row").nth(86).click();
  await page.getByRole("heading", { name: "Главная", exact: true }).waitFor();
  await checkFrame(); scenarios++;
  await page.locator(".server-choice").click();
  await page.locator('.server-row[data-selected="true"]').click();
  await page.getByRole("heading", { name: "Главная", exact: true }).waitFor();
  await checkFrame(); scenarios++;
  await page.getByRole("button", { name: "Подключить", exact: true }).click();
  await connected();
  await page.screenshot({ path: ".cache/ux-qa/home-connected.png" });
  assert.match(await page.locator(".connection-metrics").innerText(), /42 мс/);
  assert.doesNotMatch(await page.locator(".connection-metrics").innerText(), /384 мс/);
  await page.getByRole("button", { name: "Как измеряется отклик через VPN" }).click();
  await page.getByRole("dialog").getByText(/DNS и установка TCP\/TLS/).waitFor();
  await page.getByRole("button", { name: "Понятно", exact: true }).click();
  await page.getByRole("dialog").waitFor({ state: "hidden" }); await checkFrame(); scenarios++;
  await page.evaluate(() => window.__routeDeckFixture.setMetricAvailable(false));
  assert.equal(await page.locator(".latency-metric strong").innerText(), "—");
  assert.equal(await page.evaluate(() => window.__routeDeckFixture.snapshot().phase), "connected");
  await page.evaluate(() => window.__routeDeckFixture.setMetricAvailable(true)); scenarios++;
  await page.locator('.mode-section label').filter({ hasText: /^TUN$/ }).click();
  await connected();
  assert.equal(await page.evaluate(() => window.__routeDeckFixture.snapshot().activeMode), "tun");
  await page.locator(".server-choice").click();
  await page.getByRole("searchbox").fill("Мой Naive");
  await page.locator(".server-row:visible").click();
  await connected(); await checkFrame();
  const sequence = await page.evaluate(() => window.__routeDeckFixture.calls.map((entry) => entry.command).filter((entry) => /^(start|stop)_/.test(entry)));
  assert.deepEqual(sequence, ["start_system_proxy", "stop_system_proxy", "start_tun"]);
  assert.equal(await page.evaluate(() => window.__routeDeckFixture.calls.filter(entry => entry.command === "switch_tun_server").length), 1);
  scenarios += 3;

  await nav("Серверы");
  const serverSearch = page.getByRole("searchbox");
  await serverSearch.fill("");
  await page.waitForFunction(() => {
    const search = document.querySelector('.page-slot:not([hidden]) input[type="search"]');
    const refresh = document.querySelector('button[aria-label="Обновить подписку Основная подписка"]');
    return search?.value === "" && refresh instanceof HTMLButtonElement && !refresh.disabled;
  });
  await page.getByRole("button", { name: "Обновить подписку Основная подписка", exact: true }).click();
  await settle(); await checkFrame();
  assert.equal(await page.evaluate(() => window.__routeDeckFixture.calls.filter((entry) => /^stop_/.test(entry.command)).length), 1, "refreshing another source stopped active runtime");
  await page.getByRole("button", { name: "Обновить подписку Старая подписка", exact: true }).click();
  await page.getByLabel("Ссылка на подписку", { exact: true }).fill("https://provider.invalid/fixture-token");
  await page.getByRole("button", { name: "Обновить", exact: true }).click();
  await page.getByRole("dialog").waitFor({ state: "hidden" }); await settle(); await checkFrame();
  scenarios += 2;

  await page.getByRole("button", { name: "Удалить группу Личные серверы", exact: true }).click();
  await page.getByRole("button", { name: "Отмена", exact: true }).click(); await checkFrame();
  await page.getByRole("button", { name: "Удалить группу Личные серверы", exact: true }).click();
  await page.getByRole("button", { name: "Удалить группу", exact: true }).click();
  await page.getByRole("dialog").waitFor({ state: "hidden" }); await settle();
  assert.equal(await page.evaluate(() => window.__routeDeckFixture.snapshot().phase), "disconnected");
  assert.equal(await page.getByRole("button", { name: "Удалить группу Личные серверы", exact: true }).count(), 0);
  scenarios += 2;

  await page.getByRole("button", { name: "Добавить сервер", exact: true }).click();
  await page.getByLabel("Ссылка или конфигурация сервера").fill("naive+https://fixture:secret@example.invalid");
  await page.getByLabel("Название группы").fill("Импорт для проверки");
  await page.getByRole("button", { name: "Продолжить", exact: true }).click();
  await page.getByRole("heading", { name: /Серверов для добавления/ }).waitFor();
  assert.equal(await page.locator("#server-content").inputValue(), "");
  for (let index = 0; index < 8; index++) {
    await page.keyboard.press("Tab");
    assert.equal(await page.evaluate(() => Boolean(document.activeElement.closest('[role="dialog"]'))), true);
  }
  await page.getByRole("button", { name: "Добавить", exact: true }).click();
  await page.getByRole("dialog").waitFor({ state: "hidden" }); await checkFrame();
  scenarios++;

  await page.evaluate(() => { window.__routeDeckFixture.failRefresh = true; });
  await page.getByRole("button", { name: "Обновить подписку Основная подписка", exact: true }).click();
  await settle();
  await page.getByRole("alert").first().waitFor(); await checkFrame();
  assert.equal(await page.evaluate(() => window.__routeDeckFixture.snapshot().servers.length), 132);
  await page.evaluate(() => { window.__routeDeckFixture.failRefresh = false; });
  scenarios++;

  for (const size of [{ width: 360, height: 560 }, { width: 440, height: 760 }, { width: 1000, height: 800 }]) {
    await page.setViewportSize(size); await nav("Главная"); await checkFrame();
    await page.getByRole("button", { name: "Как измеряется отклик через VPN" }).click();
    const metricDialog = await page.getByRole("dialog").boundingBox();
    assert.ok(metricDialog.y >= 0 && metricDialog.y + metricDialog.height <= size.height + 1);
    await page.keyboard.press("Escape"); await page.getByRole("dialog").waitFor({ state: "hidden" });
    await page.getByRole("button", { name: "Подключить", exact: true }).scrollIntoViewIfNeeded();
    await nav("Серверы"); await page.locator(".server-row").nth(85).click(); await settle(); await checkFrame();
    await page.screenshot({ path: `.cache/ux-qa/library-${size.width}.png` });
    await page.getByRole("button", { name: "Подписка", exact: true }).click();
    await page.keyboard.press("Escape"); await page.getByRole("dialog").waitFor({ state: "hidden" }); await checkFrame();
    scenarios++;
  }
  await page.setViewportSize({ width: 900, height: 900 });
  await page.evaluate(() => { document.documentElement.dataset.theme = "light"; document.documentElement.style.zoom = "2"; });
  await nav("Главная"); await checkFrame();
  await page.screenshot({ path: ".cache/ux-qa/light-200-percent.png" });
  await page.getByRole("button", { name: "Как измеряется отклик через VPN" }).click();
  await page.getByRole("button", { name: "Понятно", exact: true }).click(); await checkFrame();
  await page.emulateMedia({ reducedMotion: "reduce" });
  await nav("Серверы"); await page.locator(".server-row").nth(85).click(); await settle(); await checkFrame();
  scenarios++;
  await page.evaluate(() => { document.documentElement.style.zoom = "1"; document.documentElement.dataset.theme = "dark"; window.__routeDeckFixture.startDelay = 250; });
  await page.setViewportSize({ width: 440, height: 760 }); await nav("Главная");
  await page.getByRole("button", { name: "Подключить", exact: true }).click();
  await page.getByRole("button", { name: "Отменить подключение", exact: true }).click();
  await settle();
  assert.equal(await page.evaluate(() => window.__routeDeckFixture.snapshot().phase), "disconnected");
  scenarios++;
  await page.evaluate(() => { window.__routeDeckFixture.startDelay = 40; });
  await page.getByRole("button", { name: "Подключить", exact: true }).click(); await connected();
  await page.locator('.mode-section label').filter({ hasText: /^Системный прокси$/ }).click();
  await page.locator('.mode-section label').filter({ hasText: /^TUN$/ }).click();
  await connected();
  assert.equal(await page.evaluate(() => window.__routeDeckFixture.snapshot().activeMode), "tun");
  scenarios++;
  await nav("Серверы");
  await page.evaluate(() => { window.__routeDeckFixture.failRefresh = true; });
  await page.getByRole("button", { name: "Обновить подписку Основная подписка", exact: true }).click();
  await settle(); await connected();
  await page.getByRole("alert").first().waitFor();
  await checkFrame();
  await page.evaluate(() => { window.__routeDeckFixture.failRefresh = false; window.__routeDeckFixture.failStop = true; });
  await nav("Главная");
  const startsBefore = await page.evaluate(() => window.__routeDeckFixture.calls.filter((entry) => entry.command.startsWith("start_")).length);
  await page.locator('.mode-section label').filter({ hasText: /^Системный прокси$/ }).click();
  await settle(); await page.getByRole("alert").first().waitFor();
  assert.equal(await page.evaluate(() => window.__routeDeckFixture.calls.filter((entry) => entry.command.startsWith("start_")).length), startsBefore);
  await page.evaluate(() => { window.__routeDeckFixture.failStop = false; });
  await page.getByRole("button", { name: "Отключить", exact: true }).click(); await settle();
  await checkFrame(); scenarios += 2;
  // Twenty application rules: compact list, batch add and autosave across navigation.
  await nav("Правила");
  await page.getByRole("button", { name: "Добавить", exact: true }).click();
  await page.locator(".application-picker-row").nth(19).waitFor();
  for (let index = 0; index < 20; index++) await page.locator(".application-picker-row").nth(index).click();
  await page.getByRole("button", { name: "Готово · 20", exact: true }).click();
  await nav("Главная");
  await page.waitForFunction(() => window.__routeDeckFixture.snapshot().routing.apps.length === 20);
  await nav("Правила");
  await page.getByText("Сохранено", { exact: true }).waitFor();
  assert.equal(await page.locator(".compact-rule").count(), 20);
  assert.ok((await page.locator(".compact-rule").first().boundingBox()).height <= 56);
  assert.equal(await page.getByRole("button", { name: "Сохранить правила", exact: true }).count(), 0);
  await page.getByRole("searchbox", { name: "Найти правило" }).fill("Приложение 17");
  assert.equal(await page.locator(".compact-rule").count(), 1);
  await page.getByLabel("Маршрут для Приложение 17").selectOption("inherit");
  await page.getByLabel("Пути", { exact: true }).check();
  assert.match(await page.locator(".rule-app-copy small").innerText(), /app17.exe/);
  await page.getByRole("searchbox", { name: "Найти правило" }).fill("");
  await page.getByLabel("Пути", { exact: true }).uncheck();
  await page.getByText("Сохранено", { exact: true }).waitFor(); scenarios += 3;
  for (const size of [{ width: 360, height: 560 }, { width: 1000, height: 900 }]) {
    await page.setViewportSize(size); await checkFrame();
    await page.locator("main").evaluate((element) => { element.scrollTop = 0; });
    await page.screenshot({ path: `.cache/ux-qa/rules-${size.width}.png` });
    const appRows = await page.locator(".compact-rule").evaluateAll((rows) => rows.map((row) => { const b = row.getBoundingClientRect(); return { x: b.x, y: b.y, width: b.width }; }));
    assert.ok(appRows.every((row, index) => row.x === appRows[0].x && row.width === appRows[0].width && (index === 0 || row.y > appRows[index - 1].y)), "apps stay in one column at every width");
    assert.equal(await page.locator("main").evaluate((element) => element.scrollWidth > element.clientWidth), false);
    await nav("Настройки"); await checkFrame();
    await page.screenshot({ path: `.cache/ux-qa/settings-${size.width}.png` });
    assert.equal(await page.locator("main").evaluate((element) => element.scrollWidth > element.clientWidth), false);
    await nav("Правила"); scenarios++;
  }
  // A failed local write is visible, retained across pages and explicitly retryable.
  await page.evaluate(() => { window.fixtureOriginalSetItem = Storage.prototype.setItem; Storage.prototype.setItem = function () { throw new DOMException("Fixture", "QuotaExceededError"); }; });
  await page.getByLabel("Маршрут для Приложение 01").selectOption("direct");
  await page.locator(".save-feedback [role=alert]").waitFor();
  await nav("Настройки"); await nav("Правила");
  await page.locator(".save-feedback [role=alert]").waitFor();
  await page.evaluate(() => { Storage.prototype.setItem = window.fixtureOriginalSetItem; });
  await page.locator(".save-feedback").getByRole("button", { name: "Повторить" }).click();
  await page.getByText("Сохранено", { exact: true }).waitFor(); scenarios++;
  await nav("Настройки");
  await page.getByLabel("Тема", { exact: true }).selectOption("light");
  await page.getByText("Сохранено", { exact: true }).waitFor();
  assert.equal(await page.locator("html").getAttribute("data-theme"), "light");
  await page.reload(); await page.waitForFunction(() => window.__routeDeckFixture?.snapshot().backendAvailable);
  assert.equal(await page.locator("html").getAttribute("data-theme"), "light");
  await nav("Правила"); assert.equal(await page.locator(".compact-rule").count(), 20); scenarios++;
  await page.setViewportSize({ width: 900, height: 900 });
  await page.evaluate(() => { document.documentElement.style.zoom = "2"; });
  for (const destination of ["Правила", "Настройки"]) {
    await nav(destination); await checkFrame();
    assert.equal(await page.locator("main").evaluate((element) => element.scrollWidth > element.clientWidth), false);
  }
  await page.evaluate(() => { document.documentElement.style.zoom = "1"; }); scenarios++;
  await nav("Серверы");
  await page.locator(".server-row").nth(3).click();
  await page.keyboard.press("ArrowDown"); await settle(); await checkFrame();
  assert.equal(await page.locator('.server-row[data-selected="true"]').evaluate((element) => getComputedStyle(element).outlineStyle), "solid", "keyboard focus must remain visible inside the row"); scenarios++;
  // Editing while connected triggers one safe stop/start and keeps current page.
  await nav("Главная"); await page.getByRole("button", { name: "Подключить", exact: true }).click(); await connected();
  const beforeRules = await page.evaluate(() => window.__routeDeckFixture.calls.filter((entry) => entry.command.startsWith("start_")).length);
  await nav("Правила"); await page.getByLabel("Маршрут для Приложение 01").selectOption("vpn");
  await page.getByText("Сохранено", { exact: true }).waitFor(); await connected();
  assert.equal(await page.evaluate(() => window.__routeDeckFixture.calls.filter((entry) => entry.command.startsWith("start_")).length), beforeRules + 1);
  await checkFrame(); scenarios++;
  await page.evaluate(() => { window.__routeDeckFixture.startDelay = 1500; });
  await page.getByLabel("Маршрут для Приложение 02").selectOption("direct");
  await page.waitForFunction(() => window.__routeDeckFixture.snapshot().phase === "starting-core");
  await page.getByLabel("Маршрут для Приложение 02").selectOption("vpn");
  await page.getByLabel("Маршрут для Приложение 03").selectOption("direct");
  await page.getByText("Сохранено", { exact: true }).waitFor(); await connected();
  assert.deepEqual(await page.evaluate(() => window.__routeDeckFixture.snapshot().routing.apps.slice(1, 3).map((app) => app.route)), ["vpn", "direct"], "late save completion overwrote a newer draft");
  await page.evaluate(() => { window.__routeDeckFixture.startDelay = 40; }); scenarios++;
  // Background refresh waits until disconnected and reuses URLs without dialogs.
  await nav("Настройки"); await page.getByLabel("Автообновление подписок").selectOption("6");
  await page.getByText("Сохранено", { exact: true }).waitFor();
  await page.clock.fastForward(61_000);
  assert.equal(await page.evaluate(() => window.__routeDeckFixture.calls.filter((entry) => entry.command === "refresh_source").length), 0);
  await nav("Главная"); await page.getByRole("button", { name: "Отключить", exact: true }).click(); await settle();
  await page.evaluate(() => { window.__routeDeckFixture.refreshDelay = 1500; });
  await page.clock.fastForward(61_000);
  await page.waitForFunction(() => window.__routeDeckFixture.calls.some((entry) => entry.command === "refresh_source"));
  await page.locator(".connection-hero").getByRole("heading", { name: "Отключено", exact: true }).waitFor();
  await page.clock.runFor(1600); await settle();
  assert.equal(await page.evaluate(() => window.__routeDeckFixture.calls.filter((entry) => entry.command === "refresh_source").length), 1);
  assert.equal(await page.getByRole("dialog").count(), 0);
  await page.clock.fastForward(61_000); await settle();
  assert.equal(await page.evaluate(() => window.__routeDeckFixture.calls.filter((entry) => entry.command === "refresh_source").length), 1); scenarios++;
  // Every constrained page stays centered inside the content viewport.
  for (const width of [1600, 1920]) {
    await page.setViewportSize({ width, height: 900 });
    for (const destination of ["Главная", "Серверы", "Правила", "Настройки", "Статус"]) {
      await nav(destination); await checkFrame();
      const offset = await page.evaluate(() => {
        const main = document.querySelector("main");
        const content = document.querySelector(".page-slot:not([hidden]) .page");
        const box = content.getBoundingClientRect();
        return box.left + box.width / 2 - (main.getBoundingClientRect().left + main.clientWidth / 2);
      });
      assert.ok(Math.abs(offset) < 2, `${destination} is off-center by ${offset}px`);
    }
  }
  await page.screenshot({ path: ".cache/ux-qa/status-wide.png" }); scenarios++;
  for (const theme of ["dark", "light"]) {
    await nav("Настройки"); await page.getByLabel("Тема", { exact: true }).selectOption(theme);
    await page.getByText("Сохранено", { exact: true }).waitFor();
    await nav("Серверы");
    for (const width of [360, 1920, 440, 1200, 360, 1600, 720, 440]) {
      await page.setViewportSize({ width, height: 760 }); await checkFrame();
      const fill = await page.evaluate(() => ({
        body: getComputedStyle(document.body).backgroundColor,
        html: getComputedStyle(document.documentElement).backgroundColor,
        scheme: getComputedStyle(document.documentElement).colorScheme,
        scrollbar: getComputedStyle(document.querySelector("main")).scrollbarColor,
        overflow: document.querySelector("main").scrollWidth > document.querySelector("main").clientWidth,
      }));
      assert.equal(fill.body, theme === "dark" ? "rgb(11, 14, 20)" : "rgb(244, 247, 251)");
      assert.equal(fill.html, fill.body); assert.equal(fill.scheme, theme);
      assert.notEqual(fill.scrollbar, "auto"); assert.equal(fill.overflow, false);
    }
    await page.screenshot({ path: `.cache/ux-qa/library-scrollbar-${theme}.png` });
  }
  scenarios++;
  await page.emulateMedia({ forcedColors: "active" });
  assert.equal(await page.locator("main").evaluate((element) => getComputedStyle(element).scrollbarColor), "auto");
  await page.emulateMedia({ forcedColors: "none" }); scenarios++;
  const contextMenu = await page.locator(".server-row").first().evaluate((element) => {
    let applicationHandler = false;
    element.addEventListener("contextmenu", () => { applicationHandler = true; }, { once: true });
    const event = new MouseEvent("contextmenu", { bubbles: true, cancelable: true, button: 2 });
    element.dispatchEvent(event);
    return { prevented: event.defaultPrevented, applicationHandler };
  });
  assert.deepEqual(contextMenu, { prevented: true, applicationHandler: true });
  const search = page.getByRole("searchbox"); await search.fill("temporary");
  await search.press("Control+A"); await search.press("Backspace"); assert.equal(await search.inputValue(), "");
  await checkFrame(); scenarios++;
  // Stale foreign proxy actions are previewed and explicitly confirmed. The
  // fixture cannot touch Windows settings or terminate a real process.
  await nav("Статус");
  await page.getByRole("button", { name: "Обновить состояние", exact: true }).click();
  await page.getByRole("button", { name: "Отключить неработающий прокси", exact: true }).waitFor();
  for (const width of [360, 1200]) {
    await page.setViewportSize({ width, height: 760 }); await checkFrame();
    assert.equal(await page.locator("main").evaluate((element) => element.scrollWidth > element.clientWidth), false);
    await page.screenshot({ path: `.cache/ux-qa/proxy-diagnostics-${width}.png` });
  }
  const cleanupCount = () => page.evaluate(() => window.__routeDeckFixture.calls.filter((entry) => entry.command === "clear_stale_system_proxy").length);
  await page.getByRole("button", { name: "Отключить неработающий прокси", exact: true }).click();
  await page.getByRole("dialog").getByRole("button", { name: "Отмена", exact: true }).click();
  assert.equal(await cleanupCount(), 0); scenarios += 2;
  // Refreshing a preview closes its old confirmation rather than approving a
  // different snapshot with an earlier click.
  await page.getByRole("button", { name: "Отключить неработающий прокси", exact: true }).click();
  await page.evaluate(async () => {
    window.__routeDeckFixture.systemProxy.cleanupToken = "f".repeat(64);
    await window.__routeDeckFixture.runDiagnostics();
  });
  await page.getByRole("dialog").waitFor({ state: "hidden" });
  assert.equal(await cleanupCount(), 0); scenarios++;
  await page.evaluate(() => { window.__routeDeckFixture.failProxyCleanup = true; });
  await page.getByRole("button", { name: "Отключить неработающий прокси", exact: true }).click();
  await page.getByRole("dialog").getByRole("button", { name: "Отключить прокси", exact: true }).click();
  await page.getByRole("dialog").waitFor({ state: "hidden" });
  await page.getByRole("alert").filter({ hasText: "Не удалось отключить неработающий прокси" }).waitFor();
  assert.equal(await cleanupCount(), 1); await checkFrame(); scenarios++;
  await page.evaluate(() => { window.__routeDeckFixture.failProxyCleanup = false; });
  await page.getByRole("button", { name: "Обновить состояние", exact: true }).click();
  await page.getByRole("button", { name: "Отключить неработающий прокси", exact: true }).click();
  await page.getByRole("dialog").getByRole("button", { name: "Отключить прокси", exact: true }).click();
  await page.getByRole("dialog").waitFor({ state: "hidden" });
  await page.locator(".system-proxy-card [data-state=disabled]").waitFor();
  assert.equal(await cleanupCount(), 2);
  assert.equal(await page.getByRole("button", { name: "Отключить неработающий прокси", exact: true }).count(), 0);
  await checkFrame(); scenarios++;

  // Stack selection is persisted and handed only to TUN. A live TUN changes
  // through stop/start; the same preference edit leaves System Proxy running.
  await nav("Правила");
  await page.locator(".tun-stack-settings summary").click();
  await page.getByLabel("Стек TUN", { exact: true }).selectOption("gvisor");
  await page.getByText("Сохранено", { exact: true }).waitFor();
  await page.setViewportSize({ width: 360, height: 760 }); await checkFrame();
  assert.equal(await page.locator("main").evaluate((element) => element.scrollWidth > element.clientWidth), false);
  await page.locator(".tun-stack-settings").scrollIntoViewIfNeeded();
  await page.screenshot({ path: ".cache/ux-qa/tun-stack-360.png" });
  await nav("Главная");
  await page.locator('.mode-section label').filter({ hasText: /^TUN$/ }).click();
  await page.getByRole("button", { name: "Подключить", exact: true }).click(); await connected();
  assert.equal(await page.evaluate(() => window.__routeDeckFixture.calls.filter((entry) => entry.command === "start_tun").at(-1).routing.stack), "gvisor");
  const beforeStack = await page.evaluate(() => window.__routeDeckFixture.calls.filter((entry) => /^(start|stop)_/.test(entry.command)).length);
  await nav("Правила");
  await page.locator(".tun-stack-settings summary").click();
  await page.getByLabel("Стек TUN", { exact: true }).selectOption("system");
  await page.getByText("Сохранено", { exact: true }).waitFor(); await connected();
  assert.deepEqual(await page.evaluate((count) => window.__routeDeckFixture.calls.filter((entry) => /^(start|stop)_/.test(entry.command)).slice(count).map((entry) => entry.command), beforeStack), ["stop_tun", "start_tun"]);
  assert.equal(await page.evaluate(() => window.__routeDeckFixture.calls.filter((entry) => entry.command === "start_tun").at(-1).routing.stack), "system");
  await nav("Главная");
  await page.locator('.mode-section label').filter({ hasText: /^Системный прокси$/ }).click(); await connected();
  const beforeProxyStack = await page.evaluate(() => window.__routeDeckFixture.calls.filter((entry) => /^(start|stop)_/.test(entry.command)).length);
  await nav("Правила");
  await page.locator(".tun-stack-settings summary").click();
  await page.getByLabel("Стек TUN", { exact: true }).selectOption("gvisor");
  await page.getByText("Сохранено", { exact: true }).waitFor(); await connected();
  assert.equal(await page.evaluate(() => window.__routeDeckFixture.calls.filter((entry) => /^(start|stop)_/.test(entry.command)).length), beforeProxyStack);
  assert.equal(await page.evaluate(() => Object.hasOwn(window.__routeDeckFixture.calls.filter((entry) => entry.command === "start_system_proxy").at(-1).routing, "stack")), false);
  await checkFrame(); scenarios += 3;

  // Typed traffic-rule editor: save/cancel, boundary feedback, first-match order,
  // persistence and TUN-only runtime changes, using synthetic IPC throughout.
  await page.locator(".traffic-rules summary").click();
  assert.equal(await page.getByLabel("Включить правило 1", { exact: true }).isChecked(), true);
  await page.getByRole("button", { name: "Добавить правило", exact: true }).click();
  await page.getByLabel("Порт", { exact: true }).fill("53");
  await page.getByRole("button", { name: "Применить", exact: true }).click();
  await page.getByRole("alert").filter({ hasText: "Порт 53 зарезервирован" }).waitFor();
  assert.equal(await page.evaluate(() => window.__routeDeckFixture.snapshot().routing.trafficRules.length), 1);
  await page.getByRole("button", { name: "Отмена", exact: true }).click();
  await page.getByRole("dialog").waitFor({ state: "hidden" }); scenarios++;

  await page.getByRole("button", { name: "Добавить правило", exact: true }).click();
  await page.getByLabel("Действие", { exact: true }).selectOption("direct");
  for (const size of [{ width: 360, height: 560 }, { width: 1200, height: 800 }]) {
    await page.setViewportSize(size); await checkFrame();
    const box = await page.getByRole("dialog").boundingBox();
    assert.ok(box.x >= 0 && box.x + box.width <= size.width + 1 && box.y >= 0 && box.y + box.height <= size.height + 1);
    await page.screenshot({ path: `.cache/ux-qa/traffic-editor-${size.width}.png` });
  }
  await page.getByRole("button", { name: "Применить", exact: true }).click();
  await page.getByRole("dialog").waitFor({ state: "hidden" });
  await page.getByText("Сохранено", { exact: true }).waitFor();
  assert.equal(await page.locator(".traffic-rule-row").count(), 2);
  assert.equal(await page.evaluate(() => window.__routeDeckFixture.calls.filter((entry) => /^(start|stop)_/.test(entry.command)).length), beforeProxyStack);
  await page.getByRole("button", { name: "Поднять правило 2", exact: true }).click();
  await page.getByText("Сохранено", { exact: true }).waitFor();
  assert.equal(await page.locator(".traffic-rules summary").getByText("UDP 443 блокируется", { exact: true }).count(), 0, "earlier direct rule overrides later block");
  await page.getByLabel("Включить правило 1", { exact: true }).uncheck();
  await page.getByText("Сохранено", { exact: true }).waitFor();
  await page.locator(".traffic-rules summary").getByText("UDP 443 блокируется", { exact: true }).waitFor(); scenarios += 3;

  await page.locator(".traffic-rule-row").first().getByRole("button", { name: "Изменить", exact: true }).click();
  await page.getByLabel("Сеть", { exact: true }).selectOption("tcp");
  await page.getByLabel("Порт", { exact: true }).fill("8443");
  await page.getByLabel("Действие", { exact: true }).selectOption("vpn");
  await page.getByRole("button", { name: "Применить", exact: true }).click();
  await page.getByRole("dialog").waitFor({ state: "hidden" });
  await page.getByText("Сохранено", { exact: true }).waitFor();
  assert.equal(await page.locator(".traffic-rule-row").first().getByText("TCP 8443", { exact: true }).count(), 1);
  await page.getByLabel("Включить правило 1", { exact: true }).check();
  await page.getByText("Сохранено", { exact: true }).waitFor();
  for (const width of [360, 1200]) {
    await page.setViewportSize({ width, height: 800 });
    await page.locator(".traffic-rules").scrollIntoViewIfNeeded(); await checkFrame();
    assert.equal(await page.locator("main").evaluate((element) => element.scrollWidth > element.clientWidth), false);
    const rowsFit = await page.locator(".traffic-rule-row").evaluateAll((rows) => rows.every((row) => row.scrollWidth <= row.clientWidth));
    assert.equal(rowsFit, true);
    await page.screenshot({ path: `.cache/ux-qa/traffic-rules-${width}.png` });
  }
  await nav("Главная");
  await page.locator('.mode-section label').filter({ hasText: /^TUN$/ }).click(); await connected();
  assert.deepEqual(await page.evaluate(() => window.__routeDeckFixture.calls.filter((entry) => entry.command === "start_tun").at(-1).routing.trafficRules), [
    { network: "tcp", port: 8443, action: "vpn" }, { network: "udp", port: 443, action: "block" },
  ]); scenarios++;
  const beforeTraffic = await page.evaluate(() => window.__routeDeckFixture.calls.filter((entry) => /^(start|stop)_/.test(entry.command)).length);
  await nav("Правила");
  await page.locator(".traffic-rules summary").click();
  await page.getByRole("button", { name: "Удалить правило 1", exact: true }).click();
  await page.getByText("Сохранено", { exact: true }).waitFor(); await connected();
  assert.deepEqual(await page.evaluate((count) => window.__routeDeckFixture.calls.filter((entry) => /^(start|stop)_/.test(entry.command)).slice(count).map((entry) => entry.command), beforeTraffic), ["stop_tun", "start_tun"]);
  const savedTraffic = await page.evaluate(() => window.__routeDeckFixture.snapshot().routing.trafficRules);
  await page.reload();
  await page.waitForFunction(() => window.__routeDeckFixture?.snapshot().backendAvailable);
  assert.deepEqual(await page.evaluate(() => window.__routeDeckFixture.snapshot().routing.trafficRules), savedTraffic);
  await nav("Правила");
  await page.locator(".traffic-rules summary").click();
  await page.getByRole("button", { name: "Удалить правило 1", exact: true }).click();
  await page.getByText("Сохранено", { exact: true }).waitFor();
  await page.reload();
  await page.waitForFunction(() => window.__routeDeckFixture?.snapshot().backendAvailable);
  assert.deepEqual(await page.evaluate(() => window.__routeDeckFixture.snapshot().routing.trafficRules), []); scenarios += 2;

  await nav("Правила");
  await page.locator(".naive-settings summary").click();
  assert.equal(await page.getByLabel("UDP over TCP для Naive", { exact: true }).isChecked(), false);
  await page.getByLabel("UDP over TCP для Naive", { exact: true }).check();
  await page.getByText("Сохранено", { exact: true }).waitFor();
  for (const width of [360, 1600]) {
    await page.setViewportSize({ width, height: 800 });
    await page.locator(".naive-settings").scrollIntoViewIfNeeded(); await checkFrame();
    assert.equal(await page.locator("main").evaluate((element) => element.scrollWidth > element.clientWidth), false);
    await page.screenshot({ path: `.cache/ux-qa/naive-settings-${width}.png` });
  }
  await nav("Серверы");
  await page.getByRole("searchbox").fill("Мой Naive");
  await page.locator(".server-row:visible").click();
  await page.locator(".server-row:visible").getByText(/UoT v2 включён/).waitFor();
  const selectedNaive = await page.evaluate(() => window.__routeDeckFixture.snapshot().selectedServerId);
  await nav("Главная");
  await page.locator('.mode-section label').filter({ hasText: /^TUN$/ }).click();
  await page.reload();
  await page.waitForFunction(() => window.__routeDeckFixture?.snapshot().backendAvailable);
  assert.equal(await page.evaluate(() => window.__routeDeckFixture.snapshot().selectedServerId), selectedNaive);
  assert.equal(await page.evaluate(() => window.__routeDeckFixture.snapshot().mode), "tun");
  assert.equal(await page.evaluate(() => window.__routeDeckFixture.snapshot().phase), "disconnected");
  assert.equal(await page.evaluate(() => window.__routeDeckFixture.snapshot().routing.naiveUdpOverTcp), true);
  await page.getByRole("button", { name: "Подключить", exact: true }).click(); await connected();
  assert.equal(await page.evaluate(() => window.__routeDeckFixture.calls.filter((entry) => entry.command === "start_tun").at(-1).routing.naiveUdpOverTcp), true);
  await nav("Правила");
  await page.locator(".naive-settings summary").click();
  await page.getByLabel("UDP over TCP для Naive", { exact: true }).uncheck();
  await page.getByText("Сохранено", { exact: true }).waitFor(); await connected();
  assert.equal(await page.evaluate(() => Boolean(window.__routeDeckFixture.calls.filter((entry) => entry.command === "start_tun").at(-1).routing.naiveUdpOverTcp)), false);
  scenarios += 3;

  // Update checks stay inside typed synthetic IPC; no request may leave the Vite origin.
  await nav("Настройки");
  await page.getByText("Версия 0.1.0", { exact: true }).waitFor();
  await page.getByText("Установлена актуальная версия", { exact: true }).waitFor();
  await page.evaluate(() => { window.__routeDeckFixture.updateResponse = { currentVersion: "0.1.0", latestVersion: "0.2.0", status: "available", releaseUrl: "https://github.com/oda02/RouteDeck/releases/latest" }; });
  await page.getByRole("button", { name: "Проверить", exact: true }).click();
  await page.getByText("Доступна версия 0.2.0", { exact: true }).waitFor();
  const opensBefore = await page.evaluate(() => window.__routeDeckFixture.calls.filter((entry) => entry.command === "open_app_releases").length);
  await page.getByRole("button", { name: "Скачать на GitHub", exact: true }).click();
  await page.waitForFunction((count) => window.__routeDeckFixture.calls.filter((entry) => entry.command === "open_app_releases").length === count + 1, opensBefore);
  assert.equal(await page.evaluate(() => window.__routeDeckFixture.calls.some((entry) => Object.hasOwn(entry, "url"))), false);
  await page.evaluate(() => { window.__routeDeckFixture.updateResponse = { currentVersion: "0.1.0", latestVersion: null, status: "noRelease", releaseUrl: null }; });
  await page.getByRole("button", { name: "Проверить", exact: true }).click();
  await page.getByText("Опубликованных выпусков пока нет", { exact: true }).waitFor();
  await page.evaluate(() => { window.__routeDeckFixture.failUpdateCheck = true; });
  await page.getByRole("button", { name: "Проверить", exact: true }).click();
  await page.getByText("Не удалось проверить обновления", { exact: true }).waitFor();
  await page.evaluate(() => { window.__routeDeckFixture.failUpdateCheck = false; window.__routeDeckFixture.updateResponse = { currentVersion: "0.1.0", latestVersion: "0.1.0", status: "upToDate", releaseUrl: null }; });
  await page.getByRole("button", { name: "Повторить", exact: true }).click();
  await page.getByText("Установлена актуальная версия", { exact: true }).waitFor();
  for (const width of [360, 1200]) {
    await page.setViewportSize({ width, height: 800 });
    await page.locator(".update-settings").scrollIntoViewIfNeeded(); await checkFrame();
    assert.equal(await page.locator(".update-settings").evaluate((element) => element.scrollWidth > element.clientWidth), false);
    await page.screenshot({ path: `.cache/ux-qa/update-settings-${width}.png` });
  }
  await page.getByLabel("Проверять автоматически раз в 6 часов", { exact: true }).uncheck();
  assert.equal(await page.evaluate(() => JSON.parse(localStorage.getItem("routedeck.updates.v1")).automatic), false);
  await page.reload(); await page.waitForFunction(() => window.__routeDeckFixture?.snapshot().backendAvailable);
  await nav("Настройки");
  assert.equal(await page.getByLabel("Проверять автоматически раз в 6 часов", { exact: true }).isChecked(), false);
  assert.equal(await page.evaluate(() => window.__routeDeckFixture.calls.filter((entry) => entry.command === "check_app_update").length), 0);
  scenarios += 6;

  assert.deepEqual(errors, []);
  console.log(`PASS: ${scenarios} browser scenarios; real frontend controller with synthetic IPC, no native networking`);
} catch (error) {
  if (page) {
    const captures = await Promise.allSettled([
      page.screenshot({ path: ".cache/ux-qa/ci-failure.png", fullPage: true }),
      page.content().then((html) => writeFile(new URL("../.cache/ux-qa/ci-failure.html", import.meta.url), html, "utf8")),
    ]);
    for (const capture of captures) {
      if (capture.status === "rejected") console.error(`Could not capture browser failure artifact: ${capture.reason}`);
    }
  }
  throw error;
} finally {
  await browser.close();
}

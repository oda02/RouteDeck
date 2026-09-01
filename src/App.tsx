import { useState } from "react";

type Mode = "proxy" | "tun";

export default function App() {
  const [mode, setMode] = useState<Mode>("proxy");

  return (
    <main className="shell">
      <header className="header">
        <div>
          <p className="eyebrow">RouteDeck</p>
          <h1>Маршруты без догадок</h1>
        </div>
        <span className="status">Не подключено</span>
      </header>

      <section className="mode-card" aria-labelledby="mode-title">
        <div>
          <p id="mode-title" className="label">Режим</p>
          <p className="hint">
            {mode === "proxy"
              ? "Для программ, использующих системный прокси"
              : "Для всего трафика и правил по приложениям · потребуется UAC"}
          </p>
        </div>
        <div className="segmented" role="group" aria-label="Режим подключения">
          <button className={mode === "proxy" ? "selected" : ""} onClick={() => setMode("proxy")}>System Proxy</button>
          <button className={mode === "tun" ? "selected" : ""} onClick={() => setMode("tun")}>TUN</button>
        </div>
      </section>

      <section className="server-card" aria-label="Выбранный сервер">
        <div>
          <p className="label">Сервер</p>
          <strong>Добавьте подписку</strong>
          <p className="hint">VLESS · Hysteria2 · Naive</p>
        </div>
        <button className="secondary">Импортировать</button>
      </section>

      <section className="route-card">
        <div>
          <p className="label">Маршрут по умолчанию</p>
          <strong>Напрямую</strong>
          <p className="hint">Через VPN пойдут только выбранные приложения</p>
        </div>
        <button className="text-button">Настроить</button>
      </section>

      <button className="connect" disabled>
        Подключить
        <span>Сначала импортируйте подписку</span>
      </button>

      <footer>
        <span>Без изменений в системе</span>
        <button className="text-button">Настройки</button>
      </footer>
    </main>
  );
}

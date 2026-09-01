import {
  useCallback,
  useEffect,
  useId,
  useMemo,
  useRef,
  useState,
  useSyncExternalStore,
  type ReactNode,
} from "react";
import { controller } from "./controller";
import {
  ActivityIcon,
  CheckIcon,
  ChevronRightIcon,
  CopyIcon,
  EyeIcon,
  HomeIcon,
  IdleIcon,
  ImportIcon,
  InfoIcon,
  LoaderIcon,
  PlusIcon,
  RefreshIcon,
  RoutingIcon,
  SearchIcon,
  ServersIcon,
  SettingsIcon,
  ShieldIcon,
  TrashIcon,
  WarningIcon,
  XCircleIcon,
  XIcon,
} from "./icons";
import {
  RouteDeckError,
  destinations,
  type AppNotice,
  type AppRouteChoice,
  type ConnectionMode,
  type ConnectionPhase,
  type ConnectionProof,
  type ControllerSnapshot,
  type Destination,
  type RoutingConfig,
  type SettingsConfig,
  type SubscriptionImportSource,
  type SubscriptionPreview,
  type TunPathChoice,
} from "./model";

type DialogKind = "import" | "tun-preflight" | "mode-change" | "reset" | null;
type ToastKind = "success" | "info" | "warning";
type ToastState = { message: string; kind: ToastKind };
type PublicActionError = { message: string; redactedDetail?: string };
type ActionFailure = { page: Destination; notice: AppNotice; retry?: () => void };
type AsyncActionOptions<T> = {
  page: Destination;
  title: string;
  action: () => Promise<T>;
  setBusy?: (busy: boolean) => void;
  onSuccess?: (value: T) => void;
  onError?: (error: PublicActionError) => void;
  errorPresentation?: "persistent" | "inline";
  retry?: () => void;
};
type RunAsyncAction = <T>(options: AsyncActionOptions<T>) => Promise<T | undefined>;

const navigation = [
  { id: "home", label: "Главная", icon: HomeIcon },
  { id: "servers", label: "Серверы", icon: ServersIcon },
  { id: "routing", label: "Правила", icon: RoutingIcon },
  { id: "settings", label: "Настройки", icon: SettingsIcon },
  { id: "diagnostics", label: "Статус", icon: ActivityIcon },
] satisfies Array<{ id: Destination; label: string; icon: typeof HomeIcon }>;

const phaseLabels: Record<ConnectionPhase, string> = {
  disconnected: "Отключено",
  "validating-config": "Проверка конфигурации",
  "starting-core": "Запуск ядра",
  "checking-local-ingress": "Проверка прокси",
  "applying-windows-mode": "Применение режима",
  "verifying-outbound": "Проверка маршрута",
  connected: "Подключено",
  degraded: "Требует внимания",
  disconnecting: "Отключение",
  "blocked-by-conflict": "Прокси не применён",
  failed: "Ошибка подключения",
};

const pendingPhases: ConnectionPhase[] = [
  "validating-config",
  "starting-core",
  "checking-local-ingress",
  "applying-windows-mode",
  "verifying-outbound",
  "disconnecting",
];

const proofStateLabels = {
  idle: "Не проверялось",
  running: "Проверка",
  pass: "Готово",
  warn: "Требует внимания",
  fail: "Ошибка",
  skipped: "Недоступно",
} as const;

function toPublicActionError(error: unknown): PublicActionError {
  if (error instanceof RouteDeckError) {
    switch (error.code) {
      case "backend-unavailable":
        return { message: "Backend RouteDeck недоступен. Действие безопасно заблокировано." };
      case "invalid-subscription-url":
        return { message: "Проверьте формат URL подписки." };
      case "insecure-subscription-url":
        return { message: "Для подписки требуется защищённый HTTPS URL." };
      case "empty-subscription-source":
        return { message: "Источник подписки пуст." };
      case "stale-subscription-preview":
        return { message: "Предпросмотр устарел. Проверьте источник ещё раз." };
    }
  }
  if (error instanceof DOMException && error.name === "NotAllowedError") {
    return { message: "Windows не разрешила доступ к буферу обмена. Проверьте разрешение и повторите действие." };
  }
  return {
    message: "Действие не выполнено. Технические сведения скрыты, чтобы не показать секреты.",
    redactedDetail: "Откройте безопасный диагностический отчёт или повторите действие.",
  };
}

function useController() {
  return useSyncExternalStore(controller.subscribe, controller.getSnapshot, controller.getSnapshot);
}

function ProofStateIcon({ proof }: { proof: ConnectionProof }) {
  if (proof.state === "running") return <LoaderIcon size={18} />;
  if (proof.state === "pass") return <CheckIcon size={18} />;
  if (proof.state === "warn") return <WarningIcon size={18} />;
  if (proof.state === "fail") return <XCircleIcon size={18} />;
  return <IdleIcon size={18} />;
}

function StatusBadge({ phase }: { phase: ConnectionPhase }) {
  const kind = phase === "connected" ? "success" : phase === "degraded" || phase === "blocked-by-conflict" ? "warning" : phase === "failed" ? "danger" : "neutral";
  return (
    <span className="status-badge" data-kind={kind} aria-live="polite">
      {phase === "connected" ? <CheckIcon size={15} /> : pendingPhases.includes(phase) ? <LoaderIcon size={15} /> : <ShieldIcon size={15} />}
      <span>{phaseLabels[phase]}</span>
    </span>
  );
}

function Navigation({ active, onNavigate, variant }: { active: Destination; onNavigate: (destination: Destination) => void; variant: "rail" | "bottom" }) {
  return (
    <nav className={`navigation navigation-${variant}`} aria-label="Основная навигация">
      {navigation.map((item, index) => {
        const Icon = item.icon;
        const selected = item.id === active;
        return (
          <button
            key={item.id}
            className="navigation-item"
            type="button"
            aria-current={selected ? "page" : undefined}
            aria-label={`${item.label}, Alt+${index + 1}`}
            title={`${item.label} · Alt+${index + 1}`}
            onClick={() => onNavigate(item.id)}
          >
            <Icon size={20} />
            <span>{item.label}</span>
          </button>
        );
      })}
    </nav>
  );
}

function OpaqueNotice({ notice, onClose, primaryAction, secondaryAction }: {
  notice: AppNotice;
  onClose?: () => void;
  primaryAction?: { label: string; onClick: () => void };
  secondaryAction?: { label: string; onClick: () => void };
}) {
  const [detailsOpen, setDetailsOpen] = useState(false);
  const Icon = notice.kind === "error" ? XCircleIcon : notice.kind === "warning" ? WarningIcon : notice.kind === "success" ? CheckIcon : InfoIcon;
  const role = notice.kind === "error" ? "alert" : "status";
  return (
    <section className="notice" data-kind={notice.kind} role={role}>
      <div className="notice-icon"><Icon size={20} /></div>
      <div className="notice-content">
        <div className="notice-heading-row">
          <h2>{notice.title}</h2>
          {onClose ? (
            <button className="icon-button notice-close" type="button" aria-label="Закрыть сообщение" title="Закрыть" onClick={onClose}>
              <XIcon size={18} />
            </button>
          ) : null}
        </div>
        <p>{notice.body}</p>
        {notice.redactedDetail ? (
          <>
            <button className="text-action" type="button" aria-expanded={detailsOpen} onClick={() => setDetailsOpen((open) => !open)}>
              {detailsOpen ? "Скрыть подробности" : "Показать подробности"}
            </button>
            {detailsOpen ? <p className="notice-detail">{notice.redactedDetail}</p> : null}
          </>
        ) : null}
        {primaryAction || secondaryAction ? (
          <div className="notice-actions">
            {primaryAction ? <button className="secondary-button" type="button" onClick={primaryAction.onClick}>{primaryAction.label}</button> : null}
            {secondaryAction ? <button className="text-button" type="button" onClick={secondaryAction.onClick}>{secondaryAction.label}</button> : null}
          </div>
        ) : null}
      </div>
    </section>
  );
}

function ActionFailureNotice({ failure, page, onClear }: { failure: ActionFailure | null; page: Destination; onClear: () => void }) {
  if (!failure || failure.page !== page) return null;
  return (
    <OpaqueNotice
      notice={failure.notice}
      onClose={onClear}
      primaryAction={failure.retry ? { label: "Повторить", onClick: failure.retry } : undefined}
    />
  );
}

function ProofCard({ proofs, title = "Проверка подключения", historical = false }: { proofs: ConnectionProof[]; title?: string; historical?: boolean }) {
  return (
    <section className="card proof-card" aria-labelledby="proof-card-title">
      <div className="section-heading">
        <div>
          <p className="overline">Контроль состояния</p>
          <h2 id="proof-card-title">{title}</h2>
        </div>
        {historical ? <span className="quiet-badge">Последние данные</span> : null}
      </div>
      <div className="proof-list" aria-live="polite">
        {proofs.map((proof) => (
          <div className="proof-row" data-state={proof.state} key={proof.id}>
            <span className="proof-icon"><ProofStateIcon proof={proof} /></span>
            <span className="proof-copy">
              <span className="proof-label">{proof.label}</span>
              <span className="proof-summary">{proof.summary}</span>
            </span>
            <span className="proof-value">
              {proof.value ? <strong>{proof.value}</strong> : null}
              <span>{proofStateLabels[proof.state]}{proof.durationMs ? ` · ${proof.durationMs} мс` : ""}</span>
            </span>
          </div>
        ))}
      </div>
    </section>
  );
}

function SegmentedControl<T extends string>({ label, value, options, onChange, disabled = false }: {
  label: string;
  value: T;
  options: Array<{ value: T; label: string; disabled?: boolean }>;
  onChange: (value: T) => void;
  disabled?: boolean;
}) {
  const groupName = useId();
  return (
    <fieldset className="segmented-control" aria-label={label} data-count={options.length}>
      <legend className="sr-only">{label}</legend>
      {options.map((option) => (
        <label key={option.value} data-selected={value === option.value} data-disabled={disabled || option.disabled || undefined}>
          <input
            className="control-input"
            type="radio"
            name={groupName}
            value={option.value}
            checked={value === option.value}
            disabled={disabled || option.disabled}
            onChange={() => onChange(option.value)}
          />
          <span>{option.label}</span>
        </label>
      ))}
    </fieldset>
  );
}

function HomePage({ snapshot, headingRef, onNavigate, onModeChange, onConnect, onDisconnect, onRetry, actionFailure, onClearFailure }: {
  snapshot: ControllerSnapshot;
  headingRef: React.RefObject<HTMLHeadingElement | null>;
  onNavigate: (destination: Destination) => void;
  onModeChange: (mode: ConnectionMode) => void;
  onConnect: () => void;
  onDisconnect: () => void;
  onRetry: () => void;
  actionFailure: ActionFailure | null;
  onClearFailure: () => void;
}) {
  const server = snapshot.servers.find((item) => item.id === snapshot.selectedServerId);
  const pending = pendingPhases.includes(snapshot.phase);
  const hasLiveCore = ["connected", "degraded", "blocked-by-conflict"].includes(snapshot.phase);
  const buttonLabel = pending
    ? phaseLabels[snapshot.phase]
    : hasLiveCore
      ? snapshot.phase === "blocked-by-conflict" ? "Остановить локальный прокси" : "Отключить"
      : snapshot.phase === "failed" ? "Повторить" : "Подключить";
  const visibleProofs = snapshot.proofs.filter((proof) => proof.id !== "config");
  const vpnApps = snapshot.routing.apps.filter((app) => app.route === "vpn");
  const directApps = snapshot.routing.apps.filter((app) => app.route === "direct");
  const routeSummary = snapshot.routing.defaultRoute === "direct"
    ? `По умолчанию напрямую · ${vpnApps.length} ${vpnApps.length === 1 ? "приложение" : "приложения"} через VPN`
    : `По умолчанию через VPN · ${directApps.length} исключений напрямую`;

  return (
    <div className="page home-page">
      <div className="page-title-row">
        <div>
          <p className="overline">Управление соединением</p>
          <h1 ref={headingRef} tabIndex={-1}>Главная</h1>
        </div>
        <span className="mode-readout">{snapshot.mode === "proxy" ? "System Proxy" : "TUN"}</span>
      </div>

      <ActionFailureNotice failure={actionFailure} page="home" onClear={onClearFailure} />

      <button className="selection-card" type="button" onClick={() => onNavigate("servers")}>
        <span className="selection-leading"><ServersIcon size={20} /></span>
        <span className="selection-copy">
          <span className="selection-label">Выбранный сервер</span>
          <strong>{server ? `${server.country} · ${server.name}` : "Сервер не выбран"}</strong>
          <span>{server ? `${server.protocol} · ${server.detail}` : "Импортируйте подписку"}</span>
        </span>
        <ChevronRightIcon size={20} />
      </button>

      <section className="card mode-card" aria-labelledby="connection-mode-title">
        <div className="section-heading compact-heading">
          <div>
            <p className="overline">Перехват трафика</p>
            <h2 id="connection-mode-title">Режим</h2>
          </div>
        </div>
        <SegmentedControl
          label="Режим подключения"
          value={snapshot.mode}
          options={[{ value: "proxy", label: "Системный прокси" }, { value: "tun", label: "TUN" }]}
          onChange={onModeChange}
          disabled={pending}
        />
        <div className="persistent-hint" data-kind={snapshot.mode === "tun" ? "warning" : "info"}>
          {snapshot.mode === "proxy" ? <InfoIcon size={18} /> : <ShieldIcon size={18} />}
          <p>
            {snapshot.mode === "proxy"
              ? "Работает только в приложениях, которые используют прокси Windows. Для надёжных правил по приложениям выберите TUN."
              : "Перехватывает системный трафик, может запросить UAC и проверит маршрут перед зелёным статусом."}
          </p>
        </div>
      </section>

      <button
        className={`primary-button connection-button${hasLiveCore ? " disconnect-button" : ""}`}
        type="button"
        disabled={pending || !server}
        aria-busy={pending}
        onClick={hasLiveCore ? onDisconnect : onConnect}
      >
        {pending ? <LoaderIcon size={20} /> : hasLiveCore ? <XCircleIcon size={20} /> : <ShieldIcon size={20} />}
        <span>{buttonLabel}</span>
      </button>

      {snapshot.notice ? (
        <OpaqueNotice
          notice={snapshot.notice}
          onClose={snapshot.notice.id === "backend-unavailable" ? undefined : controller.dismissNotice}
          primaryAction={snapshot.notice.id === "backend-unavailable" ? undefined : { label: "Повторить проверку", onClick: onRetry }}
          secondaryAction={{ label: "Открыть диагностику", onClick: () => onNavigate("diagnostics") }}
        />
      ) : null}

      <ProofCard proofs={visibleProofs} historical={snapshot.phase === "disconnected"} />

      <button className="summary-card" type="button" onClick={() => onNavigate("routing")}>
        <span className="summary-icon"><RoutingIcon size={20} /></span>
        <span className="selection-copy">
          <span className="selection-label">Маршрутизация</span>
          <strong>{routeSummary}</strong>
          <span>{snapshot.mode === "tun" ? "Правила применяются через TUN" : "В System Proxy правила best effort"}</span>
        </span>
        <ChevronRightIcon size={20} />
      </button>
    </div>
  );
}

function ServersPage({ snapshot, headingRef, search, onSearch, onImport, onToast, runAsyncAction, actionFailure, onClearFailure }: {
  snapshot: ControllerSnapshot;
  headingRef: React.RefObject<HTMLHeadingElement | null>;
  search: string;
  onSearch: (value: string) => void;
  onImport: () => void;
  onToast: (message: string, kind?: ToastKind) => void;
  runAsyncAction: RunAsyncAction;
  actionFailure: ActionFailure | null;
  onClearFailure: () => void;
}) {
  const [refreshing, setRefreshing] = useState(false);
  const filtered = useMemo(() => {
    const query = search.trim().toLocaleLowerCase("ru-RU");
    return snapshot.servers.filter((server) => !query || `${server.country} ${server.name} ${server.protocol}`.toLocaleLowerCase("ru-RU").includes(query));
  }, [search, snapshot.servers]);

  const refresh = () => {
    if (refreshing) return;
    void runAsyncAction({
      page: "servers",
      title: "Не удалось проверить задержки серверов",
      setBusy: setRefreshing,
      action: controller.refreshServers,
      retry: refresh,
      onSuccess: () => onToast("Задержки серверов обновлены", "success"),
    });
  };

  return (
    <div className="page">
      <div className="page-title-row">
        <div><p className="overline">Узлы подписки</p><h1 ref={headingRef} tabIndex={-1}>Серверы</h1></div>
        <span className="count-badge">{snapshot.servers.length}</span>
      </div>
      <ActionFailureNotice failure={actionFailure} page="servers" onClear={onClearFailure} />
      <button className="primary-button" type="button" onClick={onImport}><ImportIcon size={20} />Импортировать подписку</button>
      <div className="toolbar">
        <label className="search-field">
          <span className="sr-only">Поиск серверов</span>
          <SearchIcon size={18} />
          <input value={search} type="search" placeholder="Поиск по имени или протоколу" onChange={(event) => onSearch(event.target.value)} />
        </label>
        <button className="icon-button bordered" type="button" aria-label="Проверить задержки" title="Проверить задержки" disabled={refreshing} onClick={refresh}>
          {refreshing ? <LoaderIcon size={19} /> : <RefreshIcon size={19} />}
        </button>
      </div>
      <div className="subscription-meta">
        <span><strong>{snapshot.subscriptionName}</strong> · обновлено {snapshot.subscriptionUpdatedAt}</span>
        <span>VLESS · Hysteria2 · Naive</span>
      </div>
      <div className="server-list" role="radiogroup" aria-label="Выбор сервера">
        {filtered.length ? filtered.map((server) => {
          const selected = server.id === snapshot.selectedServerId;
          const latency = server.latencyState === "pending" ? "Проверка…" : server.latencyState === "timeout" ? "Тайм-аут" : server.latencyState === "unavailable" ? "—" : `${server.latencyMs} мс`;
          return (
            <label
              className="server-row"
              data-selected={selected}
              key={server.id}
            >
              <input className="control-input" type="radio" name="selected-server" value={server.id} checked={selected} onChange={() => controller.selectServer(server.id)} />
              <span className="radio-indicator" aria-hidden="true"><span /></span>
              <span className="country-code">{server.country}</span>
              <span className="server-copy">
                <strong>{server.name}</strong>
                <span>{server.protocol} · {server.detail} · {server.source}</span>
              </span>
              <span className="latency" data-state={server.latencyState}>
                <strong>{latency}</strong>
                <span>{server.checkedAt ? `проверено ${server.checkedAt}` : "ещё не проверено"}</span>
              </span>
            </label>
          );
        }) : <div className="empty-state"><SearchIcon size={24} /><strong>Ничего не найдено</strong><span>Измените запрос или обновите подписку.</span></div>}
      </div>
    </div>
  );
}

function RoutingPage({ snapshot, headingRef, draft, onDraftChange, onApply, onToast, runAsyncAction, actionFailure, onClearFailure }: {
  snapshot: ControllerSnapshot;
  headingRef: React.RefObject<HTMLHeadingElement | null>;
  draft: RoutingConfig;
  onDraftChange: (routing: RoutingConfig) => void;
  onApply: () => Promise<void>;
  onToast: (message: string, kind?: ToastKind) => void;
  runAsyncAction: RunAsyncAction;
  actionFailure: ActionFailure | null;
  onClearFailure: () => void;
}) {
  const [applying, setApplying] = useState(false);
  const dirty = JSON.stringify(draft) !== JSON.stringify(snapshot.routing);
  const summary = draft.defaultRoute === "direct"
    ? `Весь остальной трафик напрямую · ${draft.apps.filter((app) => app.route === "vpn").length} правила через VPN`
    : `Весь остальной трафик через VPN · ${draft.apps.filter((app) => app.route === "direct").length} исключений напрямую`;

  const updateApp = (id: string, route: AppRouteChoice) => onDraftChange({
    ...draft,
    apps: draft.apps.map((app) => app.id === id ? { ...app, route } : app),
  });

  const apply = () => {
    if (!dirty || applying) return;
    void runAsyncAction({
      page: "routing",
      title: "Не удалось применить маршрутизацию",
      setBusy: setApplying,
      action: onApply,
      retry: apply,
      onSuccess: () => onToast("Правила маршрутизации применены", "success"),
    });
  };

  return (
    <div className="page">
      <div className="page-title-row">
        <div><p className="overline">Политика трафика</p><h1 ref={headingRef} tabIndex={-1}>Маршрутизация</h1></div>
        {dirty ? <span className="quiet-badge warning-badge">Не сохранено</span> : <span className="quiet-badge">Применено</span>}
      </div>
      <ActionFailureNotice failure={actionFailure} page="routing" onClear={onClearFailure} />
      <section className="card">
        <div className="section-heading compact-heading"><div><p className="overline">Базовое правило</p><h2>Маршрут по умолчанию</h2></div></div>
        <SegmentedControl
          label="Маршрут по умолчанию"
          value={draft.defaultRoute}
          options={[{ value: "direct", label: "Напрямую" }, { value: "vpn", label: "Через VPN" }]}
          onChange={(defaultRoute) => onDraftChange({ ...draft, defaultRoute })}
        />
        <p className="effective-summary"><RoutingIcon size={18} />{summary}</p>
      </section>

      {snapshot.mode === "proxy" ? (
        <OpaqueNotice notice={{ id: "proxy-routing-limit", kind: "info", title: "Правила в System Proxy работают best effort", body: "Они применяются к трафику proxy-aware приложений, который вошёл в локальный прокси. Для надёжного перехвата по приложениям нужен TUN." }} />
      ) : null}

      <section className="card app-rules-card">
        <div className="section-heading">
          <div><p className="overline">Исключения</p><h2>Приложения</h2></div>
          <button className="secondary-button compact-button" type="button" disabled title="Выбор приложения появится с Tauri dialog adapter"><PlusIcon size={18} />Добавить · скоро</button>
        </div>
        <div className="app-rule-list">
          {draft.apps.map((app) => (
            <div className="app-rule" key={app.id}>
              <div className="app-rule-heading">
                <span className="app-monogram" aria-hidden="true">{app.name.slice(0, 1).toUpperCase()}</span>
                <span className="app-copy"><strong>{app.name}</strong><span title={app.path}>{app.path}</span></span>
                <button className="icon-button" type="button" aria-label={`Удалить правило ${app.name}`} title="Удалить правило" onClick={() => onDraftChange({ ...draft, apps: draft.apps.filter((item) => item.id !== app.id) })}><TrashIcon size={18} /></button>
              </div>
              <SegmentedControl
                label={`Маршрут для ${app.name}`}
                value={app.route}
                options={[{ value: "inherit", label: "Наследовать" }, { value: "direct", label: "Напрямую" }, { value: "vpn", label: "VPN" }]}
                onChange={(route) => updateApp(app.id, route)}
              />
              <p className="rule-effective">
                {snapshot.mode === "proxy"
                  ? "Best effort в proxy-aware приложениях · гарантия требует TUN"
                  : app.route === "inherit" ? `Эффективно: ${draft.defaultRoute === "direct" ? "напрямую" : "VPN"}` : `Эффективно: ${app.route === "direct" ? "напрямую" : "VPN"}`}
              </p>
            </div>
          ))}
        </div>
      </section>
      <button className="primary-button" type="button" disabled={!dirty || applying} aria-busy={applying} onClick={apply}>
        {applying ? <LoaderIcon size={20} /> : <CheckIcon size={20} />}{applying ? "Применяем…" : "Применить изменения"}
      </button>
    </div>
  );
}

function SettingsPage({ headingRef, snapshot, draft, onDraftChange, onSave, onReset, onToast, runAsyncAction, actionFailure, onClearFailure }: {
  headingRef: React.RefObject<HTMLHeadingElement | null>;
  snapshot: ControllerSnapshot;
  draft: SettingsConfig;
  onDraftChange: (settings: SettingsConfig) => void;
  onSave: () => Promise<void>;
  onReset: () => void;
  onToast: (message: string, kind?: ToastKind) => void;
  runAsyncAction: RunAsyncAction;
  actionFailure: ActionFailure | null;
  onClearFailure: () => void;
}) {
  const [saving, setSaving] = useState(false);
  const dirty = JSON.stringify(draft) !== JSON.stringify(snapshot.settings);
  const portsValid = draft.httpPort >= 1024 && draft.httpPort <= 65535 && draft.socksPort >= 1024 && draft.socksPort <= 65535 && draft.httpPort !== draft.socksPort;
  const save = () => {
    if (!dirty || !portsValid || saving) return;
    void runAsyncAction({
      page: "settings",
      title: "Не удалось сохранить настройки",
      setBusy: setSaving,
      action: onSave,
      retry: save,
      onSuccess: () => onToast("Настройки сохранены", "success"),
    });
  };
  return (
    <div className="page">
      <div className="page-title-row">
        <div><p className="overline">Поведение приложения</p><h1 ref={headingRef} tabIndex={-1}>Настройки</h1></div>
        {dirty ? <span className="quiet-badge warning-badge">Изменено</span> : null}
      </div>
      <ActionFailureNotice failure={actionFailure} page="settings" onClear={onClearFailure} />

      <section className="card settings-group">
        <div className="section-heading compact-heading"><div><p className="overline">Интерфейс</p><h2>Общие</h2></div></div>
        <label className="check-row"><input type="checkbox" checked={draft.startMinimized} onChange={(event) => onDraftChange({ ...draft, startMinimized: event.target.checked })} /><span><strong>Запускать свёрнутым</strong><small>Показывать RouteDeck только в трее после старта</small></span></label>
        <label className="field-row"><span><strong>При закрытии окна</strong><small>Действие системной кнопки закрытия</small></span><select value={draft.closeBehavior} onChange={(event) => onDraftChange({ ...draft, closeBehavior: event.target.value as SettingsConfig["closeBehavior"] })}><option value="tray">Скрыть в трей</option><option value="exit">Завершить работу</option></select></label>
        <label className="field-row"><span><strong>Тема</strong><small>Dark-first, без внешних шрифтов</small></span><select value={draft.theme} onChange={(event) => onDraftChange({ ...draft, theme: event.target.value as SettingsConfig["theme"] })}><option value="dark">Тёмная</option><option value="light">Светлая</option><option value="system">Как в Windows</option></select></label>
      </section>

      <section className="card settings-group">
        <div className="section-heading compact-heading"><div><p className="overline">Локальные endpoints</p><h2>Подключение</h2></div></div>
        <label className="number-field"><span>HTTP-порт</span><input type="number" min="1024" max="65535" value={draft.httpPort} aria-describedby="port-help" onChange={(event) => onDraftChange({ ...draft, httpPort: Number(event.target.value) })} /></label>
        <label className="number-field"><span>SOCKS-порт</span><input type="number" min="1024" max="65535" value={draft.socksPort} aria-describedby="port-help" onChange={(event) => onDraftChange({ ...draft, socksPort: Number(event.target.value) })} /></label>
        <p id="port-help" className={`field-help${portsValid ? "" : " field-error"}`}>{portsValid ? "Допустимо: 1024–65535. Порты должны отличаться." : "Укажите разные свободные порты от 1024 до 65535."}</p>
      </section>

      <section className="card settings-group">
        <div className="section-heading compact-heading"><div><p className="overline">Владение Windows</p><h2>Совместимость с другими VPN</h2></div></div>
        <label className="radio-setting"><input type="radio" name="proxy-policy" value="never-overwrite" checked={draft.proxyConflictPolicy === "never-overwrite"} onChange={() => onDraftChange({ ...draft, proxyConflictPolicy: "never-overwrite" })} /><span><strong>Никогда не перезаписывать чужой прокси</strong><small>Безопасный вариант: сохранить состояние и показать конфликт</small></span></label>
        <label className="radio-setting"><input type="radio" name="proxy-policy" value="ask" checked={draft.proxyConflictPolicy === "ask"} onChange={() => onDraftChange({ ...draft, proxyConflictPolicy: "ask" })} /><span><strong>Всегда спрашивать</strong><small>Показывать точные текущие и ожидаемые endpoints</small></span></label>
        <div className="persistent-hint" data-kind="info"><InfoIcon size={18} /><p>Windows использует один эффективный системный прокси. Разные локальные порты не создают двух владельцев.</p></div>
      </section>

      <details className="card advanced-settings"><summary>Расширенные настройки</summary><div className="details-body"><p>Строгая маршрутизация TUN уменьшает утечки DNS, но может конфликтовать с виртуальными адаптерами. Диагностика покажет конкретную причину до UAC.</p><p>Сервис, драйвер и задача автозапуска в первой версии не устанавливаются.</p></div></details>

      <button className="primary-button" type="button" disabled={!dirty || !portsValid || saving} aria-busy={saving} onClick={save}>{saving ? <LoaderIcon size={20} /> : <CheckIcon size={20} />}{saving ? "Сохраняем…" : "Сохранить изменения"}</button>

      <section className="danger-zone" aria-labelledby="danger-title"><div><h2 id="danger-title">Опасная зона</h2><p>Сбрасывает только локальные настройки и черновики RouteDeck. Чужой VPN и настройки Windows не изменяются.</p></div><button className="danger-button" type="button" onClick={onReset}>Сбросить локальное состояние…</button></section>
    </div>
  );
}

function DiagnosticsPage({ snapshot, headingRef, onToast, runAsyncAction, actionFailure, onClearFailure }: {
  snapshot: ControllerSnapshot;
  headingRef: React.RefObject<HTMLHeadingElement | null>;
  onToast: (message: string, kind?: ToastKind) => void;
  runAsyncAction: RunAsyncAction;
  actionFailure: ActionFailure | null;
  onClearFailure: () => void;
}) {
  const [checking, setChecking] = useState(false);
  const [copying, setCopying] = useState(false);
  const run = () => {
    void runAsyncAction({
      page: "diagnostics",
      title: "Не удалось запустить диагностику",
      setBusy: setChecking,
      action: controller.runDiagnostics,
      retry: run,
    });
  };
  const copyReport = () => {
    void runAsyncAction({
      page: "diagnostics",
      title: "Не удалось скопировать безопасный отчёт",
      setBusy: setCopying,
      action: () => navigator.clipboard.writeText(controller.getSanitizedReport()),
      retry: copyReport,
      onSuccess: () => onToast("Безопасный отчёт скопирован", "success"),
    });
  };
  const externalNotice: AppNotice = {
    id: "external-vpn",
    kind: "warning",
    title: "Обнаружен другой VPN",
    body: `${snapshot.environment.otherVpnName ?? "Другой клиент"} использует системный прокси ${snapshot.environment.externalProxyEndpoint ?? "Windows"}. RouteDeck не изменяет его без явного выбора.`,
    redactedDetail: "Локальные proxy listeners могут работать на разных портах, но эффективный системный прокси Windows только один.",
  };
  return (
    <div className="page">
      <div className="page-title-row"><div><p className="overline">Проверка без догадок</p><h1 ref={headingRef} tabIndex={-1}>Диагностика</h1></div>{snapshot.diagnostics.lastRunAt ? <span className="quiet-badge">{snapshot.diagnostics.lastRunAt}</span> : null}</div>
      <ActionFailureNotice failure={actionFailure} page="diagnostics" onClear={onClearFailure} />
      <button className="primary-button" type="button" disabled={checking || snapshot.diagnostics.running} aria-busy={checking || snapshot.diagnostics.running} onClick={run}>{checking || snapshot.diagnostics.running ? <LoaderIcon size={20} /> : <ActivityIcon size={20} />}{checking || snapshot.diagnostics.running ? "Проверяем все этапы…" : "Запустить полную проверку"}</button>
      {snapshot.environment.otherVpnDetected ? <OpaqueNotice notice={externalNotice} primaryAction={{ label: "Повторить после изменения", onClick: run }} /> : null}
      <ProofCard proofs={snapshot.diagnostics.steps} title="Цепочка доказательств" historical={!snapshot.diagnostics.lastRunAt} />
      {snapshot.diagnostics.lastRunAt ? <p className="diagnostic-duration">Полная проверка: {snapshot.diagnostics.durationMs} мс · {snapshot.diagnostics.lastRunAt}</p> : null}
      <button className="secondary-button full-width" type="button" disabled={copying} aria-busy={copying} onClick={copyReport}>{copying ? <LoaderIcon size={19} /> : <CopyIcon size={19} />}{copying ? "Копируем…" : "Копировать безопасный отчёт"}</button>
      <details className="card log-viewer"><summary>Технический журнал</summary><div className="details-body"><p className="field-help">Секреты и адрес подписки удаляются до отображения и копирования.</p><pre>{snapshot.diagnostics.sanitizedLog.join("\n")}</pre></div></details>
    </div>
  );
}

function Dialog({ title, description, focusKey, onClose, children, actions }: { title: string; description?: string; focusKey?: string; onClose: () => void; children: ReactNode; actions: ReactNode }) {
  const dialogRef = useRef<HTMLDivElement>(null);
  useEffect(() => {
    const previouslyFocused = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    const dialog = dialogRef.current;
    const focusable = dialog?.querySelector<HTMLElement>("[data-autofocus]")
      ?? dialog?.querySelector<HTMLElement>("button:not(:disabled), input:not(:disabled), select:not(:disabled), textarea:not(:disabled)");
    window.requestAnimationFrame(() => focusable?.focus());
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        event.preventDefault();
        onClose();
        return;
      }
      if (event.key !== "Tab" || !dialog) return;
      const items = Array.from(dialog.querySelectorAll<HTMLElement>("button:not(:disabled), input:not(:disabled), select:not(:disabled), textarea:not(:disabled), [tabindex]:not([tabindex='-1'])"));
      const first = items[0];
      const last = items[items.length - 1];
      if (!first || !last) return;
      if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last.focus(); }
      if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first.focus(); }
    };
    document.addEventListener("keydown", onKeyDown);
    return () => {
      document.removeEventListener("keydown", onKeyDown);
      previouslyFocused?.focus({ preventScroll: true });
    };
  }, [focusKey, onClose]);

  return (
    <div className="dialog-scrim" role="presentation">
      <div className="dialog" ref={dialogRef} role="dialog" aria-modal="true" aria-labelledby="dialog-title" aria-describedby={description ? "dialog-description" : undefined}>
        <div className="dialog-header"><div><h2 id="dialog-title">{title}</h2>{description ? <p id="dialog-description">{description}</p> : null}</div><button className="icon-button" type="button" aria-label="Закрыть окно" title="Закрыть" onClick={onClose}><XIcon size={19} /></button></div>
        <div className="dialog-content">{children}</div>
        <div className="dialog-actions">{actions}</div>
      </div>
    </div>
  );
}

function Toast({ toast, onClose, onPausedChange }: { toast: ToastState; onClose: () => void; onPausedChange: (paused: boolean) => void }) {
  const [hovered, setHovered] = useState(false);
  const [focusWithin, setFocusWithin] = useState(false);
  const Icon = toast.kind === "warning" ? WarningIcon : toast.kind === "info" ? InfoIcon : CheckIcon;
  useEffect(() => onPausedChange(hovered || focusWithin), [focusWithin, hovered, onPausedChange]);
  useEffect(() => () => onPausedChange(false), [onPausedChange]);
  return (
    <div
      className="toast"
      data-kind={toast.kind}
      role="status"
      aria-live="polite"
      aria-atomic="true"
      onMouseEnter={() => setHovered(true)}
      onMouseLeave={() => setHovered(false)}
      onFocus={() => setFocusWithin(true)}
      onBlur={(event) => setFocusWithin(event.currentTarget.contains(event.relatedTarget as Node | null))}
    >
      <Icon size={19} /><span>{toast.message}</span><button className="icon-button" type="button" aria-label="Закрыть уведомление" title="Закрыть" onClick={onClose}><XIcon size={17} /></button>
    </div>
  );
}

export default function App() {
  const snapshot = useController();
  const [activePage, setActivePage] = useState<Destination>("home");
  const [dialog, setDialog] = useState<DialogKind>(null);
  const [pendingMode, setPendingMode] = useState<ConnectionMode | null>(null);
  const [tunChoice, setTunChoice] = useState<"" | "nested" | "physical">("");
  const [adapterId, setAdapterId] = useState(snapshot.environment.physicalAdapters[0]?.id ?? "");
  const [search, setSearch] = useState("");
  const [routingDraft, setRoutingDraft] = useState<RoutingConfig>(snapshot.routing);
  const [settingsDraft, setSettingsDraft] = useState<SettingsConfig>(snapshot.settings);
  const [toast, setToast] = useState<ToastState | null>(null);
  const [toastPaused, setToastPaused] = useState(false);
  const [actionFailure, setActionFailure] = useState<ActionFailure | null>(null);
  const [importMethod, setImportMethod] = useState<"url" | "clipboard" | "file">("url");
  const [subscriptionSource, setSubscriptionSource] = useState("");
  const [subscriptionVisible, setSubscriptionVisible] = useState(false);
  const [importError, setImportError] = useState("");
  const [importing, setImporting] = useState(false);
  const [subscriptionPreview, setSubscriptionPreview] = useState<SubscriptionPreview | null>(null);
  const mainRef = useRef<HTMLElement>(null);
  const headingRef = useRef<HTMLHeadingElement>(null);
  const subscriptionInputRef = useRef<HTMLInputElement>(null);
  const clipboardButtonRef = useRef<HTMLButtonElement>(null);
  const scrollPositions = useRef<Record<Destination, number>>({ home: 0, servers: 0, routing: 0, settings: 0, diagnostics: 0 });

  const closeDialog = useCallback(() => {
    setDialog(null);
    setPendingMode(null);
    setImportError("");
    setSubscriptionPreview(null);
    setSubscriptionSource("");
    setSubscriptionVisible(false);
  }, []);

  const showToast = useCallback((message: string, kind: ToastKind = "success") => {
    setToast({ message, kind });
  }, []);

  const runAsyncAction: RunAsyncAction = useCallback(async <T,>({ page, title, action, setBusy, onSuccess, onError, errorPresentation = "persistent", retry }: AsyncActionOptions<T>) => {
    setBusy?.(true);
    setActionFailure((current) => current?.page === page ? null : current);
    try {
      const value = await action();
      setActionFailure((current) => current?.page === page ? null : current);
      onSuccess?.(value);
      return value;
    } catch (error) {
      const publicError = toPublicActionError(error);
      onError?.(publicError);
      if (errorPresentation === "persistent") {
        setActionFailure({
          page,
          retry,
          notice: {
            id: `action-${page}`,
            kind: "error",
            title,
            body: publicError.message,
            redactedDetail: publicError.redactedDetail ?? "Действие остановлено безопасно. Повторите попытку или откройте диагностику; зелёный статус не выставлен.",
          },
        });
      }
      return undefined;
    } finally {
      setBusy?.(false);
    }
  }, []);

  const navigate = useCallback((destination: Destination) => {
    if (mainRef.current) scrollPositions.current[activePage] = mainRef.current.scrollTop;
    setActivePage(destination);
  }, [activePage]);

  useEffect(() => {
    const frame = window.requestAnimationFrame(() => {
      headingRef.current?.focus({ preventScroll: true });
      if (mainRef.current) mainRef.current.scrollTop = scrollPositions.current[activePage];
    });
    return () => window.cancelAnimationFrame(frame);
  }, [activePage]);

  useEffect(() => {
    const onKeyDown = (event: KeyboardEvent) => {
      if (!event.altKey || event.ctrlKey || event.metaKey || dialog) return;
      const index = Number(event.key) - 1;
      const destination = destinations[index];
      if (!destination) return;
      event.preventDefault();
      navigate(destination);
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [dialog, navigate]);

  useEffect(() => {
    if (!toast || toastPaused) return;
    // Resuming starts a fresh five-second reading window; no notification expires while hovered or focused.
    const timer = window.setTimeout(() => setToast(null), 5000);
    return () => window.clearTimeout(timer);
  }, [toast, toastPaused]);

  useEffect(() => {
    const query = window.matchMedia("(prefers-color-scheme: light)");
    const applyTheme = () => {
      const theme = settingsDraft.theme === "system" ? (query.matches ? "light" : "dark") : settingsDraft.theme;
      document.documentElement.dataset.theme = theme;
    };
    applyTheme();
    query.addEventListener("change", applyTheme);
    return () => query.removeEventListener("change", applyTheme);
  }, [settingsDraft.theme]);

  const handleModeChange = (mode: ConnectionMode) => {
    if (mode === snapshot.mode) return;
    if (snapshot.phase !== "disconnected") {
      setPendingMode(mode);
      setDialog("mode-change");
      return;
    }
    void runAsyncAction({
      page: "home",
      title: "Не удалось сменить режим",
      action: async () => controller.setMode(mode),
      retry: () => handleModeChange(mode),
    });
  };

  const handleConnect = () => {
    if (snapshot.mode === "tun" && snapshot.environment.otherVpnDetected) {
      setTunChoice("");
      setDialog("tun-preflight");
      return;
    }
    void runAsyncAction({
      page: "home",
      title: "Не удалось подключиться",
      action: () => controller.connect(),
      retry: handleConnect,
    });
  };

  const connectTun = () => {
    if (!tunChoice) return;
    const choice: TunPathChoice = tunChoice === "nested" ? { type: "nested" } : { type: "physical", adapterId };
    closeDialog();
    void runAsyncAction({
      page: "home",
      title: "Не удалось запустить TUN",
      action: () => controller.connect(choice),
      retry: () => {
        setTunChoice("");
        setDialog("tun-preflight");
      },
    });
  };

  const applyRouting = async () => {
    await controller.applyRouting(routingDraft);
    setRoutingDraft(controller.getSnapshot().routing);
  };

  const saveSettings = async () => {
    await controller.saveSettings(settingsDraft);
    setSettingsDraft(controller.getSnapshot().settings);
  };

  const focusImportInput = () => window.requestAnimationFrame(() => {
    if (importMethod === "url") subscriptionInputRef.current?.focus();
    else clipboardButtonRef.current?.focus();
  });

  const readClipboardSource = () => {
    void runAsyncAction({
      page: "servers",
      title: "Не удалось прочитать буфер обмена",
      setBusy: setImporting,
      action: () => navigator.clipboard.readText(),
      retry: readClipboardSource,
      errorPresentation: "inline",
      onError: (publicError) => {
        setImportError(publicError.message);
        focusImportInput();
      },
      onSuccess: (value) => {
        setSubscriptionSource(value);
        setImportError(value.trim() ? "" : "Буфер обмена пуст.");
        if (!value.trim()) focusImportInput();
      },
    });
  };

  const previewImport = () => {
    if (importMethod === "file") {
      setImportError("Выбор файла появится вместе с Tauri dialog adapter.");
      return;
    }
    if (!subscriptionSource.trim()) {
      setImportError(importMethod === "url" ? "Введите URL подписки. Значение будет скрыто после импорта." : "Сначала явно прочитайте подписку из буфера обмена.");
      focusImportInput();
      return;
    }
    setImportError("");
    const source: SubscriptionImportSource = importMethod === "url"
      ? { type: "url", value: subscriptionSource }
      : { type: "clipboard", value: subscriptionSource };
    void runAsyncAction({
      page: "servers",
      title: "Не удалось проверить подписку",
      setBusy: setImporting,
      action: () => controller.previewSubscription(source),
      retry: previewImport,
      errorPresentation: "inline",
      onError: (publicError) => {
        setImportError(publicError.message);
        focusImportInput();
      },
      onSuccess: (preview) => setSubscriptionPreview(preview),
    });
  };

  const commitImport = () => {
    if (!subscriptionPreview) return;
    void runAsyncAction({
      page: "servers",
      title: "Не удалось импортировать подписку",
      setBusy: setImporting,
      action: () => controller.commitSubscription(subscriptionPreview),
      retry: commitImport,
      errorPresentation: "inline",
      onError: (publicError) => setImportError(publicError.message),
      onSuccess: () => {
        closeDialog();
        setSubscriptionSource("");
        showToast("Подписка проверена и импортирована", "success");
      },
    });
  };

  const disconnect = () => {
    void runAsyncAction({
      page: "home",
      title: "Не удалось безопасно отключиться",
      action: controller.disconnect,
      retry: disconnect,
    });
  };

  const retryConnection = () => {
    void runAsyncAction({
      page: "home",
      title: "Повторная проверка не удалась",
      action: controller.retry,
      retry: retryConnection,
    });
  };

  const renderPage = () => {
    switch (activePage) {
      case "home":
        return <HomePage snapshot={snapshot} headingRef={headingRef} onNavigate={navigate} onModeChange={handleModeChange} onConnect={handleConnect} onDisconnect={disconnect} onRetry={retryConnection} actionFailure={actionFailure} onClearFailure={() => setActionFailure(null)} />;
      case "servers":
        return <ServersPage snapshot={snapshot} headingRef={headingRef} search={search} onSearch={setSearch} onImport={() => setDialog("import")} onToast={showToast} runAsyncAction={runAsyncAction} actionFailure={actionFailure} onClearFailure={() => setActionFailure(null)} />;
      case "routing":
        return <RoutingPage snapshot={snapshot} headingRef={headingRef} draft={routingDraft} onDraftChange={setRoutingDraft} onApply={applyRouting} onToast={showToast} runAsyncAction={runAsyncAction} actionFailure={actionFailure} onClearFailure={() => setActionFailure(null)} />;
      case "settings":
        return <SettingsPage snapshot={snapshot} headingRef={headingRef} draft={settingsDraft} onDraftChange={setSettingsDraft} onSave={saveSettings} onReset={() => setDialog("reset")} onToast={showToast} runAsyncAction={runAsyncAction} actionFailure={actionFailure} onClearFailure={() => setActionFailure(null)} />;
      case "diagnostics":
        return <DiagnosticsPage snapshot={snapshot} headingRef={headingRef} onToast={showToast} runAsyncAction={runAsyncAction} actionFailure={actionFailure} onClearFailure={() => setActionFailure(null)} />;
    }
  };

  return (
    <div className="app-shell" data-demo={snapshot.isDemo || undefined}>
      <header className="app-header">
        <div className="brand"><span className="brand-mark"><RoutingIcon size={20} /></span><span><strong>RouteDeck</strong><small>sing-box controller</small></span></div>
        <StatusBadge phase={snapshot.phase} />
      </header>
      {snapshot.isDemo ? (
        <div className="demo-banner" role="status">
          <InfoIcon size={17} />
          <strong>DEMO</strong>
          <span>Нет сети и системных изменений. Все статусы примерные.</span>
        </div>
      ) : null}
      <div className="workspace">
        <Navigation active={activePage} onNavigate={navigate} variant="rail" />
        <main className="app-main" ref={mainRef}>{renderPage()}</main>
      </div>
      <Navigation active={activePage} onNavigate={navigate} variant="bottom" />
      {toast ? <Toast toast={toast} onPausedChange={setToastPaused} onClose={() => { setToast(null); setToastPaused(false); }} /> : null}

      {dialog === "import" ? (
        <Dialog
          title="Импорт подписки"
          description="RouteDeck импортирует только поддерживаемые узлы и не выполняет чужие команды или настройки."
          focusKey={subscriptionPreview ? "preview" : "source"}
          onClose={closeDialog}
          actions={subscriptionPreview ? <>
            <button className="secondary-button" type="button" data-autofocus onClick={() => { setSubscriptionPreview(null); setImportError(""); }}>Назад</button>
            <button className="primary-button dialog-primary" type="button" disabled={importing} aria-busy={importing} onClick={commitImport}>{importing ? <LoaderIcon size={19} /> : <ImportIcon size={19} />}{importing ? "Импортируем…" : "Подтвердить импорт"}</button>
          </> : <>
            <button className="secondary-button" type="button" data-autofocus onClick={closeDialog}>Отмена</button>
            <button className="primary-button dialog-primary" type="button" disabled={importing || importMethod === "file"} aria-busy={importing} onClick={previewImport}>{importing ? <LoaderIcon size={19} /> : <ImportIcon size={19} />}{importing ? "Проверяем…" : "Проверить источник"}</button>
          </>}
        >
          {subscriptionPreview ? (
            <section className="import-preview" aria-live="polite">
              {importError ? <p id="import-error" className="field-error" role="alert">{importError}</p> : null}
              <p className="overline">Предпросмотр · данные ещё не сохранены</p>
              <h3>Найдено поддерживаемых узлов</h3>
              <p className="preview-source">Источник: {subscriptionPreview.sourceLabel}</p>
              <div className="preview-counts">{subscriptionPreview.supported.map((item) => <span key={item.protocol}><strong>{item.count}</strong>{item.protocol}</span>)}</div>
              <p>{subscriptionPreview.unsupportedCount} неподдерживаемых записей будут пропущены.</p>
              <ul>{subscriptionPreview.nodeNames.map((name) => <li key={name}>{name}</li>)}</ul>
            </section>
          ) : <>
            <SegmentedControl
              label="Источник подписки"
              value={importMethod}
              options={[{ value: "url", label: "URL" }, { value: "clipboard", label: "Буфер" }, { value: "file", label: "Файл · скоро", disabled: true }]}
              onChange={(method) => { setImportMethod(method); setSubscriptionSource(""); setSubscriptionVisible(false); setImportError(""); setSubscriptionPreview(null); }}
            />
            {importMethod === "url" ? (
              <div className="dialog-field"><label htmlFor="subscription-url">URL подписки</label><span className="secret-input"><input ref={subscriptionInputRef} id="subscription-url" type={subscriptionVisible ? "text" : "password"} autoComplete="off" value={subscriptionSource} aria-invalid={Boolean(importError)} aria-describedby={importError ? "import-error" : "import-help"} placeholder="https://provider.example/••••" onChange={(event) => { setSubscriptionSource(event.target.value); setImportError(""); }} /><button className="icon-button" type="button" aria-label={subscriptionVisible ? "Скрыть URL" : "Показать URL"} title={subscriptionVisible ? "Скрыть URL" : "Показать URL"} onClick={() => setSubscriptionVisible((visible) => !visible)}><EyeIcon size={18} /></button></span><small id="import-help">URL передаётся typed adapter как секрет и не попадает в диагностику.</small>{importError ? <small id="import-error" className="field-error" role="alert">{importError}</small> : null}</div>
            ) : (
              <div className="method-placeholder compact-placeholder">
                <ImportIcon size={24} />
                <strong>{subscriptionSource ? "Подписка прочитана и скрыта" : "Буфер не читается автоматически"}</strong>
                <p>Нажмите кнопку сами — только это действие запрашивает clipboard API.</p>
                <button ref={clipboardButtonRef} className="secondary-button full-width" type="button" disabled={importing} onClick={readClipboardSource}>Прочитать буфер обмена</button>
                {importError ? <small className="field-error" role="alert">{importError}</small> : null}
              </div>
            )}
            <p className="file-adapter-note"><InfoIcon size={17} />Локальный файл будет доступен после подключения безопасного Tauri dialog adapter; fake-импорт отключён.</p>
          </>}
        </Dialog>
      ) : null}

      {dialog === "tun-preflight" ? (
        <Dialog
          title="Обнаружен другой VPN"
          description="Выберите, как подключать выбранный сервер. RouteDeck перепроверит интерфейс до запроса UAC."
          onClose={closeDialog}
          actions={<><button className="secondary-button" type="button" data-autofocus onClick={closeDialog}>Отмена</button><button className="primary-button dialog-primary" type="button" disabled={!tunChoice || (tunChoice === "physical" && !adapterId)} onClick={connectTun}><ShieldIcon size={19} />Продолжить</button></>}
        >
          <div className="choice-list">
            <label className="choice-card" data-selected={tunChoice === "nested"}><input type="radio" name="tun-path" checked={tunChoice === "nested"} onChange={() => setTunChoice("nested")} /><span><strong>Через текущий VPN</strong><small>RouteDeck будет вложен в существующий путь. Результат помечается как nested.</small></span></label>
            <label className="choice-card" data-selected={tunChoice === "physical"}><input type="radio" name="tun-path" checked={tunChoice === "physical"} onChange={() => setTunChoice("physical")} /><span><strong>Через физический адаптер</strong><small>Попытаться обойти текущий VPN через проверенный интерфейс.</small></span></label>
          </div>
          {tunChoice === "physical" ? <label className="dialog-field"><span>Физический адаптер</span><select value={adapterId} onChange={(event) => setAdapterId(event.target.value)}>{snapshot.environment.physicalAdapters.map((adapter) => <option value={adapter.id} key={adapter.id}>{adapter.label}</option>)}</select></label> : null}
          <div className="persistent-hint" data-kind="warning"><WarningIcon size={18} /><p>Совместимость не предполагается заранее: после запуска нужен свежий HTTPS-proof выбранного outbound.</p></div>
        </Dialog>
      ) : null}

      {dialog === "mode-change" && pendingMode ? (
        <Dialog
          title="Сменить режим подключения?"
          description="RouteDeck сначала безопасно остановит текущую сессию. Новый режим не запустится автоматически."
          onClose={closeDialog}
          actions={<><button className="secondary-button" type="button" data-autofocus onClick={closeDialog}>Оставить текущий</button><button className="primary-button dialog-primary" type="button" onClick={() => { const mode = pendingMode; closeDialog(); void runAsyncAction({ page: "home", title: "Не удалось безопасно сменить режим", action: async () => { await controller.disconnect(); controller.setMode(mode); }, retry: () => handleModeChange(mode) }); }}><CheckIcon size={19} />Отключить и выбрать</button></>}
        ><p className="dialog-copy">Будет выбран режим <strong>{pendingMode === "tun" ? "TUN" : "Системный прокси"}</strong>. После восстановления Windows-состояния нажмите «Подключить».</p></Dialog>
      ) : null}

      {dialog === "reset" ? (
        <Dialog
          title="Сбросить локальное состояние?"
          description="Будут удалены только локальные настройки и черновики RouteDeck. Чужой VPN и Windows не изменяются."
          onClose={closeDialog}
          actions={<><button className="secondary-button" type="button" data-autofocus onClick={closeDialog}>Отмена</button><button className="danger-button" type="button" onClick={() => { closeDialog(); void runAsyncAction({ page: "settings", title: "Не удалось сбросить локальное состояние", action: controller.resetLocalState, retry: () => setDialog("reset"), onSuccess: () => { setRoutingDraft(controller.getSnapshot().routing); setSettingsDraft(controller.getSnapshot().settings); showToast("Локальное состояние сброшено", "info"); } }); }}><TrashIcon size={19} />Сбросить RouteDeck</button></>}
        ><p className="dialog-copy">Активное соединение будет безопасно остановлено контроллером. Перед сбросом backend обязан подтвердить восстановление принадлежащего RouteDeck состояния.</p></Dialog>
      ) : null}
    </div>
  );
}

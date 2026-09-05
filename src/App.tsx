import {
  useCallback,
  useDeferredValue,
  useEffect,
  useId,
  useMemo,
  useRef,
  useState,
  useSyncExternalStore,
  type ReactNode,
} from "react";
import { createPortal } from "react-dom";
import { controller } from "./controller";
import { syncWindowTheme } from "./windowAppearance";
import { useAutoSave } from "./useAutoSave";
import { nextSubscriptionRefresh } from "./subscriptionRefresh";
import { appUpdateMonitor } from "./appUpdates";
import { toPublicActionError, type PublicActionError } from "./actionErrors";
import {
  ActivityIcon,
  CheckIcon,
  ChevronRightIcon,
  CopyIcon,
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
  destinations,
  type AppNotice,
  type AppRouteChoice,
  type ConnectionMode,
  type ConnectionPhase,
  type ConnectionProof,
  type ControllerSnapshot,
  type Destination,
  type RoutingConfig,
  type RunningApplication,
  type Server,
  type SettingsConfig,
  type SubscriptionPreview,
  type TrafficRule,
} from "./model";

type DialogKind = "import" | "refresh-source" | "remove-source" | "reset" | "latency-info" | "clear-stale-proxy" | null;
type ImportKind = "manual" | "subscription";
type ToastKind = "success" | "info" | "warning";
type ToastState = { message: string; kind: ToastKind };
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

function useController() {
  return useSyncExternalStore(controller.subscribe, controller.getSnapshot, controller.getSnapshot);
}

function useAppUpdates() {
  return useSyncExternalStore(appUpdateMonitor.subscribe, appUpdateMonitor.getSnapshot, appUpdateMonitor.getSnapshot);
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

function HomePage({ snapshot, libraryBusy, headingRef, onNavigate, onModeChange, onConnect, onDisconnect, onRetry, onLatencyInfo, actionFailure, onClearFailure }: {
  snapshot: ControllerSnapshot;
  libraryBusy: boolean;
  headingRef: React.RefObject<HTMLHeadingElement | null>;
  onNavigate: (destination: Destination) => void;
  onModeChange: (mode: ConnectionMode) => void;
  onConnect: () => void;
  onDisconnect: () => void;
  onRetry: () => void;
  onLatencyInfo: () => void;
  actionFailure: ActionFailure | null;
  onClearFailure: () => void;
}) {
  const server = snapshot.servers.find((item) => item.id === snapshot.selectedServerId);
  const activeServer = snapshot.servers.find((item) => item.id === snapshot.activeServerId);
  const pending = (Boolean(snapshot.switching) && !libraryBusy) || pendingPhases.includes(snapshot.phase);
  const connected = snapshot.phase === "connected" && !pending;
  const active = Boolean(snapshot.activeServerId) || ["connected", "degraded", "blocked-by-conflict"].includes(snapshot.phase);
  const mode = snapshot.activeMode ?? snapshot.mode;
  const liveLatency = connected && activeServer?.latencyState === "ready" ? activeServer.latencyMs : undefined;
  const status = pending ? "Переключаемся" : phaseLabels[snapshot.phase];
  const boundaryNotice = !snapshot.backendAvailable && !snapshot.isDemo;
  return (
    <div className="page home-page">
      <h1 className="sr-only" ref={headingRef} tabIndex={-1}>Главная</h1>
      <ActionFailureNotice failure={actionFailure} page="home" onClear={onClearFailure} />
      <section className="connection-hero" data-state={connected ? "connected" : pending ? "pending" : snapshot.phase === "failed" ? "failed" : "idle"} aria-label="Подключение">
        <div className="hero-topline"><span className="eyebrow">ВАШЕ ПОДКЛЮЧЕНИЕ</span><span className="connection-live-dot" aria-hidden="true" /></div>
        <div className="hero-status-row">
          <span className="hero-symbol">{pending ? <LoaderIcon size={32} /> : <ShieldIcon size={32} />}</span>
          <div className="hero-status-copy"><h2 aria-live="polite">{status}</h2><p>{pending ? phaseLabels[snapshot.phase] : connected ? `${mode === "tun" ? "TUN" : "Системный прокси"} · маршрут проверен` : active ? "Соединение требует внимания" : "Готов к подключению"}</p></div>
        </div>
        <div className="connection-current">
          <span>{activeServer ? "Сейчас используется" : "Сервер для подключения"}</span>
          <strong>{activeServer?.name ?? server?.name ?? "Добавьте первый сервер"}</strong>
          <span>{activeServer?.source ?? server?.source ?? "Подписка или отдельная ссылка"}</span>
        </div>
        <button className={`primary-button connection-button${active || pending ? " disconnect-button" : ""}`} type="button"
          disabled={boundaryNotice || (!server && !active && !pending) || snapshot.phase === "disconnecting"}
          onClick={active || pending ? onDisconnect : onConnect}>
          {active || pending ? <XCircleIcon size={23} /> : <ShieldIcon size={23} />}
          <span>{snapshot.phase === "disconnecting" ? "Отключаем…" : pending ? "Отменить подключение" : active ? "Отключить" : "Подключить"}</span>
        </button>
        <div className="connection-metrics">
          <button type="button" className="latency-metric" onClick={onLatencyInfo} aria-label="Как измеряется отклик через VPN"><ActivityIcon size={16} /><strong>{liveLatency !== undefined ? `${liveLatency} мс` : "—"}</strong><span>Отклик · Google</span><InfoIcon size={14} /></button>
          <span>{connected ? liveLatency === undefined ? "Ожидаем замер" : "Обновляется автоматически" : "Замер после подключения"}</span>
        </div>
      </section>
      <button className="selection-card server-choice" type="button" onClick={() => onNavigate("servers")}>
        <span className="selection-leading"><ServersIcon size={20} /></span>
        <span className="selection-copy"><span className="selection-label">{pending ? "Переключаем на" : "Выбранный сервер"}</span><strong>{server?.name ?? "Выбрать сервер"}</strong><span>{server ? `${server.protocol} · ${server.source}` : "Добавить или выбрать из библиотеки"}</span></span>
        <ChevronRightIcon size={20} />
      </button>
      <section className="mode-section" aria-labelledby="connection-mode-title">
        <div className="section-heading compact-heading"><h2 id="connection-mode-title">Режим подключения</h2><span className="field-help">Автопереключение</span></div>
        <SegmentedControl label="Режим подключения" value={snapshot.mode} options={[{ value: "proxy", label: "Системный прокси" }, { value: "tun", label: "TUN" }]} onChange={onModeChange} disabled={boundaryNotice} />
        <p className="mode-explanation">{snapshot.mode === "tun" ? "Трафик устройства через TUN. Windows запросит права при подключении." : "Для приложений с поддержкой прокси Windows. UDP и системный DNS не перехватываются."}</p>
      </section>
      {snapshot.notice && actionFailure?.page !== "home" ? <OpaqueNotice notice={snapshot.notice} onClose={boundaryNotice ? undefined : controller.dismissNotice} primaryAction={boundaryNotice ? undefined : { label: "Повторить", onClick: onRetry }} secondaryAction={{ label: "Диагностика", onClick: () => onNavigate("diagnostics") }} /> : null}
      <button className="summary-card routing-shortcut" type="button" onClick={() => onNavigate("routing")}><RoutingIcon size={19} /><span className="selection-copy"><strong>Правила маршрутизации</strong><span>{snapshot.routing.defaultRoute === "vpn" ? "По умолчанию через VPN" : "По умолчанию напрямую"} · исключений: {snapshot.routing.apps.filter((app) => app.route !== "inherit" && app.route !== snapshot.routing.defaultRoute).length}</span></span><ChevronRightIcon size={18} /></button>
    </div>
  );
}

function ServersPage({ snapshot, headingRef, search, onSearch, onImport, onSelect, picking, onBack, onRefresh, onRemove, sourceBusy, actionFailure, onClearFailure }: {
  snapshot: ControllerSnapshot;
  headingRef: React.RefObject<HTMLHeadingElement | null>;
  search: string;
  onSearch: (value: string) => void;
  onImport: (kind: ImportKind) => void;
  onSelect: (id: string) => void;
  picking: boolean;
  onBack: () => void;
  onRefresh: (server: Server) => void;
  onRemove: (server: Server) => void;
  sourceBusy: boolean;
  actionFailure: ActionFailure | null;
  onClearFailure: () => void;
}) {
  const filtered = useMemo(() => {
    const query = search.trim().toLocaleLowerCase("ru-RU");
    return snapshot.servers.filter((server) => !query || `${server.country} ${server.name} ${server.protocol} ${server.source}`.toLocaleLowerCase("ru-RU").includes(query));
  }, [search, snapshot.servers]);
  const [collapsedGroups, setCollapsedGroups] = useState<Set<string>>(() => new Set());
  const [visibleCounts, setVisibleCounts] = useState<Record<string, number>>({});
  const groupIdPrefix = useId();
  useEffect(() => {
    setCollapsedGroups(new Set());
    setVisibleCounts({});
  }, [search]);
  const groups = useMemo(() => {
    const result = new Map<string, { name: string; kind: ImportKind; servers: typeof filtered }>();
    for (const server of filtered) {
      const id = server.sourceId ?? server.source;
      const group = result.get(id) ?? { name: server.source, kind: server.sourceKind ?? "subscription", servers: [] };
      group.servers.push(server);
      result.set(id, group);
    }
    return [...result.entries()];
  }, [filtered]);

  return (
    <div className="page">
      <div className="page-title-row">
        <div><p className="overline">{picking ? "Выбор подключения" : "Моя библиотека"}</p><h1 ref={headingRef} tabIndex={-1}>{picking ? "Выбрать сервер" : "Серверы"}</h1></div>
        <span className="count-badge">{snapshot.servers.length}</span>
      </div>
      {picking ? <button type="button" className="text-button picker-back" onClick={onBack}>← Назад к подключению</button> : null}
      <ActionFailureNotice failure={actionFailure} page="servers" onClear={onClearFailure} />
      <div className="server-add-actions">
        <button className="primary-button" type="button" disabled={sourceBusy} onClick={() => onImport("manual")}><PlusIcon size={20} />Добавить сервер</button>
        <button className="secondary-button" type="button" disabled={sourceBusy} onClick={() => onImport("subscription")}><ImportIcon size={20} />Подписка</button>
      </div>
      <div className="toolbar">
        <label className="search-field">
          <span className="sr-only">Поиск серверов</span>
          <SearchIcon size={18} />
          <input value={search} type="search" placeholder="Имя, протокол или группа" onChange={(event) => onSearch(event.target.value)} />
        </label>
      </div>
      <div className="subscription-meta">
        <span>{filtered.length} из {snapshot.servers.length} серверов</span>
        <span>{snapshot.switching ? "Переподключение…" : sourceBusy ? "Обновление библиотеки…" : picking ? "После выбора вернёмся на главную" : "Выбор применяется автоматически"}</span>
      </div>
      <div className="server-list" role="radiogroup" aria-label="Выбор сервера">
        {filtered.length ? groups.map(([groupId, group], index) => {
          const expanded = !collapsedGroups.has(groupId);
          const visibleCount = Object.hasOwn(visibleCounts, groupId) ? visibleCounts[groupId] : 100;
          const panelId = `${groupIdPrefix}-${index}`;
          return <section className="server-group" key={groupId}>
            <div className="source-heading"><h2><button className="server-group-toggle" type="button" aria-expanded={expanded} aria-controls={panelId} onClick={() => setCollapsedGroups((current) => {
              const next = new Set(current);
              if (next.has(groupId)) next.delete(groupId); else next.add(groupId);
              return next;
            })}>
              <ChevronRightIcon size={18} />
              <span className="server-group-copy"><strong>{group.name}</strong><span>{group.kind === "manual" ? "Добавлено вручную" : group.servers[0].sourceUpdatedAtMs ? `Обновлено ${new Date(group.servers[0].sourceUpdatedAtMs).toLocaleDateString("ru-RU", { day: "2-digit", month: "2-digit" })}` : "Подписка"}</span></span>
              <span className="count-badge">{group.servers.length}</span>
            </button></h2>
            {group.servers[0].sourceId ? <div className="source-actions">
              {group.kind === "subscription" ? <button className="icon-button" type="button" disabled={sourceBusy} aria-label={`Обновить подписку ${group.name}`} title="Обновить подписку" onClick={() => onRefresh(group.servers[0])}><RefreshIcon size={18} /></button> : null}
              <button className="icon-button" type="button" disabled={sourceBusy} aria-label={`Удалить группу ${group.name}`} title="Удалить группу" onClick={() => onRemove(group.servers[0])}><TrashIcon size={18} /></button>
            </div> : null}</div>
            <div id={panelId} className="server-group-rows" hidden={!expanded}>
            {group.servers.slice(0, visibleCount).map((server) => {
          const selected = server.id === snapshot.selectedServerId;
          const latency = server.latencyState === "pending" ? "Проверка…" : server.latencyState === "timeout" ? "Тайм-аут" : server.latencyState === "unavailable" ? "—" : `${server.latencyMs} мс`;
          return (
            <label
              className="server-row"
              data-selected={selected}
              key={server.id}
            >
              <input className="control-input" type="radio" name="selected-server" value={server.id} checked={selected} onClick={() => { if (selected) onSelect(server.id); }} onChange={() => onSelect(server.id)} />
              <span className="radio-indicator" aria-hidden="true"><span /></span>
              <span className="protocol-mark" aria-hidden="true">{server.protocol.slice(0, 1)}</span>
              <span className="server-copy">
                <strong title={server.name}>{server.name}</strong>
                <span>{server.protocol}{server.protocol === "Naive" ? snapshot.routing.naiveUdpOverTcp ? " · UoT v2 включён" : " · TCP без UDP" : ""}{server.id === snapshot.activeServerId ? " · Активен" : ""}</span>
              </span>
              <span className="latency" data-state={server.latencyState}>
                <strong>{latency}</strong>
                <span title="Отклик Google через выбранный VPN на установленном соединении">{server.latencyMs !== undefined && server.latencyState === "ready" ? "Google" : "не измерено"}</span>
              </span>
            </label>
          );
            })}
            {group.servers.length > visibleCount ? <button className="secondary-button" type="button" onClick={() => setVisibleCounts((current) => ({ ...current, [groupId]: visibleCount + 100 }))}>Показать ещё · осталось {group.servers.length - visibleCount}</button> : null}
            </div>
          </section>;
        }) : <div className="empty-state"><ServersIcon size={24} /><strong>{snapshot.servers.length ? "Ничего не найдено" : "Добавьте первый сервер"}</strong><span>{snapshot.servers.length ? "Попробуйте другое имя, протокол или группу." : "Вставьте ссылку сервера или добавьте подписку от провайдера."}</span></div>}
      </div>
    </div>
  );
}

type SaveFeedback = { pending: boolean; error: string; retry: () => void };

function SaveState({ state, unapplied = false }: { state: SaveFeedback; unapplied?: boolean }) {
  return <div className="save-feedback" data-error={Boolean(state.error)}>
    <span role="status" aria-live="polite">{state.error ? "Не сохранено или не применено" : state.pending ? "Сохраняем…" : unapplied ? "Сохранено · ожидает подключения" : "Сохранено"}</span>
    {state.error ? <><p role="alert">{state.error}</p><button className="text-button" type="button" onClick={state.retry}>Повторить</button></> : null}
  </div>;
}

function RoutingPage({ snapshot, headingRef, draft, onDraftChange, saveState }: {
  snapshot: ControllerSnapshot;
  headingRef: React.RefObject<HTMLHeadingElement | null>;
  draft: RoutingConfig;
  onDraftChange: (routing: RoutingConfig) => void;
  saveState: SaveFeedback;
}) {
  const [search, setSearch] = useState("");
  const [showPaths, setShowPaths] = useState(false);
  const [pickerOpen, setPickerOpen] = useState(false);
  const [pickerLoading, setPickerLoading] = useState(false);
  const [pickerSearch, setPickerSearch] = useState("");
  const [pickerError, setPickerError] = useState("");
  const [runningApplications, setRunningApplications] = useState<RunningApplication[]>([]);
  const [trafficEditor, setTrafficEditor] = useState<TrafficRule | null>(null);
  const [trafficEditorOriginalId, setTrafficEditorOriginalId] = useState<string | null>(null);
  const [trafficEditorError, setTrafficEditorError] = useState("");
  const deferredPickerSearch = useDeferredValue(pickerSearch);
  const summary = draft.defaultRoute === "direct"
    ? `По умолчанию напрямую · ${draft.apps.filter((app) => app.route === "vpn").length} исключений через VPN`
    : `По умолчанию через VPN · ${draft.apps.filter((app) => app.route === "direct").length} исключений напрямую`;
  const selectedPaths = useMemo(() => new Set(
    draft.apps.map((app) => app.path.replaceAll("/", "\\").toLocaleLowerCase("en-US")),
  ), [draft.apps]);
  const filteredApplications = useMemo(() => {
    const query = deferredPickerSearch.trim().toLocaleLowerCase("ru-RU");
    return runningApplications.filter((application) => !query
      || `${application.displayName} ${application.processName} ${application.executablePath}`.toLocaleLowerCase("ru-RU").includes(query));
  }, [deferredPickerSearch, runningApplications]);

  const updateApp = (id: string, route: AppRouteChoice) => onDraftChange({
    ...draft,
    apps: draft.apps.map((app) => app.id === id ? { ...app, route } : app),
  });

  const openApplicationPicker = () => {
    if (pickerLoading) return;
    setPickerOpen(true);
    setPickerLoading(true);
    setPickerSearch("");
    setPickerError("");
    void controller.listRunningApplications()
      .then(setRunningApplications)
      .catch((error) => setPickerError(toPublicActionError(error).message))
      .finally(() => setPickerLoading(false));
  };

  const addApplication = (application: RunningApplication) => {
    const canonicalPath = application.executablePath.replaceAll("/", "\\").toLocaleLowerCase("en-US");
    if (selectedPaths.has(canonicalPath)) return;
    const name = application.displayName.replace(/\.exe$/i, "") || application.displayName;
    onDraftChange({
      ...draft,
      apps: [...draft.apps, {
        id: canonicalPath,
        name,
        path: application.executablePath,
        route: draft.defaultRoute === "direct" ? "vpn" : "direct",
      }],
    });
  };

  const matchingApps = draft.apps.filter((app) => `${app.name} ${app.path}`.toLocaleLowerCase("ru-RU").includes(search.trim().toLocaleLowerCase("ru-RU")));
  const openTrafficEditor = (rule?: TrafficRule) => {
    setTrafficEditorOriginalId(rule?.id ?? null);
    setTrafficEditor(rule ? { ...rule } : { id: `traffic-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`, enabled: true, network: "udp", port: 443, action: "block" });
    setTrafficEditorError("");
  };
  const closeTrafficEditor = () => { setTrafficEditor(null); setTrafficEditorOriginalId(null); setTrafficEditorError(""); };
  const applyTrafficEditor = () => {
    if (!trafficEditor) return;
    if (!Number.isInteger(trafficEditor.port) || trafficEditor.port < 1 || trafficEditor.port > 65535) { setTrafficEditorError("Укажите целый порт от 1 до 65535."); return; }
    if (trafficEditor.port === 53) { setTrafficEditorError("Порт 53 зарезервирован для защищённой обработки DNS."); return; }
    const trafficRules = trafficEditorOriginalId
      ? draft.trafficRules.map((rule) => rule.id === trafficEditorOriginalId ? trafficEditor : rule)
      : [...draft.trafficRules, trafficEditor];
    onDraftChange({ ...draft, trafficRules });
    closeTrafficEditor();
  };
  const moveTrafficRule = (index: number, direction: -1 | 1) => {
    const target = index + direction;
    if (target < 0 || target >= draft.trafficRules.length) return;
    const trafficRules = [...draft.trafficRules];
    [trafficRules[index], trafficRules[target]] = [trafficRules[target], trafficRules[index]];
    onDraftChange({ ...draft, trafficRules });
  };
  const blocksQuic = draft.trafficRules.find((rule) => rule.enabled && rule.network === "udp" && rule.port === 443)?.action === "block";
  return (
    <div className="page routing-page">
      <div className="page-title-row">
        <h1 ref={headingRef} tabIndex={-1}>Правила</h1>
        <SaveState state={saveState} unapplied={snapshot.routingPending} />
      </div>
      <section className="card route-default">
        <label htmlFor="default-route"><strong>Остальной трафик</strong><small>Приложения ниже — исключения</small></label>
        <select id="default-route" value={draft.defaultRoute} onChange={(event) => onDraftChange({ ...draft, defaultRoute: event.target.value as RoutingConfig["defaultRoute"] })}>
          <option value="vpn">Через VPN</option><option value="direct">Напрямую</option>
        </select>
      </section>

      <details className="routing-scope"><summary>{snapshot.mode === "tun" ? "TUN · трафик Windows" : "Системный прокси · ограниченный охват"}</summary><p>{snapshot.mode === "tun" ? "Правила охватывают трафик Windows." : "Только TCP приложений, использующих прокси Windows. Для остальных приложений и UDP нужен TUN."} Изменения сохраняются автоматически; активное соединение переподключится.</p></details>
      <section className="card rules-table">
        <div className="rules-toolbar">
          <h2>Приложения <span className="quiet-count">{draft.apps.length}</span></h2>
          <button className="secondary-button compact-action" type="button" disabled={pickerLoading} onClick={openApplicationPicker}><PlusIcon size={17} />Добавить</button>
        </div>
        {draft.apps.length > 0 ? <div className="rules-filter">
          <label className="search-field"><SearchIcon size={17} /><input type="search" aria-label="Найти правило" placeholder="Найти приложение" value={search} onChange={(event) => setSearch(event.target.value)} /></label>
          <label className="paths-toggle"><input type="checkbox" checked={showPaths} onChange={(event) => setShowPaths(event.target.checked)} />Пути</label>
        </div> : null}
        <div className="app-rule-list">
          {matchingApps.map((app) => <div className="compact-rule" key={app.id}>
            <span className="rule-app-copy"><strong title={app.path}>{app.name}</strong>{showPaths ? <small>{app.path}</small> : null}</span>
            <select aria-label={`Маршрут для ${app.name}`} value={app.route} onChange={(event) => updateApp(app.id, event.target.value as AppRouteChoice)}>
              <option value="inherit">По умолчанию</option><option value="vpn">Через VPN</option><option value="direct">Напрямую</option>
            </select>
            <button className="icon-button rule-remove" type="button" aria-label={`Удалить правило ${app.name}`} title="Удалить правило" onClick={() => onDraftChange({ ...draft, apps: draft.apps.filter((item) => item.id !== app.id) })}><XIcon size={16} /></button>
          </div>)}
          {matchingApps.length === 0 ? <div className="empty-state compact-empty"><RoutingIcon size={22} /><strong>{draft.apps.length ? "Ничего не найдено" : "Исключений пока нет"}</strong><span>{draft.apps.length ? "Измените запрос или очистите поиск." : "Добавьте запущенное приложение и выберите его маршрут."}</span></div> : null}
        </div>
        <p className="rules-footer">{search ? `Найдено: ${matchingApps.length} из ${draft.apps.length}` : summary}</p>
      </section>

      <details className="card traffic-rules">
        <summary><span><strong>Правила трафика</strong><small>Только TUN · {draft.trafficRules.length} из 32 · первое совпадение</small></span>{blocksQuic ? <span className="quiet-badge">UDP 443 блокируется</span> : null}</summary>
        <div className="traffic-rules-body">
          <p className="field-help">Только для TUN. Эти правила применяются перед исключениями приложений, но после защищённой обработки DNS и IPv6.</p>
          <div className="traffic-rule-list">
            {draft.trafficRules.map((rule, index) => <div className="traffic-rule-row" key={rule.id}>
              <label className="traffic-rule-enabled"><input type="checkbox" checked={rule.enabled} onChange={(event) => onDraftChange({ ...draft, trafficRules: draft.trafficRules.map((item) => item.id === rule.id ? { ...item, enabled: event.target.checked } : item) })} /><span className="sr-only">Включить правило {index + 1}</span></label>
              <span className="traffic-rule-copy"><strong>{rule.network.toUpperCase()} {rule.port}</strong><small>{rule.action === "block" ? "Блокировать" : rule.action === "direct" ? "Напрямую" : "Через VPN"}</small></span>
              <span className="traffic-rule-order"><button className="icon-button" type="button" disabled={index === 0} aria-label={`Поднять правило ${index + 1}`} title="Поднять" onClick={() => moveTrafficRule(index, -1)}>↑</button><button className="icon-button" type="button" disabled={index === draft.trafficRules.length - 1} aria-label={`Опустить правило ${index + 1}`} title="Опустить" onClick={() => moveTrafficRule(index, 1)}>↓</button></span>
              <button className="text-button" type="button" onClick={() => openTrafficEditor(rule)}>Изменить</button>
              <button className="icon-button" type="button" aria-label={`Удалить правило ${index + 1}`} title="Удалить" onClick={() => onDraftChange({ ...draft, trafficRules: draft.trafficRules.filter((item) => item.id !== rule.id) })}><XIcon size={16} /></button>
            </div>)}
          </div>
          <button className="secondary-button compact-action" type="button" disabled={draft.trafficRules.length >= 32} onClick={() => openTrafficEditor()}><PlusIcon size={17} />Добавить правило</button>
          <p className="settings-explanation">Блокировка UDP 443 может улучшить совместимость YouTube за счёт перехода на TCP. Приложения, работающие только через QUIC, потребуют отключить это правило.</p>
        </div>
      </details>

      <details className="card settings-details naive-settings">
        <summary>Дополнительные настройки Naive</summary>
        <label className="field-row"><span><strong>UDP over TCP для Naive</strong><small>Для всех профилей Naive</small></span><input type="checkbox" aria-label="UDP over TCP для Naive" checked={draft.naiveUdpOverTcp} onChange={(event) => onDraftChange({ ...draft, naiveUdpOverTcp: event.target.checked })} /></label>
        <p className="settings-explanation">На сервере нужна поддержка SagerNet UoT v2, например в sing-box. Обычного Naive или Caddy недостаточно. Для UDP приложений используйте TUN. Правила трафика, включая блокировку UDP 443, продолжают действовать.</p>
      </details>

      <details className="card settings-details tun-stack-settings">
        <summary>Дополнительные настройки TUN</summary>
        <label className="field-row"><span><strong>Стек TUN</strong><small>Применяется только в режиме TUN</small></span><select aria-label="Стек TUN" value={draft.tunStack} onChange={(event) => onDraftChange({ ...draft, tunStack: event.target.value as RoutingConfig["tunStack"] })}><option value="gvisor">gVisor</option><option value="system">System</option></select></label>
        <p className="settings-explanation">По умолчанию используется gVisor. Он может помочь с совместимостью с zapret. При необходимости можно выбрать System; настройка сохраняется.</p>
      </details>

      {pickerOpen ? (
        <Dialog
          title="Добавить приложение"
          description="Выберите приложение из запущенных сейчас."
          focusKey="application-picker-search"
          onClose={() => setPickerOpen(false)}
          busy={pickerLoading}
          actions={<><button className="text-button" type="button" disabled={pickerLoading} onClick={openApplicationPicker}><RefreshIcon size={16} />Обновить список</button><button className="secondary-button" type="button" onClick={() => setPickerOpen(false)}>Готово · {draft.apps.length}</button></>}
        >
          {pickerLoading ? <p className="persistent-hint" role="status" aria-live="polite" tabIndex={-1} data-dialog-busy-focus><LoaderIcon size={17} />Ищем запущенные приложения…</p> : (
            <>
              <label className="search-field application-search" htmlFor="application-picker-search">
                <SearchIcon size={18} /><span className="sr-only">Поиск приложений</span>
                <input id="application-picker-search" value={pickerSearch} onChange={(event) => setPickerSearch(event.target.value)} placeholder="Найти приложение" autoComplete="off" data-autofocus />
              </label>
              {pickerError ? <p className="field-error" role="alert">{pickerError}</p> : null}
              {!pickerError ? <div className="application-picker-list">
                {filteredApplications.length > 0 ? filteredApplications.map((application) => {
                  const canonicalPath = application.executablePath.replaceAll("/", "\\").toLocaleLowerCase("en-US");
                  const added = selectedPaths.has(canonicalPath);
                  return (
                    <button className="application-picker-row" type="button" disabled={added} onClick={() => addApplication(application)} key={canonicalPath}>
                      <span className="app-monogram" aria-hidden="true">{application.displayName.slice(0, 1).toUpperCase()}</span>
                      <span className="app-copy"><strong>{application.displayName}</strong><span title={application.executablePath}>{application.executablePath}</span></span>
                      <span className="picker-row-state">{added ? "Добавлено" : draft.defaultRoute === "direct" ? "Через VPN" : "Напрямую"}</span>
                    </button>
                  );
                }) : <div className="empty-state compact-empty"><SearchIcon size={22} /><strong>Приложения не найдены</strong><span>{pickerSearch ? "Измените запрос." : "Запустите приложение и откройте список снова."}</span></div>}
              </div> : null}
            </>
          )}
        </Dialog>
      ) : null}
      {trafficEditor ? (
        <Dialog title={trafficEditorOriginalId ? "Изменить правило трафика" : "Добавить правило трафика"} description="Правило применяется только после нажатия «Применить»." onClose={closeTrafficEditor}
          actions={<><button className="secondary-button" type="button" onClick={closeTrafficEditor}>Отмена</button><button className="primary-button dialog-primary" type="submit" form="traffic-rule-form">Применить</button></>}>
          <form id="traffic-rule-form" className="traffic-rule-form" onSubmit={(event) => { event.preventDefault(); applyTrafficEditor(); }}>
            <label className="dialog-field"><span>Сеть</span><select aria-label="Сеть" value={trafficEditor.network} data-autofocus onChange={(event) => { setTrafficEditor({ ...trafficEditor, network: event.target.value as TrafficRule["network"] }); setTrafficEditorError(""); }}><option value="udp">UDP</option><option value="tcp">TCP</option></select></label>
            <label className="dialog-field"><span>Порт</span><input type="number" inputMode="numeric" min={1} max={65535} value={trafficEditor.port} aria-invalid={Boolean(trafficEditorError)} aria-describedby={trafficEditorError ? "traffic-rule-error" : undefined} onChange={(event) => { setTrafficEditor({ ...trafficEditor, port: Number(event.target.value) }); setTrafficEditorError(""); }} /></label>
            <label className="dialog-field"><span>Действие</span><select aria-label="Действие" value={trafficEditor.action} onChange={(event) => setTrafficEditor({ ...trafficEditor, action: event.target.value as TrafficRule["action"] })}><option value="block">Блокировать</option><option value="direct">Напрямую</option><option value="vpn">Через VPN</option></select></label>
            <label className="paths-toggle"><input type="checkbox" checked={trafficEditor.enabled} onChange={(event) => setTrafficEditor({ ...trafficEditor, enabled: event.target.checked })} />Правило включено</label>
          </form>
          {trafficEditorError ? <p id="traffic-rule-error" className="field-error" role="alert">{trafficEditorError}</p> : null}
        </Dialog>
      ) : null}
    </div>
  );
}

function SettingsPage({ headingRef, draft, onDraftChange, onReset, saveState, resetDisabled, actionFailure, onClearFailure }: {
  headingRef: React.RefObject<HTMLHeadingElement | null>;
  draft: SettingsConfig;
  onDraftChange: (settings: SettingsConfig) => void;
  onReset: () => void;
  saveState: SaveFeedback;
  resetDisabled: boolean;
  actionFailure: ActionFailure | null;
  onClearFailure: () => void;
}) {
  const update = useAppUpdates();
  const updateMessage = update.status === "checking" ? "Проверяем выпуск…"
    : update.status === "available" ? `Доступна версия ${update.latestVersion}`
      : update.status === "upToDate" ? "Установлена актуальная версия"
        : update.status === "noRelease" ? "Опубликованных выпусков пока нет"
          : update.status === "error" ? "Не удалось проверить обновления"
            : update.status === "unavailable" ? "Проверка доступна в приложении RouteDeck"
              : "Проверка ещё не выполнялась";
  return (
    <div className="page settings-page">
      <div className="page-title-row"><h1 ref={headingRef} tabIndex={-1}>Настройки</h1><SaveState state={saveState} /></div>
      <ActionFailureNotice failure={actionFailure} page="settings" onClear={onClearFailure} />
      <section className="card settings-group lean-settings">
        <h2>Интерфейс</h2>
        <label className="field-row"><span><strong>Тема</strong></span><select aria-label="Тема" value={draft.theme} onChange={(event) => onDraftChange({ ...draft, theme: event.target.value as SettingsConfig["theme"] })}><option value="dark">Тёмная</option><option value="light">Светлая</option><option value="system">Как в Windows</option></select></label>
      </section>
      <section className="card settings-group lean-settings">
        <h2>Подписки</h2>
        <label className="field-row"><span><strong>Автообновление</strong></span><select aria-label="Автообновление подписок" value={draft.subscriptionRefreshHours} onChange={(event) => onDraftChange({ ...draft, subscriptionRefreshHours: Number(event.target.value) as SettingsConfig["subscriptionRefreshHours"] })}><option value={0}>Выключено</option><option value={6}>Раз в 6 часов</option><option value={24}>Раз в сутки</option></select></label>
        <p className="settings-explanation">Работает, пока RouteDeck открыт и отключён. Во время подключения обновление откладывается, чтобы не прерывать сеанс. Вручную обновить можно в списке серверов.</p>
      </section>
      <section className="card settings-group lean-settings update-settings" aria-labelledby="app-updates-title">
        <div className="settings-card-heading"><div><h2 id="app-updates-title">Обновления RouteDeck</h2>{update.currentVersion ? <small>Версия {update.currentVersion}</small> : null}</div><button className="secondary-button compact-action" type="button" disabled={update.status === "checking" || update.status === "unavailable"} aria-busy={update.status === "checking"} onClick={() => { void appUpdateMonitor.check(false); }}>{update.status === "checking" ? <LoaderIcon size={17} /> : <RefreshIcon size={17} />}{update.status === "error" ? "Повторить" : "Проверить"}</button></div>
        <p className="update-status" role="status" aria-live="polite">{updateMessage}</p>
        {update.status === "available" ? <><p className="settings-explanation">Обновление устанавливается вручную: скачайте portable-выпуск и замените текущие файлы после закрытия RouteDeck.</p><button className="primary-button compact-action" type="button" onClick={() => { void appUpdateMonitor.openReleases().catch(() => undefined); }}>Скачать на GitHub</button></> : null}
        <label className="paths-toggle"><input type="checkbox" checked={update.automatic} disabled={update.status === "unavailable"} onChange={(event) => appUpdateMonitor.setAutomatic(event.target.checked)} />Проверять автоматически раз в 6 часов</label>
      </section>
      <details className="card settings-details">
        <summary>Как устроено подключение</summary>
        <dl><div><dt>Локальные порты</dt><dd>Свободные порты выбираются автоматически.</dd></div><div><dt>Другие VPN</dt><dd>RouteDeck не заменяет чужие настройки системного прокси.</dd></div><div><dt>TUN</dt><dd>Windows запрашивает права при подключении. Постоянная служба не устанавливается.</dd></div></dl>
      </details>
      <details className="card settings-details reset-details">
        <summary>Сброс приложения</summary>
        <p>Удаляет все серверы, подписки, правила и настройки RouteDeck. Активное соединение будет остановлено.</p>
        <button className="danger-button compact-action" type="button" disabled={resetDisabled} onClick={onReset}>Сбросить RouteDeck…</button>
      </details>
    </div>
  );
}

function DiagnosticsPage({ snapshot, headingRef, onToast, runAsyncAction, actionFailure, onClearFailure, onClearStaleProxy }: {
  snapshot: ControllerSnapshot;
  headingRef: React.RefObject<HTMLHeadingElement | null>;
  onToast: (message: string, kind?: ToastKind) => void;
  runAsyncAction: RunAsyncAction;
  actionFailure: ActionFailure | null;
  onClearFailure: () => void;
  onClearStaleProxy: () => void;
}) {
  const [checking, setChecking] = useState(false);
  const [copying, setCopying] = useState(false);
  const run = () => {
    void runAsyncAction({
      page: "diagnostics",
      title: "Не удалось обновить состояние",
      setBusy: setChecking,
      action: controller.runDiagnostics,
      retry: run,
    });
  };
  const copyReport = () => {
    void runAsyncAction({
      page: "diagnostics",
      title: "Не удалось скопировать отчёт",
      setBusy: setCopying,
      action: () => navigator.clipboard.writeText(controller.getSanitizedReport()),
      retry: copyReport,
      onSuccess: () => onToast("Отчёт скопирован", "success"),
    });
  };
  const externalNotice: AppNotice = {
    id: "external-vpn",
    kind: "warning",
    title: "Обнаружен другой VPN",
    body: `${snapshot.environment.otherVpnName ?? "Другой клиент"} использует системный прокси ${snapshot.environment.externalProxyEndpoint ?? "Windows"}. RouteDeck не изменяет его без явного выбора.`,
    redactedDetail: "Локальные прокси могут работать на разных портах, но эффективный системный прокси Windows только один.",
  };
  const proxy = snapshot.diagnostics.systemProxy;
  const proxyPresentation = {
    disabled: ["Отключён", "Прокси Windows не используется."],
    owned: ["Принадлежит RouteDeck", "Системная настройка принадлежит текущему подключению RouteDeck."],
    foreignActive: ["Используется другой программой", "По сохранённому адресу есть локальный слушатель. RouteDeck не будет менять эти настройки."],
    stale: ["Не отвечает", "Прокси Windows указывает на локальный порт, на котором нет работающего слушателя."],
    conflict: ["Требует проверки", "Настройки неоднозначны или не совпадают с сохранённым состоянием. Автоматическая очистка недоступна."],
    unavailable: ["Не удалось проверить", "Windows не вернула достоверное состояние системного прокси."],
  }[proxy.state];
  return (
    <div className="page">
      <div className="page-title-row"><div><p className="overline">Состояние приложения</p><h1 ref={headingRef} tabIndex={-1}>Диагностика</h1></div>{snapshot.diagnostics.snapshotReceivedAt ? <span className="quiet-badge">Обновлено {snapshot.diagnostics.snapshotReceivedAt}</span> : null}</div>
      <ActionFailureNotice failure={actionFailure} page="diagnostics" onClear={onClearFailure} />
      <p className="field-help">Здесь показано последнее состояние подключения. Обновление не запускает новое сетевое подключение.</p>
      <button className="primary-button" type="button" disabled={checking || snapshot.diagnostics.running} aria-busy={checking || snapshot.diagnostics.running} onClick={run}>{checking || snapshot.diagnostics.running ? <LoaderIcon size={20} /> : <ActivityIcon size={20} />}{checking || snapshot.diagnostics.running ? "Обновляем…" : "Обновить состояние"}</button>
      {snapshot.environment.otherVpnDetected ? <OpaqueNotice notice={externalNotice} primaryAction={{ label: "Обновить", onClick: run }} /> : null}
      <section className="card system-proxy-card" aria-labelledby="system-proxy-title">
        <div className="system-proxy-card__heading"><div><p className="overline">Windows</p><h2 id="system-proxy-title">Системный прокси</h2></div><span className="quiet-badge" data-state={proxy.state}>{proxyPresentation[0]}</span></div>
        <p>{proxyPresentation[1]}</p>
        {proxy.endpoint ? <dl className="diagnostic-facts"><div><dt>Адрес</dt><dd>{proxy.endpoint}</dd></div><div><dt>Локальный слушатель</dt><dd>{proxy.state === "stale" ? "Не найден" : proxy.state === "foreignActive" ? "Обнаружен" : "Не проверялся"}</dd></div></dl> : null}
        {proxy.state === "stale" && proxy.cleanupToken ? <button className="danger-button compact-action" type="button" disabled={checking || snapshot.diagnostics.running || Boolean(snapshot.switching) || !(snapshot.phase === "disconnected" || (snapshot.phase === "connected" && snapshot.activeMode === "tun"))} onClick={onClearStaleProxy}>Отключить неработающий прокси</button> : null}
      </section>
      <ProofCard proofs={snapshot.diagnostics.steps} title="Проверки" />
      {snapshot.diagnostics.snapshotReceivedAt ? <p className="diagnostic-duration">Состояние обновлено в {snapshot.diagnostics.snapshotReceivedAt}; время отдельных этапов отображается только при наличии данных.</p> : null}
      <button className="secondary-button full-width" type="button" disabled={copying} aria-busy={copying} onClick={copyReport}>{copying ? <LoaderIcon size={19} /> : <CopyIcon size={19} />}{copying ? "Копируем…" : "Копировать отчёт"}</button>
      <details className="card log-viewer"><summary>Технический журнал</summary><div className="details-body"><p className="field-help">Личные данные удаляются из отчёта автоматически.</p><pre>{snapshot.diagnostics.sanitizedLog.join("\n")}</pre></div></details>
    </div>
  );
}

function Dialog({ title, description, focusKey, onClose, busy = false, closeDisabled = false, children, actions }: { title: string; description?: string; focusKey?: string; onClose: () => void; busy?: boolean; closeDisabled?: boolean; children: ReactNode; actions: ReactNode }) {
  const dialogRef = useRef<HTMLDivElement>(null);
  const previouslyFocusedRef = useRef<HTMLElement | null>(null);

  useEffect(() => {
    previouslyFocusedRef.current = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    const shell = document.querySelector<HTMLElement>(".app-shell");
    const previousInert = shell?.inert ?? false;
    if (shell) shell.inert = true;
    return () => {
      if (shell) shell.inert = previousInert;
      if (previouslyFocusedRef.current?.isConnected && previouslyFocusedRef.current.getClientRects().length) previouslyFocusedRef.current.focus({ preventScroll: true });
    };
  }, []);

  useEffect(() => {
    const dialog = dialogRef.current;
    const focusable = busy || closeDisabled
      ? dialog?.querySelector<HTMLElement>("[data-dialog-busy-focus]")
      : dialog?.querySelector<HTMLElement>("[data-error-autofocus]:not(:disabled)")
      ?? dialog?.querySelector<HTMLElement>("[data-autofocus]:not(:disabled)")
      ?? dialog?.querySelector<HTMLElement>("button:not(:disabled), input:not(:disabled), select:not(:disabled), textarea:not(:disabled)");
    const frame = window.requestAnimationFrame(() => focusable?.focus({ preventScroll: true }));
    return () => window.cancelAnimationFrame(frame);
  }, [busy, closeDisabled, focusKey]);

  useEffect(() => {
    const dialog = dialogRef.current;
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        event.preventDefault();
        if (!closeDisabled) onClose();
        return;
      }
      if (event.key !== "Tab" || !dialog) return;
      const items = Array.from(dialog.querySelectorAll<HTMLElement>("button:not(:disabled), input:not(:disabled), select:not(:disabled), textarea:not(:disabled), [tabindex]:not([tabindex='-1'])")).filter((item) => item.getClientRects().length > 0);
      const first = items[0];
      const last = items[items.length - 1];
      const busyTarget = dialog.querySelector<HTMLElement>("[data-dialog-busy-focus]");
      if (!first || !last) {
        if (busyTarget) {
          event.preventDefault();
          busyTarget.focus({ preventScroll: true });
        }
        return;
      }
      if (document.activeElement === busyTarget) {
        event.preventDefault();
        (event.shiftKey ? last : first).focus({ preventScroll: true });
        return;
      }
      if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last.focus({ preventScroll: true }); }
      if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first.focus({ preventScroll: true }); }
    };
    const onFocusIn = (event: FocusEvent) => {
      if (!dialog || dialog.contains(event.target as Node | null)) return;
      const target = busy || closeDisabled
        ? dialog.querySelector<HTMLElement>("[data-dialog-busy-focus]")
        : dialog.querySelector<HTMLElement>("[data-error-autofocus]:not(:disabled)")
        ?? dialog.querySelector<HTMLElement>("[data-autofocus]:not(:disabled)")
        ?? dialog.querySelector<HTMLElement>("button:not(:disabled), input:not(:disabled), select:not(:disabled), textarea:not(:disabled)");
      target?.focus({ preventScroll: true });
    };
    document.addEventListener("keydown", onKeyDown);
    document.addEventListener("focusin", onFocusIn);
    return () => {
      document.removeEventListener("keydown", onKeyDown);
      document.removeEventListener("focusin", onFocusIn);
    };
  }, [busy, closeDisabled, onClose]);

  return createPortal(
    <div className="dialog-scrim" role="presentation">
      <div className="dialog" ref={dialogRef} role="dialog" aria-modal="true" aria-labelledby="dialog-title" aria-describedby={description ? "dialog-description" : undefined}>
        <div className="dialog-header"><div><h2 id="dialog-title">{title}</h2>{description ? <p id="dialog-description">{description}</p> : null}</div><button className="icon-button" type="button" aria-label="Закрыть окно" title={closeDisabled ? "Дождитесь завершения импорта" : "Закрыть"} disabled={closeDisabled} onClick={onClose}><XIcon size={19} /></button></div>
        <div className="dialog-content">{children}</div>
        <div className="dialog-actions">{actions}</div>
      </div>
    </div>, document.body
  );
}

function Toast({ toast, onClose, onPausedChange }: { toast: ToastState; onClose: () => void; onPausedChange: (paused: boolean) => void }) {
  const [hovered, setHovered] = useState(false);
  const [focusWithin, setFocusWithin] = useState(false);
  const Icon = toast.kind === "warning" ? WarningIcon : toast.kind === "info" ? InfoIcon : CheckIcon;
  useEffect(() => onPausedChange(hovered || focusWithin), [focusWithin, hovered, onPausedChange]);
  useEffect(() => () => onPausedChange(false), [onPausedChange]);
  return createPortal(
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
    </div>, document.body
  );
}

export default function App() {
  const snapshot = useController();
  const appUpdate = useAppUpdates();
  const [activePage, setActivePage] = useState<Destination>("home");
  const [dialog, setDialog] = useState<DialogKind>(null);
  const [returnAfterPick, setReturnAfterPick] = useState(false);
  const [sourceAction, setSourceAction] = useState<Server | null>(null);
  const [sourceBusy, setSourceBusy] = useState(false);
  const [backgroundRefreshing, setBackgroundRefreshing] = useState(false);
  const [sourceReconnect, setSourceReconnect] = useState(false);
  const [sourceError, setSourceError] = useState("");
  const refreshUrlRef = useRef<HTMLInputElement>(null);
  const serversHeadingRef = useRef<HTMLHeadingElement>(null);
  const [search, setSearch] = useState("");
  const routingSave = useAutoSave(snapshot.routing, controller.applyRouting);
  const settingsSave = useAutoSave(snapshot.settings, controller.saveSettings);
  const routingDraft = routingSave.draft;
  const settingsDraft = settingsSave.draft;
  const [toast, setToast] = useState<ToastState | null>(null);
  const [toastPaused, setToastPaused] = useState(false);
  const [actionFailure, setActionFailure] = useState<ActionFailure | null>(null);
  const [importError, setImportError] = useState("");
  const [importing, setImporting] = useState(false);
  const [importKind, setImportKind] = useState<ImportKind>("manual");
  const [importPreview, setImportPreview] = useState<SubscriptionPreview | null>(null);
  const [committingImport, setCommittingImport] = useState(false);
  const [proxyCleanupToken, setProxyCleanupToken] = useState<string | null>(null);
  const [proxyCleanupBusy, setProxyCleanupBusy] = useState(false);
  const mainRef = useRef<HTMLElement>(null);
  const headingRef = useRef<HTMLHeadingElement>(null);
  const subscriptionInputRef = useRef<HTMLInputElement>(null);
  const serverInputRef = useRef<HTMLTextAreaElement>(null);
  const sourceNameRef = useRef<HTMLInputElement>(null);
  const importGeneration = useRef(0);
  const scrollPositions = useRef<Record<Destination, number>>({ home: 0, servers: 0, routing: 0, settings: 0, diagnostics: 0 });

  useEffect(() => {
    if (!snapshot.isDemo) void appUpdateMonitor.start();
  }, [snapshot.isDemo]);

  useEffect(() => {
    const attempts = new Map<string, number>();
    let refreshing = false;
    const tick = () => {
      if (refreshing) return;
      const now = Date.now();
      const sourceId = nextSubscriptionRefresh(controller.getSnapshot(), attempts, now);
      if (!sourceId) return;
      attempts.set(sourceId, now);
      refreshing = true;
      setBackgroundRefreshing(true);
      void controller.refreshSource(sourceId, undefined, true).catch(() => {
        // Manual refresh exposes actionable errors. A failed background fetch
        // preserves the source and waits the full interval before trying again.
      }).finally(() => { refreshing = false; setBackgroundRefreshing(false); });
    };
    const timer = window.setInterval(tick, 60_000);
    return () => window.clearInterval(timer);
  }, []);

  const clearSubscriptionUrl = useCallback(() => {
    if (subscriptionInputRef.current) subscriptionInputRef.current.value = "";
    if (serverInputRef.current) serverInputRef.current.value = "";
  }, []);

  const invalidateImport = useCallback(() => {
    importGeneration.current += 1;
    controller.cancelImportPreview();
    setImporting(false);
    setImportPreview(null);
  }, []);

  const closeDialog = useCallback(() => {
    invalidateImport();
    setDialog(null);
    setSourceAction(null);
    setSourceError("");
    if (refreshUrlRef.current) refreshUrlRef.current.value = "";
    setImportError("");
    setProxyCleanupToken(null);
    clearSubscriptionUrl();
  }, [clearSubscriptionUrl, invalidateImport]);

  useEffect(() => {
    if (dialog === "clear-stale-proxy" && snapshot.diagnostics.systemProxy.cleanupToken !== proxyCleanupToken) {
      setDialog(null);
      setProxyCleanupToken(null);
    }
  }, [dialog, proxyCleanupToken, snapshot.diagnostics.systemProxy.cleanupToken]);

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
            redactedDetail: publicError.redactedDetail ?? "Повторите попытку или откройте диагностику.",
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
    setToast(null);
    setReturnAfterPick(false);
    setActivePage(destination);
  }, [activePage]);

  useEffect(() => {
    const frame = window.requestAnimationFrame(() => {
      (activePage === "servers" ? serversHeadingRef.current : headingRef.current)?.focus({ preventScroll: true });
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
      syncWindowTheme(theme);
    };
    applyTheme();
    query.addEventListener("change", applyTheme);
    return () => query.removeEventListener("change", applyTheme);
  }, [settingsDraft.theme]);

  useEffect(() => {
    // Suppress WebView navigation/printing menus; application handlers still receive
    // the event, and keyboard editing shortcuts retain their normal behavior.
    const suppressBrowserMenu = (event: MouseEvent) => event.preventDefault();
    document.addEventListener("contextmenu", suppressBrowserMenu);
    return () => document.removeEventListener("contextmenu", suppressBrowserMenu);
  }, []);

  const handleModeChange = (mode: ConnectionMode) => {
    if (mode === snapshot.mode) return;
    void runAsyncAction({ page: "home", title: "Не удалось сменить режим", action: () => controller.setMode(mode), retry: retryConnection });
  };

  const openServerPicker = (destination: Destination) => {
    navigate(destination);
    if (destination === "servers") setReturnAfterPick(true);
  };

  const selectServer = (serverId: string) => {
    const returnHome = returnAfterPick;
    if (returnHome) navigate("home");
    void runAsyncAction({ page: returnHome ? "home" : "servers", title: "Не удалось переключить сервер", action: () => controller.selectServer(serverId) });
  };

  const refreshSource = (server: Server, url?: string) => {
    void runAsyncAction({
      page: "servers", title: "Не удалось обновить подписку", setBusy: setSourceBusy,
      action: () => controller.refreshSource(server.sourceId!, url), errorPresentation: dialog === "refresh-source" ? "inline" : "persistent",
      onError: (error) => setSourceError(error.message),
      onSuccess: () => { if (dialog === "refresh-source") closeDialog(); else setSourceAction(null); showToast("Подписка обновлена"); },
    });
  };

  const requestSourceRefresh = (server: Server) => {
    setSourceReconnect(snapshot.servers.some((item) => item.sourceId === server.sourceId && item.id === snapshot.activeServerId));
    setSourceError(""); setSourceAction(server);
    if (server.sourceRefreshable) refreshSource(server);
    else setDialog("refresh-source");
  };

  const handleConnect = () => {
    setBackgroundRefreshing(false);
    void runAsyncAction({
      page: "home",
      title: snapshot.mode === "tun" ? "Не удалось запустить TUN" : "Не удалось подключиться",
      action: () => controller.connect(),
      retry: handleConnect,
    });
  };

  const importSubscription = () => {
    const subscriptionUrl = (importKind === "subscription" ? subscriptionInputRef.current?.value : serverInputRef.current?.value)?.trim() ?? "";
    if (!subscriptionUrl) {
      setImportError(importKind === "subscription" ? "Вставьте ссылку на подписку." : "Вставьте ссылку сервера или конфигурацию.");
      window.requestAnimationFrame(() => (importKind === "subscription" ? subscriptionInputRef.current : serverInputRef.current)?.focus({ preventScroll: true }));
      return;
    }
    setImportError("");
    controller.cancelImportPreview();
    const generation = ++importGeneration.current;
    void runAsyncAction({
      page: "servers",
      title: "Не удалось прочитать источник",
      setBusy: (busy) => {
        if (generation === importGeneration.current) setImporting(busy);
      },
      action: async () => {
        const preview = await controller.previewSubscription({ type: importKind === "subscription" ? "url" : "clipboard", value: subscriptionUrl });
        if (generation !== importGeneration.current) return null;
        return preview;
      },
      errorPresentation: "persistent",
      onError: (publicError) => {
        if (generation !== importGeneration.current) return;
        setImportError(publicError.message);
      },
      onSuccess: (preview) => {
        if (!preview || generation !== importGeneration.current) return;
        clearSubscriptionUrl();
        setImportPreview(preview);
      },
    });
  };

  const confirmImport = () => {
    if (!importPreview || committingImport) return;
    const preview = importPreview;
    const sourceName = sourceNameRef.current?.value.trim() || undefined;
    void runAsyncAction({
      page: "servers",
      title: "Не удалось добавить серверы",
      setBusy: setCommittingImport,
      action: () => controller.commitSubscription(preview, sourceName),
      errorPresentation: "inline",
      onError: (publicError) => setImportError(publicError.message),
      onSuccess: () => {
        closeDialog();
        showToast(`Добавлено серверов: ${preview.nodeNames.length}`, "success");
      },
    });
  };

  const disconnect = () => {
    void runAsyncAction({
      page: "home",
      title: "Не удалось отключиться",
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

  const requestProxyCleanup = () => {
    const token = snapshot.diagnostics.systemProxy.cleanupToken;
    if (snapshot.diagnostics.systemProxy.state !== "stale" || !token) return;
    setProxyCleanupToken(token);
    setDialog("clear-stale-proxy");
  };

  const confirmProxyCleanup = () => {
    if (!proxyCleanupToken || proxyCleanupBusy) return;
    const token = proxyCleanupToken;
    void runAsyncAction({
      page: "diagnostics",
      title: "Не удалось отключить неработающий прокси",
      setBusy: setProxyCleanupBusy,
      errorPresentation: "persistent",
      action: async () => {
        try { await controller.clearStaleSystemProxy(token); }
        catch (error) {
          await controller.runDiagnostics().catch(() => undefined);
          throw error;
        }
      },
      onSuccess: () => { closeDialog(); showToast("Неработающий прокси Windows отключён", "success"); },
    });
  };

  const renderPage = () => {
    switch (activePage) {
      case "home":
        return <HomePage snapshot={snapshot} libraryBusy={(sourceBusy && !sourceReconnect) || backgroundRefreshing} headingRef={headingRef} onNavigate={openServerPicker} onModeChange={handleModeChange} onConnect={handleConnect} onDisconnect={disconnect} onRetry={retryConnection} onLatencyInfo={() => setDialog("latency-info")} actionFailure={actionFailure} onClearFailure={() => setActionFailure(null)} />;
      case "servers":
        return null;
      case "routing":
        return <RoutingPage snapshot={snapshot} headingRef={headingRef} draft={routingDraft} onDraftChange={routingSave.change} saveState={routingSave} />;
      case "settings":
        return <SettingsPage headingRef={headingRef} draft={settingsDraft} onDraftChange={settingsSave.change} saveState={settingsSave} resetDisabled={routingSave.running || settingsSave.running || (routingSave.pending && !routingSave.error) || (settingsSave.pending && !settingsSave.error) || Boolean(snapshot.switching)} onReset={() => setDialog("reset")} actionFailure={actionFailure} onClearFailure={() => setActionFailure(null)} />;
      case "diagnostics":
        return <DiagnosticsPage snapshot={snapshot} headingRef={headingRef} onToast={showToast} runAsyncAction={runAsyncAction} actionFailure={actionFailure} onClearFailure={() => setActionFailure(null)} onClearStaleProxy={requestProxyCleanup} />;
    }
  };

  return (
    <div className="app-shell" data-demo={snapshot.isDemo || undefined}>
      <header className="app-header">
        <div className="brand"><span className="brand-mark"><RoutingIcon size={20} /></span><span><strong>RouteDeck{appUpdate.currentVersion ? <span className="brand-version">v{appUpdate.currentVersion}</span> : null}</strong><small>VPN-клиент</small></span></div>
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
        <main className="app-main" ref={mainRef}>
          <div className="page-slot" hidden={activePage !== "servers"}>
            <ServersPage snapshot={snapshot} headingRef={serversHeadingRef} search={search} onSearch={setSearch}
              onImport={(kind) => { invalidateImport(); clearSubscriptionUrl(); setImportError(""); setImportKind(kind); setDialog("import"); }}
              onSelect={selectServer} picking={returnAfterPick} onBack={() => navigate("home")}
              onRefresh={requestSourceRefresh} onRemove={(server) => { setSourceAction(server); setSourceError(""); setDialog("remove-source"); }} sourceBusy={sourceBusy}
              actionFailure={actionFailure} onClearFailure={() => setActionFailure(null)} />
          </div>
          {activePage !== "servers" ? <div className="page-slot">{renderPage()}</div> : null}
        </main>
      </div>
      <Navigation active={activePage} onNavigate={navigate} variant="bottom" />
      {toast && !dialog ? <Toast toast={toast} onPausedChange={setToastPaused} onClose={() => { setToast(null); setToastPaused(false); }} /> : null}

      {dialog === "latency-info" ? <Dialog title="Отклик через VPN" onClose={closeDialog}
        description="Вы → выбранный VPN → Google. Измеряется ответ на короткий запрос через уже установленное соединение."
        actions={<button className="secondary-button" type="button" data-autofocus onClick={closeDialog}>Понятно</button>}>
        <p className="dialog-copy">Сначала устанавливаем соединение, затем выполняем три замера. Показываем медиану — среднее по порядку значение. DNS и установка TCP/TLS в эти три замера не входят.</p>
        <p className="dialog-copy">Это ориентир для работы через VPN, а не пинг до любой игры или сайта: у них свои серверы и маршруты. Если соединение для замера пришлось открыть заново, показываем «—».</p>
        <p className="dialog-copy">Замер появляется после первой фоновой проверки. Полная проверка доступности интернета сохраняется отдельно на странице «Статус».</p>
      </Dialog> : null}

      {dialog === "import" ? (
        <Dialog
          title={importPreview ? "Добавить в библиотеку" : importKind === "manual" ? "Добавить сервер" : "Добавить подписку"}
          description={importPreview ? "Проверьте состав новой группы перед добавлением." : importKind === "manual" ? "Вставьте ссылку сервера, несколько ссылок или JSON-конфигурацию." : "Вставьте HTTPS-ссылку на подписку от провайдера."}
          focusKey={importPreview ? "import-preview" : importKind}
          onClose={closeDialog}
          busy={importing || committingImport}
          closeDisabled={committingImport}
          actions={<>
            <button className="secondary-button" type="button" disabled={committingImport} onClick={closeDialog}>Отмена</button>
            <button className="primary-button dialog-primary" type="submit" form="subscription-import-form" disabled={importing || committingImport || Boolean(importPreview && !importPreview.nodeNames.length)} aria-busy={importing || committingImport}>{importing || committingImport ? <LoaderIcon size={19} /> : importPreview ? <PlusIcon size={19} /> : <ImportIcon size={19} />}{committingImport ? "Добавляем…" : importing ? "Проверяем…" : importPreview ? "Добавить" : "Продолжить"}</button>
          </>}
        >
          <form id="subscription-import-form" className="import-form" onSubmit={(event) => { event.preventDefault(); if (importPreview) confirmImport(); else importSubscription(); }}>
            {importing || committingImport ? <p className="persistent-hint" role="status" aria-live="polite" tabIndex={-1} data-dialog-busy-focus><LoaderIcon size={17} />{committingImport ? "Сохраняем группу…" : importKind === "subscription" ? "Загружаем и проверяем подписку…" : "Проверяем конфигурацию…"}</p> : null}
            <div className="dialog-field" hidden={Boolean(importPreview)}>
              {importKind === "subscription" ? <>
                <label htmlFor="subscription-url">Ссылка на подписку</label>
                <input ref={subscriptionInputRef} id="subscription-url" type="url" inputMode="url" autoComplete="off" spellCheck={false} defaultValue="" disabled={importing || Boolean(importPreview)} data-autofocus data-error-autofocus={importError ? "true" : undefined} aria-invalid={Boolean(importError)} aria-describedby={importError ? "import-error" : "import-source-help"} placeholder="https://provider.example/subscription" onInput={() => setImportError("")} />
              </> : <>
                <label htmlFor="server-content">Ссылка или конфигурация сервера</label>
                <textarea ref={serverInputRef} id="server-content" rows={4} autoComplete="off" spellCheck={false} defaultValue="" disabled={importing || Boolean(importPreview)} data-autofocus data-error-autofocus={importError ? "true" : undefined} aria-invalid={Boolean(importError)} aria-describedby={importError ? "import-error" : "import-source-help"} placeholder="naive+https://user:password@server.example:443#Мой сервер" onInput={() => setImportError("")} />
              </>}
              <small id="import-source-help">{importKind === "manual" ? "VLESS, Hysteria2, Naive HTTPS / QUIC; JSON sing-box. Каждая ссылка — с новой строки." : "Ссылка может содержать ключ доступа. Не передавайте её другим."}</small>
            </div>
            {importPreview ? <section className="import-preview" aria-label="Состав новой группы">
              <h3 tabIndex={-1} data-autofocus>Серверов для добавления: {importPreview.nodeNames.length}</h3>
              <div className="import-protocols">{importPreview.supported.map((item) => <span className="quiet-badge" key={item.protocol}>{item.protocol} · {item.count}</span>)}</div>
              {importPreview.unsupportedCount ? <p className="import-warning"><WarningIcon size={17} />Не будут добавлены неподдерживаемые записи: {importPreview.unsupportedCount}.</p> : null}
              <p className="field-help">Это проверка формата. Доступность сервера проверяется при подключении.</p>
              <button className="text-button" type="button" disabled={committingImport} onClick={() => { invalidateImport(); setImportError(""); }}>Вставить другой источник</button>
            </section> : null}
            <div className="dialog-field">
              <label htmlFor="source-name">Название группы <span className="optional-label">необязательно</span></label>
              <input ref={sourceNameRef} id="source-name" type="text" autoComplete="off" maxLength={80} defaultValue="" disabled={importing || committingImport} placeholder={importKind === "manual" ? "Например, Мой Naive" : "Например, Основная подписка"} onInput={() => setImportError("")} />
            </div>
            {importError ? <p id="import-error" className="field-error" role="alert">{importError}</p> : null}
            {snapshot.phase !== "disconnected" && snapshot.phase !== "failed" ? <p className="persistent-hint"><InfoIcon size={17} />Перед добавлением отключите соединение RouteDeck.</p> : null}
          </form>
        </Dialog>
      ) : null}

      {dialog === "refresh-source" && sourceAction ? (
        <Dialog title="Обновить подписку" description="У этой группы ещё нет сохранённой ссылки. Укажите её один раз для следующих обновлений." onClose={closeDialog} busy={sourceBusy} closeDisabled={sourceBusy}
          actions={<><button className="secondary-button" type="button" disabled={sourceBusy} onClick={closeDialog}>Отмена</button><button className="primary-button dialog-primary" type="submit" form="refresh-source-form" disabled={sourceBusy}>{sourceBusy ? "Обновляем…" : "Обновить"}</button></>}>
          <form id="refresh-source-form" onSubmit={(event) => { event.preventDefault(); const url = refreshUrlRef.current?.value.trim(); if (!url) { setSourceError("Вставьте HTTPS-ссылку на подписку."); return; } refreshSource(sourceAction, url); }}>
            <div className="dialog-field"><label htmlFor="refresh-url">Ссылка на подписку</label><input id="refresh-url" ref={refreshUrlRef} type="url" autoComplete="off" spellCheck={false} defaultValue="" data-autofocus disabled={sourceBusy} placeholder="https://provider.example/subscription" /></div>
          </form>
          {sourceBusy ? <p role="status" tabIndex={-1} data-dialog-busy-focus>Загружаем и проверяем подписку…</p> : null}
          {sourceError ? <p className="field-error" role="alert">{sourceError}</p> : null}
        </Dialog>
      ) : null}

      {dialog === "remove-source" && sourceAction ? (
        <Dialog title="Удалить группу?" description={`«${sourceAction.source}» и её серверы будут удалены из библиотеки.`} onClose={closeDialog} busy={sourceBusy} closeDisabled={sourceBusy}
          actions={<><button className="secondary-button" type="button" data-autofocus disabled={sourceBusy} onClick={closeDialog}>Отмена</button><button className="danger-button" type="button" disabled={sourceBusy} onClick={() => { void runAsyncAction({ page: "servers", title: "Не удалось удалить группу", setBusy: setSourceBusy, errorPresentation: "inline", action: () => controller.removeSource(sourceAction.sourceId!), onError: (error) => setSourceError(error.message), onSuccess: () => { closeDialog(); showToast("Группа удалена", "info"); } }); }}>{sourceBusy ? "Удаляем…" : "Удалить группу"}</button></>}>
          <p className="dialog-copy">{snapshot.servers.some((server) => server.sourceId === sourceAction.sourceId && server.id === snapshot.activeServerId) ? "Текущее соединение будет отключено. Вы сможете выбрать другой сервер." : "Другие группы останутся в библиотеке."}</p>
          {sourceBusy ? <p role="status" tabIndex={-1} data-dialog-busy-focus>Сохраняем изменения…</p> : null}
          {sourceError ? <p className="field-error" role="alert">{sourceError}</p> : null}
        </Dialog>
      ) : null}

      {dialog === "reset" ? (
        <Dialog
          title="Сбросить локальное состояние?"
          description="Будут удалены все серверы, подписки, правила и настройки RouteDeck. Это действие нельзя отменить."
          onClose={closeDialog}
          actions={<><button className="secondary-button" type="button" data-autofocus onClick={closeDialog}>Отмена</button><button className="danger-button" type="button" onClick={() => { closeDialog(); void runAsyncAction({ page: "settings", title: "Не удалось сбросить локальное состояние", action: controller.resetLocalState, retry: () => setDialog("reset"), onSuccess: () => { routingSave.discard(); settingsSave.discard(); showToast("Локальное состояние сброшено", "info"); } }); }}><TrashIcon size={19} />Сбросить RouteDeck</button></>}
        ><p className="dialog-copy">Активное подключение будет остановлено. RouteDeck восстановит только принадлежащие ему сетевые настройки; настройки другой программы не перезаписываются.</p></Dialog>
      ) : null}
      {dialog === "clear-stale-proxy" && proxyCleanupToken ? (
        <Dialog title="Отключить неработающий прокси?" description="RouteDeck ещё раз проверит сохранённое состояние перед изменением." onClose={closeDialog} busy={proxyCleanupBusy} closeDisabled={proxyCleanupBusy}
          actions={<><button className="secondary-button" type="button" data-autofocus disabled={proxyCleanupBusy} onClick={closeDialog}>Отмена</button><button className="danger-button" type="button" disabled={proxyCleanupBusy} onClick={confirmProxyCleanup}>{proxyCleanupBusy ? <LoaderIcon size={19} /> : null}{proxyCleanupBusy ? "Отключаем…" : "Отключить прокси"}</button></>}>
          <p className="dialog-copy">Сохранённая настройка системного прокси Windows будет отключена. RouteDeck не завершает работающие процессы VPN или прокси-программ.</p>
          {proxyCleanupBusy ? <p role="status" aria-live="polite" tabIndex={-1} data-dialog-busy-focus><LoaderIcon size={17} />Проверяем состояние и отключаем прокси…</p> : null}
        </Dialog>
      ) : null}
    </div>
  );
}

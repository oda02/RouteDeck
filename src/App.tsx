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
import { controller } from "./controller";
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
  type SettingsConfig,
} from "./model";

type DialogKind = "import" | "mode-change" | "reset" | null;
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
  const localDiagnostic = snapshot.runtimeScope === "local-only";
  const server = snapshot.servers.find((item) => item.id === snapshot.selectedServerId);
  const pending = pendingPhases.includes(snapshot.phase);
  const hasLiveCore = ["connected", "degraded", "blocked-by-conflict"].includes(snapshot.phase);
  const buttonLabel = pending
    ? phaseLabels[snapshot.phase]
    : hasLiveCore
      ? localDiagnostic ? "Остановить локальный прокси" : "Отключить"
      : snapshot.phase === "failed" ? "Повторить" : "Подключить";
  const boundaryNotice = snapshot.notice?.id === "backend-unavailable" || snapshot.notice?.id === "backend-response-invalid";
  const vpnApps = snapshot.routing.apps.filter((app) => app.route === "vpn");
  const directApps = snapshot.routing.apps.filter((app) => app.route === "direct");
  const routeMode = snapshot.mode === "tun" ? "TUN" : "Прокси Windows";
  const routeSummary = snapshot.routing.defaultRoute === "direct"
    ? `${routeMode}: напрямую · ${vpnApps.length} ${vpnApps.length === 1 ? "исключение" : "исключений"} через VPN`
    : `${routeMode}: через VPN · ${directApps.length} исключений напрямую`;

  return (
    <div className="page home-page">
      <div className="page-title-row">
        <div>
          <p className="overline">Управление соединением</p>
          <h1 ref={headingRef} tabIndex={-1}>Главная</h1>
        </div>
        <span className="mode-readout">{localDiagnostic ? "Локальная диагностика" : snapshot.mode === "proxy" ? "System Proxy" : "TUN"}</span>
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
          disabled={pending || localDiagnostic}
        />
        <div className="persistent-hint" data-kind="info">
          {snapshot.mode === "proxy" ? <InfoIcon size={18} /> : <ShieldIcon size={18} />}
          <p>
            {localDiagnostic
              ? "Диагностическая сессия проверяет локальные HTTP/SOCKS-порты и не меняет настройки Windows."
              : snapshot.mode === "tun"
                ? "Перехватывает весь IP-трафик через виртуальный адаптер. При каждом подключении Windows покажет стандартный запрос прав."
                : "Применяет общий маршрут и исключения к TCP-трафику приложений, которые используют прокси Windows."}
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
          onClose={boundaryNotice ? undefined : controller.dismissNotice}
          primaryAction={boundaryNotice ? undefined : { label: "Повторить проверку", onClick: onRetry }}
          secondaryAction={{ label: "Открыть диагностику", onClick: () => onNavigate("diagnostics") }}
        />
      ) : null}

      <button className="summary-card" type="button" onClick={() => onNavigate("routing")}>
        <span className="summary-icon"><RoutingIcon size={20} /></span>
        <span className="selection-copy">
          <span className="selection-label">Маршрутизация</span>
          <strong>{routeSummary}</strong>
          <span>{snapshot.mode === "tun" ? "Общий маршрут и исключения для приложений" : "Маршрут и исключения для proxy-aware TCP; UDP и QUIC не перехватываются"}</span>
        </span>
        <ChevronRightIcon size={20} />
      </button>
    </div>
  );
}

function ServersPage({ snapshot, headingRef, search, onSearch, onImport, actionFailure, onClearFailure }: {
  snapshot: ControllerSnapshot;
  headingRef: React.RefObject<HTMLHeadingElement | null>;
  search: string;
  onSearch: (value: string) => void;
  onImport: () => void;
  actionFailure: ActionFailure | null;
  onClearFailure: () => void;
}) {
  const filtered = useMemo(() => {
    const query = search.trim().toLocaleLowerCase("ru-RU");
    return snapshot.servers.filter((server) => !query || `${server.country} ${server.name} ${server.protocol}`.toLocaleLowerCase("ru-RU").includes(query));
  }, [search, snapshot.servers]);

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
  const [pickerOpen, setPickerOpen] = useState(false);
  const [pickerLoading, setPickerLoading] = useState(false);
  const [pickerSearch, setPickerSearch] = useState("");
  const [pickerError, setPickerError] = useState("");
  const [runningApplications, setRunningApplications] = useState<RunningApplication[]>([]);
  const deferredPickerSearch = useDeferredValue(pickerSearch);
  const connectionActive = snapshot.phase !== "disconnected" && snapshot.phase !== "failed";
  const dirty = JSON.stringify(draft) !== JSON.stringify(snapshot.routing);
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

  const openApplicationPicker = () => {
    if (connectionActive || pickerLoading) return;
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

  return (
    <div className="page">
      <div className="page-title-row">
        <div><p className="overline">Политика трафика</p><h1 ref={headingRef} tabIndex={-1}>Маршрутизация</h1></div>
        {dirty ? <span className="quiet-badge warning-badge">Не сохранено</span> : <span className="quiet-badge">Готово</span>}
      </div>
      <ActionFailureNotice failure={actionFailure} page="routing" onClear={onClearFailure} />
      <section className="card">
        <div className="section-heading compact-heading"><div><p className="overline">Общая политика</p><h2>Маршрут по умолчанию</h2></div></div>
        <SegmentedControl
          label="Маршрут по умолчанию"
          value={draft.defaultRoute}
          options={[{ value: "direct", label: "Напрямую" }, { value: "vpn", label: "Через VPN" }]}
          onChange={(defaultRoute) => onDraftChange({ ...draft, defaultRoute })}
          disabled={connectionActive}
        />
        <p className="effective-summary"><RoutingIcon size={18} />{summary}</p>
      </section>

      <OpaqueNotice notice={snapshot.mode === "tun"
        ? { id: "tun-routing-scope", kind: "info", title: "Правила применятся при следующем подключении", body: "TUN использует общий маршрут для трафика Windows, а выбранные приложения — как исключения." }
        : { id: "proxy-routing-scope", kind: "info", title: "System Proxy: только приложения с поддержкой прокси", body: "Правила действуют для TCP-трафика приложений, которые используют прокси Windows. Программы, обходящие системный прокси, а также UDP, QUIC и системный DNS не перехватываются; для полного охвата используйте TUN." }} />

      <section className="card app-rules-card">
        <div className="section-heading">
          <div><p className="overline">Исключения</p><h2>Приложения</h2></div>
          <button className="secondary-button compact-action" type="button" disabled={connectionActive || pickerLoading} onClick={openApplicationPicker} title={connectionActive ? "Сначала отключитесь, чтобы изменить правила" : undefined}>
            {pickerLoading ? <LoaderIcon size={18} /> : <PlusIcon size={18} />}Добавить приложение
          </button>
        </div>
        <div className="app-rule-list">
          {draft.apps.length > 0 ? draft.apps.map((app) => (
            <div className="app-rule" key={app.id}>
              <div className="app-rule-heading">
                <span className="app-monogram" aria-hidden="true">{app.name.slice(0, 1).toUpperCase()}</span>
                <span className="app-copy"><strong>{app.name}</strong><span title={app.path}>{app.path}</span></span>
                <button className="icon-button" type="button" disabled={connectionActive} aria-label={`Удалить правило ${app.name}`} title="Удалить правило" onClick={() => onDraftChange({ ...draft, apps: draft.apps.filter((item) => item.id !== app.id) })}><TrashIcon size={18} /></button>
              </div>
              <SegmentedControl
                label={`Маршрут для ${app.name}`}
                value={app.route}
                options={[{ value: "direct", label: "Напрямую" }, { value: "vpn", label: "Через VPN" }]}
                onChange={(route) => updateApp(app.id, route)}
                disabled={connectionActive}
              />
              <p className="rule-effective">
                {snapshot.mode === "tun"
                  ? `В TUN: трафик приложения ${app.route === "direct" ? "напрямую" : "через VPN"}`
                  : `В System Proxy: TCP-трафик приложения через прокси Windows ${app.route === "direct" ? "напрямую" : "через VPN"}`}
              </p>
            </div>
          )) : (
            <div className="empty-state">
              <RoutingIcon size={24} />
              <strong>Исключений пока нет</strong>
              <span>{snapshot.mode === "tun" ? "Добавьте запущенное приложение, чтобы задать ему другой маршрут." : "Добавьте приложение, использующее прокси Windows, чтобы задать его TCP-трафику другой маршрут."}</span>
            </div>
          )}
        </div>
      </section>
      <button className="primary-button" type="button" disabled={connectionActive || !dirty || applying} aria-busy={applying} onClick={apply} title={connectionActive ? "Сначала отключитесь, чтобы изменить правила" : undefined}>
        {applying ? <LoaderIcon size={20} /> : <CheckIcon size={20} />}{applying ? "Сохраняем…" : "Сохранить правила"}
      </button>

      {pickerOpen ? (
        <Dialog
          title="Добавить приложение"
          description="Выберите приложение из запущенных сейчас."
          focusKey="application-picker-search"
          onClose={() => setPickerOpen(false)}
          busy={pickerLoading}
          actions={<button className="secondary-button" type="button" onClick={() => setPickerOpen(false)}>Готово</button>}
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
  const settingsUnavailable = !snapshot.isDemo;
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

      {settingsUnavailable ? <OpaqueNotice notice={{ id: "settings-unavailable", kind: "info", title: "Эти настройки появятся позже", body: "RouteDeck пока выбирает свободные локальные порты автоматически. Настройки трея и автозапуска ещё не подключены." }} /> : null}

      <section className="card settings-group">
        <div className="section-heading compact-heading"><div><p className="overline">Интерфейс</p><h2>Общие</h2></div></div>
        <label className="check-row"><input type="checkbox" disabled={settingsUnavailable} checked={draft.startMinimized} onChange={(event) => onDraftChange({ ...draft, startMinimized: event.target.checked })} /><span><strong>Запускать свёрнутым</strong><small>Показывать RouteDeck только в трее после старта</small></span></label>
        <label className="field-row"><span><strong>При закрытии окна</strong><small>Действие системной кнопки закрытия</small></span><select disabled={settingsUnavailable} value={draft.closeBehavior} onChange={(event) => onDraftChange({ ...draft, closeBehavior: event.target.value as SettingsConfig["closeBehavior"] })}><option value="tray">Скрыть в трей</option><option value="exit">Завершить работу</option></select></label>
        <label className="field-row"><span><strong>Тема</strong><small>Dark-first, без внешних шрифтов</small></span><select disabled={settingsUnavailable} value={draft.theme} onChange={(event) => onDraftChange({ ...draft, theme: event.target.value as SettingsConfig["theme"] })}><option value="dark">Тёмная</option><option value="light">Светлая</option><option value="system">Как в Windows</option></select></label>
      </section>

      <section className="card settings-group">
        <div className="section-heading compact-heading"><div><p className="overline">Локальные endpoints</p><h2>Подключение</h2></div></div>
        <label className="number-field"><span>HTTP-порт</span><input type="number" disabled={settingsUnavailable} min="1024" max="65535" value={draft.httpPort} aria-describedby="port-help" onChange={(event) => onDraftChange({ ...draft, httpPort: Number(event.target.value) })} /></label>
        <label className="number-field"><span>SOCKS-порт</span><input type="number" disabled={settingsUnavailable} min="1024" max="65535" value={draft.socksPort} aria-describedby="port-help" onChange={(event) => onDraftChange({ ...draft, socksPort: Number(event.target.value) })} /></label>
        <p id="port-help" className={`field-help${portsValid ? "" : " field-error"}`}>{portsValid ? "Допустимо: 1024–65535. Порты должны отличаться." : "Укажите разные свободные порты от 1024 до 65535."}</p>
      </section>

      <section className="card settings-group">
        <div className="section-heading compact-heading"><div><p className="overline">Системный прокси</p><h2>Совместимость с другими VPN</h2></div></div>
        <label className="radio-setting"><input type="radio" disabled={settingsUnavailable} name="proxy-policy" value="never-overwrite" checked={draft.proxyConflictPolicy === "never-overwrite"} onChange={() => onDraftChange({ ...draft, proxyConflictPolicy: "never-overwrite" })} /><span><strong>Не заменять настройки другой программы</strong><small>При конфликте RouteDeck покажет ошибку</small></span></label>
        <div className="persistent-hint" data-kind="info"><InfoIcon size={18} /><p>Windows использует один эффективный системный прокси. Разные локальные порты не создают двух владельцев.</p></div>
      </section>

      <button className="primary-button" type="button" disabled={settingsUnavailable || !dirty || !portsValid || saving} aria-busy={saving} onClick={save} title={settingsUnavailable ? "Сохранение настроек ещё не подключено" : undefined}>{saving ? <LoaderIcon size={20} /> : <CheckIcon size={20} />}{saving ? "Сохраняем…" : settingsUnavailable ? "Сохранение недоступно" : "Сохранить изменения"}</button>

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
  return (
    <div className="page">
      <div className="page-title-row"><div><p className="overline">Состояние приложения</p><h1 ref={headingRef} tabIndex={-1}>Диагностика</h1></div>{snapshot.diagnostics.snapshotReceivedAt ? <span className="quiet-badge">Обновлено {snapshot.diagnostics.snapshotReceivedAt}</span> : null}</div>
      <ActionFailureNotice failure={actionFailure} page="diagnostics" onClear={onClearFailure} />
      <p className="field-help">Здесь показано последнее состояние подключения. Обновление не запускает новое сетевое подключение.</p>
      <button className="primary-button" type="button" disabled={checking || snapshot.diagnostics.running} aria-busy={checking || snapshot.diagnostics.running} onClick={run}>{checking || snapshot.diagnostics.running ? <LoaderIcon size={20} /> : <ActivityIcon size={20} />}{checking || snapshot.diagnostics.running ? "Обновляем…" : "Обновить состояние"}</button>
      {snapshot.environment.otherVpnDetected ? <OpaqueNotice notice={externalNotice} primaryAction={{ label: "Обновить", onClick: run }} /> : null}
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
    return () => previouslyFocusedRef.current?.focus({ preventScroll: true });
  }, []);

  useEffect(() => {
    const dialog = dialogRef.current;
    const focusable = busy || closeDisabled
      ? dialog?.querySelector<HTMLElement>("[data-dialog-busy-focus]")
      : dialog?.querySelector<HTMLElement>("[data-error-autofocus]:not(:disabled)")
      ?? dialog?.querySelector<HTMLElement>("[data-autofocus]")
      ?? dialog?.querySelector<HTMLElement>("button:not(:disabled), input:not(:disabled), select:not(:disabled), textarea:not(:disabled)");
    const frame = window.requestAnimationFrame(() => focusable?.focus());
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
      const items = Array.from(dialog.querySelectorAll<HTMLElement>("button:not(:disabled), input:not(:disabled), select:not(:disabled), textarea:not(:disabled), [tabindex]:not([tabindex='-1'])"));
      const first = items[0];
      const last = items[items.length - 1];
      const busyTarget = dialog.querySelector<HTMLElement>("[data-dialog-busy-focus]");
      if (!first || !last) {
        if (busyTarget) {
          event.preventDefault();
          busyTarget.focus();
        }
        return;
      }
      if (document.activeElement === busyTarget) {
        event.preventDefault();
        (event.shiftKey ? last : first).focus();
        return;
      }
      if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last.focus(); }
      if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first.focus(); }
    };
    const onFocusIn = (event: FocusEvent) => {
      if (!dialog || dialog.contains(event.target as Node | null)) return;
      const target = busy || closeDisabled
        ? dialog.querySelector<HTMLElement>("[data-dialog-busy-focus]")
        : dialog.querySelector<HTMLElement>("[data-error-autofocus]:not(:disabled)")
        ?? dialog.querySelector<HTMLElement>("[data-autofocus]")
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

  return (
    <div className="dialog-scrim" role="presentation">
      <div className="dialog" ref={dialogRef} role="dialog" aria-modal="true" aria-labelledby="dialog-title" aria-describedby={description ? "dialog-description" : undefined}>
        <div className="dialog-header"><div><h2 id="dialog-title">{title}</h2>{description ? <p id="dialog-description">{description}</p> : null}</div><button className="icon-button" type="button" aria-label="Закрыть окно" title={closeDisabled ? "Дождитесь завершения импорта" : "Закрыть"} disabled={closeDisabled} onClick={onClose}><XIcon size={19} /></button></div>
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
  const [search, setSearch] = useState("");
  const [routingDraft, setRoutingDraft] = useState<RoutingConfig>(snapshot.routing);
  const [settingsDraft, setSettingsDraft] = useState<SettingsConfig>(snapshot.settings);
  const [toast, setToast] = useState<ToastState | null>(null);
  const [toastPaused, setToastPaused] = useState(false);
  const [actionFailure, setActionFailure] = useState<ActionFailure | null>(null);
  const [importError, setImportError] = useState("");
  const [importing, setImporting] = useState(false);
  const mainRef = useRef<HTMLElement>(null);
  const headingRef = useRef<HTMLHeadingElement>(null);
  const subscriptionInputRef = useRef<HTMLInputElement>(null);
  const importGeneration = useRef(0);
  const scrollPositions = useRef<Record<Destination, number>>({ home: 0, servers: 0, routing: 0, settings: 0, diagnostics: 0 });

  const clearSubscriptionUrl = useCallback(() => {
    if (subscriptionInputRef.current) subscriptionInputRef.current.value = "";
  }, []);

  const invalidateImport = useCallback(() => {
    importGeneration.current += 1;
    controller.cancelImportPreview();
    setImporting(false);
  }, []);

  const closeDialog = useCallback(() => {
    invalidateImport();
    setDialog(null);
    setPendingMode(null);
    setImportError("");
    clearSubscriptionUrl();
  }, [clearSubscriptionUrl, invalidateImport]);

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
    void runAsyncAction({
      page: "home",
      title: snapshot.mode === "tun" ? "Не удалось запустить TUN" : "Не удалось подключиться",
      action: () => controller.connect(),
      retry: handleConnect,
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

  const importSubscription = () => {
    const subscriptionUrl = subscriptionInputRef.current?.value.trim() ?? "";
    if (!subscriptionUrl) {
      setImportError("Вставьте ссылку на подписку.");
      window.requestAnimationFrame(() => subscriptionInputRef.current?.focus());
      return;
    }
    setImportError("");
    controller.cancelImportPreview();
    const generation = ++importGeneration.current;
    void runAsyncAction({
      page: "servers",
      title: "Не удалось импортировать подписку",
      setBusy: (busy) => {
        if (generation === importGeneration.current) setImporting(busy);
      },
      action: async () => {
        const preview = await controller.previewSubscription({ type: "url", value: subscriptionUrl });
        if (generation !== importGeneration.current) return null;
        await controller.commitSubscription(preview);
        return preview;
      },
      errorPresentation: "inline",
      onError: (publicError) => {
        if (generation !== importGeneration.current) return;
        setImportError(publicError.message);
      },
      onSuccess: (preview) => {
        if (!preview || generation !== importGeneration.current) return;
        clearSubscriptionUrl();
        closeDialog();
        showToast(`Импортировано серверов: ${preview.nodeNames.length}`, "success");
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

  const renderPage = () => {
    switch (activePage) {
      case "home":
        return <HomePage snapshot={snapshot} headingRef={headingRef} onNavigate={navigate} onModeChange={handleModeChange} onConnect={handleConnect} onDisconnect={disconnect} onRetry={retryConnection} actionFailure={actionFailure} onClearFailure={() => setActionFailure(null)} />;
      case "servers":
        return <ServersPage snapshot={snapshot} headingRef={headingRef} search={search} onSearch={setSearch} onImport={() => { invalidateImport(); clearSubscriptionUrl(); setDialog("import"); }} actionFailure={actionFailure} onClearFailure={() => setActionFailure(null)} />;
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
        <div className="brand"><span className="brand-mark"><RoutingIcon size={20} /></span><span><strong>RouteDeck</strong><small>VPN-клиент</small></span></div>
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
          description="Вставьте ссылку от провайдера."
          focusKey="subscription-url"
          onClose={closeDialog}
          busy={importing}
          actions={<>
            <button className="secondary-button" type="button" data-autofocus onClick={closeDialog}>Отмена</button>
            <button className="primary-button dialog-primary" type="submit" form="subscription-import-form" disabled={importing} aria-busy={importing}>{importing ? <LoaderIcon size={19} /> : <ImportIcon size={19} />}{importing ? "Импортируем…" : "Импортировать"}</button>
          </>}
        >
          <form id="subscription-import-form" onSubmit={(event) => { event.preventDefault(); importSubscription(); }}>
            {importing ? <p className="persistent-hint" role="status" aria-live="polite" tabIndex={-1} data-dialog-busy-focus><LoaderIcon size={17} />Загружаем подписку…</p> : null}
            <div className="dialog-field">
              <label htmlFor="subscription-url">Ссылка на подписку</label>
              <input ref={subscriptionInputRef} id="subscription-url" type="url" inputMode="url" autoComplete="url" defaultValue="" disabled={importing} data-autofocus data-error-autofocus={importError ? "true" : undefined} aria-invalid={Boolean(importError)} aria-describedby={importError ? "import-error" : undefined} placeholder="https://provider.example/subscription" onInput={() => setImportError("")} />
              {importError ? <small id="import-error" className="field-error" role="alert">{importError}</small> : null}
            </div>
          </form>
        </Dialog>
      ) : null}

      {dialog === "mode-change" && pendingMode ? (
        <Dialog
          title="Сменить режим подключения?"
          description="RouteDeck остановит текущее подключение. Новый режим не запустится автоматически."
          onClose={closeDialog}
          actions={<><button className="secondary-button" type="button" data-autofocus onClick={closeDialog}>Оставить текущий</button><button className="primary-button dialog-primary" type="button" onClick={() => { const mode = pendingMode; closeDialog(); void runAsyncAction({ page: "home", title: "Не удалось сменить режим", action: async () => { await controller.disconnect(); controller.setMode(mode); }, retry: () => handleModeChange(mode) }); }}><CheckIcon size={19} />Отключить и выбрать</button></>}
        ><p className="dialog-copy">Будет выбран режим <strong>{pendingMode === "tun" ? "TUN" : "Системный прокси"}</strong>. После смены режима нажмите «Подключить».</p></Dialog>
      ) : null}

      {dialog === "reset" ? (
        <Dialog
          title="Сбросить локальное состояние?"
          description="Будут удалены только локальные настройки и черновики RouteDeck. Чужой VPN и Windows не изменяются."
          onClose={closeDialog}
          actions={<><button className="secondary-button" type="button" data-autofocus onClick={closeDialog}>Отмена</button><button className="danger-button" type="button" onClick={() => { closeDialog(); void runAsyncAction({ page: "settings", title: "Не удалось сбросить локальное состояние", action: controller.resetLocalState, retry: () => setDialog("reset"), onSuccess: () => { setRoutingDraft(controller.getSnapshot().routing); setSettingsDraft(controller.getSnapshot().settings); showToast("Локальное состояние сброшено", "info"); } }); }}><TrashIcon size={19} />Сбросить RouteDeck</button></>}
        ><p className="dialog-copy">Активное подключение будет остановлено, а настройки RouteDeck — сброшены.</p></Dialog>
      ) : null}
    </div>
  );
}

use std::sync::Arc;

use tauri::{Manager, State};

use crate::{
    app_updates::{self, AppUpdateChecker, AppUpdateInfo},
    application::{
        ApplicationController, ConfirmedImport, Diagnostics, ImportPreview, PublicError,
        PublicErrorCode, PublicErrorStage, RuntimeStatus, SystemProxyRouting, TunRouting,
    },
    domain::DefaultRoute,
    running_applications::{self, RunningApplication},
};

#[tauri::command]
pub fn get_app_version() -> String {
    env!("CARGO_PKG_VERSION").into()
}

#[tauri::command]
pub async fn check_app_update(
    checker: State<'_, Arc<AppUpdateChecker>>,
) -> Result<AppUpdateInfo, &'static str> {
    let checker = Arc::clone(checker.inner());
    tauri::async_runtime::spawn_blocking(move || checker.check())
        .await
        .map_err(|_| "Update check unavailable")?
}

#[tauri::command]
pub fn open_app_releases() -> Result<(), &'static str> {
    app_updates::open_releases_page()
}

#[tauri::command]
pub fn set_interface_theme(
    app: tauri::AppHandle,
    theme: crate::window_appearance::InterfaceTheme,
) -> Result<(), &'static str> {
    let window = app
        .get_webview_window("main")
        .ok_or("Main window unavailable")?;
    // Updates both the native window and WebView fill, including during resize.
    window
        .set_background_color(Some(theme.background()))
        .map_err(|_| "Window appearance unavailable")
}

#[tauri::command]
pub async fn preview_import_content(
    controller: State<'_, Arc<ApplicationController>>,
    content: String,
) -> Result<ImportPreview, PublicError> {
    let controller = Arc::clone(controller.inner());
    let slot = controller.reserve_preview_slot()?;
    tauri::async_runtime::spawn_blocking(move || {
        controller.preview_import_content_reserved(content, slot)
    })
    .await
    .map_err(command_join_error)?
}

#[tauri::command]
pub async fn preview_import_url(
    controller: State<'_, Arc<ApplicationController>>,
    url: String,
) -> Result<ImportPreview, PublicError> {
    let controller = Arc::clone(controller.inner());
    let slot = controller.reserve_preview_slot()?;
    tauri::async_runtime::spawn_blocking(move || controller.preview_import_url_reserved(url, slot))
        .await
        .map_err(command_join_error)?
}

#[tauri::command]
pub fn discard_import_preview(
    controller: State<'_, Arc<ApplicationController>>,
    preview_id: String,
) -> Result<(), PublicError> {
    controller.discard_import_preview(&preview_id)
}

#[tauri::command]
pub async fn confirm_import(
    controller: State<'_, Arc<ApplicationController>>,
    preview_id: String,
    source_name: Option<String>,
) -> Result<ConfirmedImport, PublicError> {
    let controller = Arc::clone(controller.inner());
    tauri::async_runtime::spawn_blocking(move || {
        controller.confirm_import_named(&preview_id, source_name.as_deref())
    })
    .await
    .map_err(command_join_error)?
}

#[tauri::command]
pub async fn refresh_source(
    controller: State<'_, Arc<ApplicationController>>,
    source_id: String,
    url: Option<String>,
) -> Result<ConfirmedImport, PublicError> {
    let controller = Arc::clone(controller.inner());
    let slot = controller.reserve_preview_slot()?;
    tauri::async_runtime::spawn_blocking(move || {
        controller.refresh_source_reserved(&source_id, url.as_deref(), slot)
    })
    .await
    .map_err(command_join_error)?
}

#[tauri::command]
pub async fn remove_source(
    controller: State<'_, Arc<ApplicationController>>,
    source_id: String,
) -> Result<(), PublicError> {
    let controller = Arc::clone(controller.inner());
    tauri::async_runtime::spawn_blocking(move || controller.remove_source(&source_id))
        .await
        .map_err(command_join_error)?
}

/// Generates a product-owned local-only configuration, validates it with the
/// pinned engine, starts the fixed binary, and proves traffic. It never writes
/// Windows System Proxy or creates TUN/routes.
#[tauri::command]
pub async fn start_local_proxy(
    controller: State<'_, Arc<ApplicationController>>,
    node_id: String,
    default_route: DefaultRoute,
) -> Result<RuntimeStatus, PublicError> {
    let controller = Arc::clone(controller.inner());
    tauri::async_runtime::spawn_blocking(move || {
        controller.start_local_proxy(&node_id, default_route)
    })
    .await
    .map_err(command_join_error)?
}

#[tauri::command]
pub async fn start_system_proxy(
    controller: State<'_, Arc<ApplicationController>>,
    node_id: String,
    routing: SystemProxyRouting,
) -> Result<RuntimeStatus, PublicError> {
    let controller = Arc::clone(controller.inner());
    tauri::async_runtime::spawn_blocking(move || controller.start_system_proxy(&node_id, routing))
        .await
        .map_err(command_join_error)?
}

#[tauri::command]
pub async fn start_tun(
    controller: State<'_, Arc<ApplicationController>>,
    node_id: String,
    routing: TunRouting,
) -> Result<RuntimeStatus, PublicError> {
    let controller = Arc::clone(controller.inner());
    tauri::async_runtime::spawn_blocking(move || controller.start_tun(&node_id, routing))
        .await
        .map_err(command_join_error)?
}

#[tauri::command]
pub fn runtime_status(controller: State<'_, Arc<ApplicationController>>) -> RuntimeStatus {
    controller.status()
}

#[tauri::command]
pub fn confirmed_nodes(
    controller: State<'_, Arc<ApplicationController>>,
) -> Vec<crate::application::PreviewNode> {
    controller.confirmed_nodes()
}

#[tauri::command]
pub async fn reset_local_state(
    controller: State<'_, Arc<ApplicationController>>,
) -> Result<(), PublicError> {
    let controller = Arc::clone(controller.inner());
    tauri::async_runtime::spawn_blocking(move || controller.reset_local_state())
        .await
        .map_err(command_join_error)?
}

#[tauri::command]
pub async fn stop_local_proxy(
    controller: State<'_, Arc<ApplicationController>>,
) -> Result<RuntimeStatus, PublicError> {
    let controller = Arc::clone(controller.inner());
    tauri::async_runtime::spawn_blocking(move || controller.stop())
        .await
        .map_err(command_join_error)?
}

#[tauri::command]
pub async fn stop_system_proxy(
    controller: State<'_, Arc<ApplicationController>>,
) -> Result<RuntimeStatus, PublicError> {
    let controller = Arc::clone(controller.inner());
    tauri::async_runtime::spawn_blocking(move || controller.stop())
        .await
        .map_err(command_join_error)?
}

#[tauri::command]
pub async fn stop_tun(
    controller: State<'_, Arc<ApplicationController>>,
) -> Result<RuntimeStatus, PublicError> {
    let controller = Arc::clone(controller.inner());
    tauri::async_runtime::spawn_blocking(move || controller.stop())
        .await
        .map_err(command_join_error)?
}

/// Retries restore-before-stop for a retained live session. With no live session,
/// only rechecks preserved crash data and reconciles the owned proxy journal;
/// it never recursively removes unreviewed session files.
#[tauri::command]
pub async fn retry_session_recovery(
    controller: State<'_, Arc<ApplicationController>>,
) -> Result<RuntimeStatus, PublicError> {
    let controller = Arc::clone(controller.inner());
    tauri::async_runtime::spawn_blocking(move || controller.retry_session_recovery())
        .await
        .map_err(command_join_error)?
}

#[tauri::command]
pub async fn runtime_diagnostics(
    controller: State<'_, Arc<ApplicationController>>,
) -> Result<Diagnostics, PublicError> {
    let controller = Arc::clone(controller.inner());
    tauri::async_runtime::spawn_blocking(move || controller.diagnostics())
        .await
        .map_err(command_join_error)
}

#[tauri::command]
pub async fn clear_stale_system_proxy(
    token: String,
    controller: State<'_, Arc<ApplicationController>>,
) -> Result<Diagnostics, PublicError> {
    let controller = Arc::clone(controller.inner());
    tauri::async_runtime::spawn_blocking(move || controller.clear_stale_system_proxy(&token))
        .await
        .map_err(command_join_error)?
}

/// Lists distinct executable images in the current interactive Windows session.
/// Processes whose image path cannot be queried are deliberately omitted.
#[tauri::command]
pub fn list_running_applications() -> Result<Vec<RunningApplication>, PublicError> {
    running_applications::list().map_err(|_| PublicError {
        code: PublicErrorCode::CommandFailed,
        stage: PublicErrorStage::Command,
        message: "Could not enumerate running applications".into(),
        detail: None,
    })
}

fn command_join_error(_error: impl std::fmt::Display) -> PublicError {
    PublicError {
        code: PublicErrorCode::CommandFailed,
        stage: PublicErrorStage::Command,
        message: "Runtime command failed unexpectedly".into(),
        detail: None,
    }
}

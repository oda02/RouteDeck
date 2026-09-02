use std::sync::Arc;

use tauri::State;

use crate::{
    application::{
        ApplicationController, ConfirmedImport, Diagnostics, ImportPreview, PublicError,
        PublicErrorCode, PublicErrorStage, RuntimeStatus, SystemProxyRouting, TunRouting,
    },
    domain::DefaultRoute,
    running_applications::{self, RunningApplication},
};

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
) -> Result<ConfirmedImport, PublicError> {
    let controller = Arc::clone(controller.inner());
    tauri::async_runtime::spawn_blocking(move || controller.confirm_import(&preview_id))
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

/// Rechecks the private session root after the user has explicitly reviewed
/// and removed preserved crash data. This command never deletes files itself.
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
pub fn runtime_diagnostics(controller: State<'_, Arc<ApplicationController>>) -> Diagnostics {
    controller.diagnostics()
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

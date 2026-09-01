pub mod application;
pub mod commands;
pub mod config;
pub mod domain;
pub mod engine_runtime;
pub mod health;
pub mod redaction;
mod runtime_constants;
pub mod subscription;

use std::sync::Arc;

use tauri::{Emitter, Manager};

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .setup(|app| {
            let session_root = app.path().app_local_data_dir()?.join("sessions");
            let handle = app.handle().clone();
            let sink = Arc::new(move |status| {
                let _ = handle.emit("routedeck://runtime-phase", status);
            });
            app.manage(application::ApplicationController::production(
                session_root,
                sink,
            )?);
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::import_preview,
            commands::confirm_import,
            commands::start_local_proxy,
            commands::runtime_status,
            commands::stop_local_proxy,
            commands::retry_session_recovery,
            commands::runtime_diagnostics,
        ])
        .run(tauri::generate_context!())
        .expect("failed to run RouteDeck");
}

pub mod application;
pub mod commands;
pub mod config;
pub mod domain;
pub mod engine_runtime;
pub mod health;
pub mod redaction;
mod runtime_constants;
pub mod subscription;
pub mod subscription_fetch;
mod system_proxy;
#[cfg(windows)]
mod windows_process;
pub mod xray_config;

use std::sync::Arc;

use tauri::{Emitter, Manager};

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let app = tauri::Builder::default()
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
            commands::preview_import_content,
            commands::preview_import_url,
            commands::discard_import_preview,
            commands::confirm_import,
            commands::start_local_proxy,
            commands::start_system_proxy,
            commands::runtime_status,
            commands::stop_local_proxy,
            commands::stop_system_proxy,
            commands::retry_session_recovery,
            commands::runtime_diagnostics,
        ])
        .build(tauri::generate_context!())
        .expect("failed to build RouteDeck");
    app.run(|handle, event| match event {
        tauri::RunEvent::ExitRequested { api, .. } => {
            if let Some(controller) = handle.try_state::<Arc<application::ApplicationController>>()
            {
                if !controller.shutdown() {
                    api.prevent_exit();
                }
            }
        }
        tauri::RunEvent::Exit => {
            if let Some(controller) = handle.try_state::<Arc<application::ApplicationController>>()
            {
                let _ = controller.shutdown();
            }
        }
        _ => {}
    });
}

mod app_instance;
mod app_updates;
pub mod application;
pub mod commands;
pub mod config;
pub mod domain;
pub mod engine_runtime;
pub mod health;
pub mod redaction;
pub mod running_applications;
mod runtime_constants;
pub mod subscription;
pub mod subscription_fetch;
mod subscription_store;
mod system_proxy;
pub mod tun_helper;
mod tun_helper_protocol;
#[cfg(windows)]
mod tun_helper_transport;
pub mod window_appearance;
#[cfg(windows)]
mod windows_process;
pub mod xray_config;

use std::sync::Arc;

use tauri::{Emitter, Manager};

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run(expected_tun_helper_sha256: Option<&'static str>) {
    let app = tauri::Builder::default()
        .setup(move |app| {
            let session_root = app.path().app_local_data_dir()?.join("sessions");
            let handle = app.handle().clone();
            let sink = Arc::new(move |status| {
                let _ = handle.emit("routedeck://runtime-phase", status);
            });
            app.manage(application::ApplicationController::production(
                session_root,
                sink,
                expected_tun_helper_sha256,
            )?);
            app.manage(Arc::new(app_updates::AppUpdateChecker::default()));
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::set_interface_theme,
            commands::preview_import_content,
            commands::preview_import_url,
            commands::discard_import_preview,
            commands::confirm_import,
            commands::refresh_source,
            commands::remove_source,
            commands::start_local_proxy,
            commands::start_system_proxy,
            commands::start_tun,
            commands::runtime_status,
            commands::confirmed_nodes,
            commands::reset_local_state,
            commands::stop_local_proxy,
            commands::stop_system_proxy,
            commands::stop_tun,
            commands::retry_session_recovery,
            commands::runtime_diagnostics,
            commands::clear_stale_system_proxy,
            commands::list_running_applications,
            commands::get_app_version,
            commands::check_app_update,
            commands::open_app_releases,
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

fn main() {
    const COMMANDS: &[&str] = &[
        "preview_import_content",
        "preview_import_url",
        "discard_import_preview",
        "confirm_import",
        "start_local_proxy",
        "start_system_proxy",
        "start_tun",
        "runtime_status",
        "confirmed_nodes",
        "reset_local_state",
        "stop_local_proxy",
        "stop_system_proxy",
        "stop_tun",
        "retry_session_recovery",
        "runtime_diagnostics",
        "list_running_applications",
    ];
    let attributes = tauri_build::Attributes::new()
        .app_manifest(tauri_build::AppManifest::new().commands(COMMANDS));
    tauri_build::try_build(attributes).expect("failed to build RouteDeck Tauri manifest");
}

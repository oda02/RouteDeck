fn main() {
    const COMMANDS: &[&str] = &[
        "set_interface_theme",
        "preview_import_content",
        "preview_import_url",
        "discard_import_preview",
        "confirm_import",
        "refresh_source",
        "remove_source",
        "start_local_proxy",
        "start_system_proxy",
        "start_tun",
        "switch_tun_server",
        "runtime_status",
        "confirmed_nodes",
        "reset_local_state",
        "stop_local_proxy",
        "stop_system_proxy",
        "stop_tun",
        "retry_session_recovery",
        "runtime_diagnostics",
        "clear_stale_system_proxy",
        "list_running_applications",
        "get_app_version",
        "check_app_update",
        "open_app_releases",
    ];
    let attributes = tauri_build::Attributes::new()
        .app_manifest(tauri_build::AppManifest::new().commands(COMMANDS));
    tauri_build::try_build(attributes).expect("failed to build RouteDeck Tauri manifest");
}

fn main() {
    const COMMANDS: &[&str] = &[
        "preview_import_content",
        "discard_import_preview",
        "confirm_import",
        "start_local_proxy",
        "runtime_status",
        "stop_local_proxy",
        "retry_session_recovery",
        "runtime_diagnostics",
    ];
    let attributes = tauri_build::Attributes::new()
        .app_manifest(tauri_build::AppManifest::new().commands(COMMANDS));
    tauri_build::try_build(attributes).expect("failed to build RouteDeck Tauri manifest");
}

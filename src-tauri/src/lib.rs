pub mod config;
pub mod domain;
pub mod redaction;
pub mod subscription;

#[tauri::command]
fn application_status() -> &'static str {
    "idle"
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![application_status])
        .run(tauri::generate_context!())
        .expect("failed to run RouteDeck");
}

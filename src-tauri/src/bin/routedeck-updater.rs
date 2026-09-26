#![cfg_attr(all(windows, not(debug_assertions)), windows_subsystem = "windows")]
fn main() {
    std::hint::black_box(
        option_env!("ROUTEDECK_BUILD_METADATA").unwrap_or("RouteDeckBuildCommit=unrecorded"),
    );
    if routedeck_lib::portable_update::updater_main().is_err() {
        routedeck_lib::portable_update::show_repair_notice();
        std::process::exit(1);
    }
}

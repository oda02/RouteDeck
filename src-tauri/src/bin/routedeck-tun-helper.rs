#![cfg_attr(windows, windows_subsystem = "windows")]

fn main() {
    // Keep the same offline-verifiable source marker as the portable GUI.
    std::hint::black_box(
        option_env!("ROUTEDECK_BUILD_METADATA").unwrap_or("RouteDeckBuildCommit=unrecorded"),
    );
    if routedeck_lib::tun_helper::helper_main().is_err() {
        std::process::exit(1);
    }
}

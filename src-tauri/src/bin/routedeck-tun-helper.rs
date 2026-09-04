#![cfg_attr(windows, windows_subsystem = "windows")]

fn main() {
    // Keep the same offline-verifiable source marker as the portable GUI.
    std::hint::black_box(
        option_env!("ROUTEDECK_BUILD_METADATA").unwrap_or("RouteDeckBuildCommit=unrecorded"),
    );
    if let Err(code) = routedeck_lib::tun_helper::helper_main() {
        std::process::exit(code);
    }
}

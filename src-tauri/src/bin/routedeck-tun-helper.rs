#![cfg_attr(windows, windows_subsystem = "windows")]

fn main() {
    if routedeck_lib::tun_helper::helper_main().is_err() {
        std::process::exit(1);
    }
}

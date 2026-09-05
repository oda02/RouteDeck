#![cfg_attr(all(windows, not(debug_assertions)), windows_subsystem = "windows")]

#[cfg(all(windows, not(debug_assertions)))]
fn attach_diagnostic_console() {
    const ATTACH_PARENT_PROCESS: u32 = u32::MAX;

    #[link(name = "kernel32")]
    extern "system" {
        fn AttachConsole(process_id: u32) -> i32;
    }

    // A release GUI has no console of its own. Attach only for the explicit
    // terminal diagnostic so its existing plain-text result remains visible.
    unsafe {
        AttachConsole(ATTACH_PARENT_PROCESS);
    }
}

#[cfg(not(all(windows, not(debug_assertions))))]
fn attach_diagnostic_console() {}

fn main() {
    // Retain a plain-text provenance marker in release binaries so a portable
    // artifact can be tied to the exact reviewed source without executing it.
    std::hint::black_box(
        option_env!("ROUTEDECK_BUILD_METADATA").unwrap_or("RouteDeckBuildCommit=unrecorded"),
    );
    // Keep the portable helper pin in the GUI target only. The helper binary links
    // the shared library too, so reading this value in library code would make the
    // helper's own bytes depend on its hash during the second build pass.
    let arguments: Vec<_> = std::env::args_os().skip(1).collect();
    if arguments
        .first()
        .is_some_and(|argument| argument == "--diagnose-tun-helper")
    {
        attach_diagnostic_console();
        if arguments.len() != 1 {
            println!("helper_handshake=failed stage=arguments");
            std::process::exit(2);
        }
        match routedeck_lib::tun_helper::diagnose_helper_handshake(option_env!(
            "ROUTEDECK_TUN_HELPER_SHA256"
        )) {
            Ok(()) => println!("helper_handshake=passed start_tun_sent=false helper_exited=true"),
            Err(error) => {
                println!("helper_handshake=failed {error}");
                std::process::exit(1);
            }
        }
        return;
    }
    routedeck_lib::run(option_env!("ROUTEDECK_TUN_HELPER_SHA256"));
}

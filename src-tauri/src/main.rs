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

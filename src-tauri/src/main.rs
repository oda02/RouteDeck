fn main() {
    // Retain a plain-text provenance marker in release binaries so a portable
    // artifact can be tied to the exact reviewed source without executing it.
    std::hint::black_box(
        option_env!("ROUTEDECK_BUILD_METADATA").unwrap_or("RouteDeckBuildCommit=unrecorded"),
    );
    // Keep the portable helper pin in the GUI target only. The helper binary links
    // the shared library too, so reading this value in library code would make the
    // helper's own bytes depend on its hash during the second build pass.
    routedeck_lib::run(option_env!("ROUTEDECK_TUN_HELPER_SHA256"));
}

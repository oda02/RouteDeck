fn main() {
    // Keep the portable helper pin in the GUI target only. The helper binary links
    // the shared library too, so reading this value in library code would make the
    // helper's own bytes depend on its hash during the second build pass.
    routedeck_lib::run(option_env!("ROUTEDECK_TUN_HELPER_SHA256"));
}

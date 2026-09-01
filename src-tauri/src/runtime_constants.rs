/// Fixed username for the private health HTTP proxy. The password is random
/// per session; keeping the username shared prevents generator/prober drift.
pub(crate) const HEALTH_PROXY_USERNAME: &str = "routedeck-health";

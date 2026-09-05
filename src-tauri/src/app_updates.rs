use std::{
    cmp::Ordering,
    io::Read,
    sync::{Condvar, Mutex},
    time::{Duration, Instant},
};

use serde::{Deserialize, Serialize};

const API_URL: &str = "https://api.github.com/repos/oda02/RouteDeck/releases/latest";
pub(crate) const RELEASES_URL: &str = "https://github.com/oda02/RouteDeck/releases/latest";
const MAX_RESPONSE_BYTES: u64 = 256 * 1024;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
const THROTTLE: Duration = Duration::from_secs(60);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum AppUpdateStatus {
    UpToDate,
    Available,
    NoRelease,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AppUpdateInfo {
    pub current_version: String,
    pub latest_version: Option<String>,
    pub status: AppUpdateStatus,
    pub release_url: Option<String>,
}

#[derive(Clone)]
struct CachedResult {
    at: Instant,
    value: Result<AppUpdateInfo, &'static str>,
}

#[derive(Default)]
struct UpdateState {
    running: bool,
    cached: Option<CachedResult>,
}

#[derive(Default)]
pub struct AppUpdateChecker {
    state: Mutex<UpdateState>,
    changed: Condvar,
}

impl AppUpdateChecker {
    pub fn check(&self) -> Result<AppUpdateInfo, &'static str> {
        self.check_with(fetch_latest)
    }

    fn check_with<F>(&self, fetch: F) -> Result<AppUpdateInfo, &'static str>
    where
        F: FnOnce() -> Result<AppUpdateInfo, &'static str>,
    {
        let mut state = self.state.lock().unwrap_or_else(|value| value.into_inner());
        loop {
            if let Some(cached) = &state.cached {
                if cached.at.elapsed() < THROTTLE {
                    return cached.value.clone();
                }
            }
            if !state.running {
                state.running = true;
                break;
            }
            state = self
                .changed
                .wait(state)
                .unwrap_or_else(|value| value.into_inner());
        }
        drop(state);

        let result = fetch();
        let mut state = self.state.lock().unwrap_or_else(|value| value.into_inner());
        state.running = false;
        state.cached = Some(CachedResult {
            at: Instant::now(),
            value: result.clone(),
        });
        self.changed.notify_all();
        result
    }
}

#[derive(Deserialize)]
struct GithubRelease {
    tag_name: String,
    draft: bool,
    prerelease: bool,
    html_url: String,
}

fn fetch_latest() -> Result<AppUpdateInfo, &'static str> {
    let client = reqwest::blocking::Client::builder()
        .timeout(REQUEST_TIMEOUT)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|_| "Update check unavailable")?;
    let response = client
        .get(API_URL)
        .header(reqwest::header::ACCEPT, "application/vnd.github+json")
        .header(reqwest::header::USER_AGENT, "RouteDeck-update-check/0.1")
        .send()
        .map_err(|_| "Update check unavailable")?;
    if response.status() == reqwest::StatusCode::NOT_FOUND {
        return Ok(no_release());
    }
    if !response.status().is_success() {
        return Err("Update check unavailable");
    }
    if response
        .content_length()
        .is_some_and(|size| size > MAX_RESPONSE_BYTES)
    {
        return Err("Update response is invalid");
    }
    let mut body = Vec::new();
    response
        .take(MAX_RESPONSE_BYTES + 1)
        .read_to_end(&mut body)
        .map_err(|_| "Update check unavailable")?;
    if body.len() as u64 > MAX_RESPONSE_BYTES {
        return Err("Update response is invalid");
    }
    parse_release(&body)
}

fn no_release() -> AppUpdateInfo {
    AppUpdateInfo {
        current_version: env!("CARGO_PKG_VERSION").into(),
        latest_version: None,
        status: AppUpdateStatus::NoRelease,
        release_url: None,
    }
}

fn parse_release(body: &[u8]) -> Result<AppUpdateInfo, &'static str> {
    parse_release_for_current(body, env!("CARGO_PKG_VERSION"))
}

fn parse_release_for_current(
    body: &[u8],
    current_text: &str,
) -> Result<AppUpdateInfo, &'static str> {
    if body.len() as u64 > MAX_RESPONSE_BYTES {
        return Err("Update response is invalid");
    }
    let release: GithubRelease =
        serde_json::from_slice(body).map_err(|_| "Update response is invalid")?;
    let expected_url = format!(
        "https://github.com/oda02/RouteDeck/releases/tag/{}",
        release.tag_name
    );
    if release.draft
        || release.prerelease
        || release.html_url != expected_url
        || release.tag_name.len() > 64
        || !release.tag_name.starts_with('v')
    {
        return Err("Update response is invalid");
    }
    let latest_text = &release.tag_name[1..];
    let latest = Version::parse(latest_text).ok_or("Update response is invalid")?;
    if latest.pre.is_some() {
        return Err("Update response is invalid");
    }
    let current = Version::parse(current_text).ok_or("Current version is invalid")?;
    let status = if latest > current {
        AppUpdateStatus::Available
    } else {
        AppUpdateStatus::UpToDate
    };
    Ok(AppUpdateInfo {
        current_version: current_text.into(),
        latest_version: Some(latest_text.into()),
        status,
        release_url: (status == AppUpdateStatus::Available).then(|| RELEASES_URL.into()),
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Version {
    major: u64,
    minor: u64,
    patch: u64,
    pre: Option<Vec<PrePart>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum PrePart {
    Numeric(u64),
    Text(String),
}

impl Version {
    fn parse(value: &str) -> Option<Self> {
        if value.is_empty() || value.len() > 64 || value.contains('+') {
            return None;
        }
        let (core, pre) = value
            .split_once('-')
            .map_or((value, None), |(core, pre)| (core, Some(pre)));
        let mut numbers = core.split('.');
        let mut number = || {
            let item = numbers.next()?;
            if item.is_empty() || (item.len() > 1 && item.starts_with('0')) {
                return None;
            }
            item.parse().ok()
        };
        let major = number()?;
        let minor = number()?;
        let patch = number()?;
        if numbers.next().is_some() {
            return None;
        }
        let pre = match pre {
            Some(value) => Some({
                if value.is_empty() {
                    return None;
                }
                value
                    .split('.')
                    .map(|part| {
                        if part.is_empty()
                            || !part
                                .bytes()
                                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
                        {
                            return None;
                        }
                        if part.bytes().all(|byte| byte.is_ascii_digit()) {
                            if part.len() > 1 && part.starts_with('0') {
                                return None;
                            }
                            part.parse().ok().map(PrePart::Numeric)
                        } else {
                            Some(PrePart::Text(part.into()))
                        }
                    })
                    .collect::<Option<Vec<_>>>()?
            }),
            None => None,
        };
        Some(Self {
            major,
            minor,
            patch,
            pre,
        })
    }
}

impl Ord for Version {
    fn cmp(&self, other: &Self) -> Ordering {
        (self.major, self.minor, self.patch)
            .cmp(&(other.major, other.minor, other.patch))
            .then_with(|| match (&self.pre, &other.pre) {
                (None, None) => Ordering::Equal,
                (None, Some(_)) => Ordering::Greater,
                (Some(_), None) => Ordering::Less,
                (Some(left), Some(right)) => left
                    .iter()
                    .zip(right)
                    .find_map(|(a, b)| {
                        let order = match (a, b) {
                            (PrePart::Numeric(a), PrePart::Numeric(b)) => a.cmp(b),
                            (PrePart::Numeric(_), PrePart::Text(_)) => Ordering::Less,
                            (PrePart::Text(_), PrePart::Numeric(_)) => Ordering::Greater,
                            (PrePart::Text(a), PrePart::Text(b)) => a.cmp(b),
                        };
                        (order != Ordering::Equal).then_some(order)
                    })
                    .unwrap_or_else(|| left.len().cmp(&right.len())),
            })
    }
}

impl PartialOrd for Version {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[cfg(windows)]
pub fn open_releases_page() -> Result<(), &'static str> {
    use std::{ffi::OsStr, os::windows::ffi::OsStrExt, ptr};
    use windows_sys::Win32::UI::Shell::ShellExecuteW;
    let operation: Vec<u16> = OsStr::new("open").encode_wide().chain(Some(0)).collect();
    let target: Vec<u16> = OsStr::new(RELEASES_URL)
        .encode_wide()
        .chain(Some(0))
        .collect();
    let result = unsafe {
        ShellExecuteW(
            ptr::null_mut(),
            operation.as_ptr(),
            target.as_ptr(),
            ptr::null(),
            ptr::null(),
            1,
        )
    } as isize;
    if result <= 32 {
        Err("Release page unavailable")
    } else {
        Ok(())
    }
}

#[cfg(not(windows))]
pub fn open_releases_page() -> Result<(), &'static str> {
    Err("Release page unavailable")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn semantic_versions_order_prereleases_without_dependencies() {
        let parse = |value| Version::parse(value).unwrap();
        assert!(parse("0.2.0-beta.1") > parse("0.1.9"));
        assert!(parse("0.2.0") > parse("0.2.0-beta.1"));
        assert!(parse("1.0.0-beta.2") < parse("1.0.0-beta.10"));
        for invalid in ["", "1", "1.2", "01.2.3", "1.2.3+build", "1.2.3-"] {
            assert!(Version::parse(invalid).is_none());
        }
    }

    #[test]
    fn release_parser_rejects_untrusted_or_unstable_metadata() {
        let valid = r#"{"tag_name":"v9.0.0","draft":false,"prerelease":false,"html_url":"https://github.com/oda02/RouteDeck/releases/tag/v9.0.0","ignored_by_github_client":true}"#;
        let parsed = parse_release(valid.as_bytes()).unwrap();
        assert_eq!(parsed.status, AppUpdateStatus::Available);
        assert_eq!(parsed.release_url.as_deref(), Some(RELEASES_URL));
        for invalid in [
            valid.replace("false", "true"),
            valid.replacen("false", "true", 1),
            valid.replace(
                "https://github.com/oda02/RouteDeck/releases/tag/v9.0.0",
                "https://example.test/release",
            ),
            valid.replace("v9.0.0", "9.0.0"),
            valid.replace("v9.0.0", "v9.0.0-beta.1"),
        ] {
            assert!(parse_release(invalid.as_bytes()).is_err());
        }
        let stable = parse_release_for_current(valid.as_bytes(), "9.0.0-beta.1").unwrap();
        assert_eq!(stable.status, AppUpdateStatus::Available);
        let older = valid.replace("v9.0.0", "v0.1.9");
        let prerelease_current =
            parse_release_for_current(older.as_bytes(), "0.2.0-beta.1").unwrap();
        assert_eq!(prerelease_current.status, AppUpdateStatus::UpToDate);
        assert_eq!(prerelease_current.release_url, None);
        assert!(parse_release(&vec![b' '; MAX_RESPONSE_BYTES as usize + 1]).is_err());
    }

    #[test]
    fn checker_throttles_successes_and_errors() {
        use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};
        let checker = AppUpdateChecker::default();
        let calls = AtomicUsize::new(0);
        let fetch = || {
            calls.fetch_add(1, AtomicOrdering::SeqCst);
            Ok(no_release())
        };
        checker.check_with(fetch).unwrap();
        checker.check_with(fetch).unwrap();
        assert_eq!(calls.load(AtomicOrdering::SeqCst), 1);

        let checker = AppUpdateChecker::default();
        let calls = AtomicUsize::new(0);
        let fetch = || {
            calls.fetch_add(1, AtomicOrdering::SeqCst);
            Err("Update check unavailable")
        };
        assert!(checker.check_with(fetch).is_err());
        assert!(checker.check_with(fetch).is_err());
        assert_eq!(calls.load(AtomicOrdering::SeqCst), 1);
    }

    #[test]
    fn checker_coalesces_concurrent_calls() {
        use std::{
            sync::{
                atomic::{AtomicUsize, Ordering as AtomicOrdering},
                Arc, Barrier,
            },
            thread,
            time::Duration,
        };
        let checker = Arc::new(AppUpdateChecker::default());
        let calls = Arc::new(AtomicUsize::new(0));
        let barrier = Arc::new(Barrier::new(3));
        let handles: Vec<_> = (0..2)
            .map(|_| {
                let checker = Arc::clone(&checker);
                let calls = Arc::clone(&calls);
                let barrier = Arc::clone(&barrier);
                thread::spawn(move || {
                    barrier.wait();
                    checker
                        .check_with(|| {
                            calls.fetch_add(1, AtomicOrdering::SeqCst);
                            thread::sleep(Duration::from_millis(40));
                            Ok(no_release())
                        })
                        .unwrap()
                })
            })
            .collect();
        barrier.wait();
        for handle in handles {
            assert_eq!(handle.join().unwrap().status, AppUpdateStatus::NoRelease);
        }
        assert_eq!(calls.load(AtomicOrdering::SeqCst), 1);
    }
}

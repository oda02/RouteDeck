use std::{collections::BTreeMap, io, path::Path};

use serde::Serialize;

const MAX_RUNNING_APPLICATIONS: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RunningApplication {
    pub process_name: String,
    pub executable_path: String,
    pub display_name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ProcessCandidate {
    pid: u32,
    process_name: String,
    executable_path: Option<String>,
}

pub fn list() -> io::Result<Vec<RunningApplication>> {
    platform::candidates().map(|candidates| normalize(candidates, platform::current_pid()))
}

fn normalize(
    candidates: impl IntoIterator<Item = ProcessCandidate>,
    current_pid: u32,
) -> Vec<RunningApplication> {
    let mut by_executable = BTreeMap::<String, RunningApplication>::new();

    for candidate in candidates {
        if candidate.pid == 0 || candidate.pid == 4 || candidate.pid == current_pid {
            continue;
        }

        let process_name = candidate.process_name.trim();
        if process_name.is_empty() || is_system_process(process_name) {
            continue;
        }

        let Some(executable_path) = candidate.executable_path else {
            continue;
        };
        let executable_path = executable_path.trim();
        if executable_path.is_empty() {
            continue;
        }

        let Some(display_name) = Path::new(executable_path)
            .file_name()
            .and_then(|name| name.to_str())
            .map(str::trim)
            .filter(|name| !name.is_empty())
        else {
            continue;
        };

        let application = RunningApplication {
            process_name: process_name.to_owned(),
            executable_path: executable_path.to_owned(),
            display_name: display_name.to_owned(),
        };
        let dedup_key = executable_path.replace('/', "\\").to_lowercase();
        by_executable.entry(dedup_key).or_insert(application);
    }

    let mut applications: Vec<_> = by_executable.into_values().collect();
    applications.sort_by_key(application_sort_key);
    applications.truncate(MAX_RUNNING_APPLICATIONS);
    applications
}

fn application_sort_key(application: &RunningApplication) -> (String, String, String) {
    (
        application.display_name.to_lowercase(),
        application.process_name.to_lowercase(),
        application.executable_path.to_lowercase(),
    )
}

fn is_system_process(process_name: &str) -> bool {
    matches!(
        process_name.to_ascii_lowercase().as_str(),
        "system"
            | "registry"
            | "secure system"
            | "memory compression"
            | "idle"
            | "[system process]"
    )
}

#[cfg(windows)]
mod platform {
    use std::{ffi::OsString, mem::size_of, os::windows::ffi::OsStringExt};

    use windows_sys::Win32::{
        Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE},
        System::{
            Diagnostics::ToolHelp::{
                CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
                TH32CS_SNAPPROCESS,
            },
            RemoteDesktop::ProcessIdToSessionId,
            Threading::{
                GetCurrentProcessId, OpenProcess, QueryFullProcessImageNameW,
                PROCESS_QUERY_LIMITED_INFORMATION,
            },
        },
    };

    use super::ProcessCandidate;

    const MAX_IMAGE_PATH_UNITS: usize = 32_768;

    struct OwnedHandle(HANDLE);

    impl OwnedHandle {
        fn snapshot(handle: HANDLE) -> io::Result<Self> {
            if handle == INVALID_HANDLE_VALUE {
                Err(io::Error::last_os_error())
            } else {
                Ok(Self(handle))
            }
        }

        fn process(handle: HANDLE) -> Option<Self> {
            (!handle.is_null()).then_some(Self(handle))
        }
    }

    impl Drop for OwnedHandle {
        fn drop(&mut self) {
            unsafe { CloseHandle(self.0) };
        }
    }

    pub(super) fn current_pid() -> u32 {
        unsafe { GetCurrentProcessId() }
    }

    pub(super) fn candidates() -> io::Result<Vec<ProcessCandidate>> {
        let current_session =
            process_session(current_pid()).ok_or_else(io::Error::last_os_error)?;
        let snapshot =
            OwnedHandle::snapshot(unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) })?;
        let mut entry = PROCESSENTRY32W {
            dwSize: size_of::<PROCESSENTRY32W>() as u32,
            ..Default::default()
        };
        let mut candidates = Vec::new();

        if unsafe { Process32FirstW(snapshot.0, &mut entry) } == 0 {
            return Err(io::Error::last_os_error());
        }

        loop {
            let pid = entry.th32ProcessID;
            if process_session(pid) == Some(current_session) {
                candidates.push(ProcessCandidate {
                    pid,
                    process_name: wide_c_string(&entry.szExeFile),
                    executable_path: query_image_path(pid),
                });
            }

            entry.dwSize = size_of::<PROCESSENTRY32W>() as u32;
            if unsafe { Process32NextW(snapshot.0, &mut entry) } == 0 {
                break;
            }
        }

        Ok(candidates)
    }

    fn process_session(pid: u32) -> Option<u32> {
        let mut session_id = 0_u32;
        (unsafe { ProcessIdToSessionId(pid, &mut session_id) } != 0).then_some(session_id)
    }

    fn query_image_path(pid: u32) -> Option<String> {
        let process = OwnedHandle::process(unsafe {
            OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid)
        })?;
        let mut path = vec![0_u16; MAX_IMAGE_PATH_UNITS];
        let mut units = path.len() as u32;
        if unsafe { QueryFullProcessImageNameW(process.0, 0, path.as_mut_ptr(), &mut units) } == 0 {
            return None;
        }
        path.truncate(units as usize);
        Some(OsString::from_wide(&path).to_string_lossy().into_owned())
    }

    fn wide_c_string(value: &[u16]) -> String {
        let units = value
            .iter()
            .position(|unit| *unit == 0)
            .unwrap_or(value.len());
        OsString::from_wide(&value[..units])
            .to_string_lossy()
            .into_owned()
    }

    use std::io;
}

#[cfg(not(windows))]
mod platform {
    use std::io;

    use super::ProcessCandidate;

    pub(super) fn current_pid() -> u32 {
        std::process::id()
    }

    pub(super) fn candidates() -> io::Result<Vec<ProcessCandidate>> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "running application discovery is only available on Windows",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn candidate(pid: u32, name: &str, path: Option<&str>) -> ProcessCandidate {
        ProcessCandidate {
            pid,
            process_name: name.into(),
            executable_path: path.map(str::to_owned),
        }
    }

    #[test]
    fn normalizes_deduplicates_and_sorts_applications() {
        let actual = normalize(
            [
                candidate(40, "zeta.exe", Some(r"C:\Apps\Zeta.exe")),
                candidate(41, "zeta.exe", Some(r"c:/apps/zeta.exe")),
                candidate(20, "alpha.exe", Some(r"C:\Apps\Alpha.exe")),
            ],
            99,
        );

        assert_eq!(
            actual,
            vec![
                RunningApplication {
                    process_name: "alpha.exe".into(),
                    executable_path: r"C:\Apps\Alpha.exe".into(),
                    display_name: "Alpha.exe".into(),
                },
                RunningApplication {
                    process_name: "zeta.exe".into(),
                    executable_path: r"C:\Apps\Zeta.exe".into(),
                    display_name: "Zeta.exe".into(),
                },
            ]
        );
    }

    #[test]
    fn filters_system_self_empty_and_inaccessible_processes() {
        let actual = normalize(
            [
                candidate(0, "Idle", Some(r"C:\Windows\idle.exe")),
                candidate(4, "System", Some(r"C:\Windows\System")),
                candidate(77, "RouteDeck.exe", Some(r"C:\Apps\RouteDeck.exe")),
                candidate(78, "", Some(r"C:\Apps\empty.exe")),
                candidate(79, "hidden.exe", None),
                candidate(80, "Registry", Some(r"C:\Windows\Registry")),
                candidate(81, "good.exe", Some(r"C:\Apps\good.exe")),
            ],
            77,
        );

        assert_eq!(actual.len(), 1);
        assert_eq!(actual[0].process_name, "good.exe");
    }

    #[test]
    fn caps_results_after_deterministic_sorting() {
        let candidates = (0..(MAX_RUNNING_APPLICATIONS + 10)).map(|index| {
            candidate(
                1000 + index as u32,
                &format!("app-{index:03}.exe"),
                Some(&format!(r"C:\Apps\app-{index:03}.exe")),
            )
        });

        let actual = normalize(candidates, 1);

        assert_eq!(actual.len(), MAX_RUNNING_APPLICATIONS);
        assert_eq!(actual[0].display_name, "app-000.exe");
        assert_eq!(actual.last().unwrap().display_name, "app-255.exe");
    }
}

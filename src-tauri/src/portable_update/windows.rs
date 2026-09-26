use super::*;
use std::{
    ffi::OsString,
    mem::zeroed,
    os::windows::{ffi::OsStringExt, process::CommandExt},
    process::{Command, Stdio},
    ptr,
    time::Instant,
};
use windows_sys::Win32::{
    Foundation::{CloseHandle, FILETIME, HANDLE, WAIT_OBJECT_0, WAIT_TIMEOUT},
    System::Threading::{
        GetCurrentProcess, GetProcessTimes, OpenProcess, QueryFullProcessImageNameW,
        WaitForSingleObject, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE,
    },
    UI::WindowsAndMessaging::{MessageBoxW, MB_ICONERROR, MB_OK},
};

pub(super) fn local_absolute_path(path: &Path) -> bool {
    use std::path::{Component, Prefix};
    path.is_absolute()
        && matches!(
            path.components().next(),
            Some(Component::Prefix(p))
                if matches!(p.kind(), Prefix::Disk(_) | Prefix::VerbatimDisk(_))
        )
        && !path.components().any(|p| matches!(p, Component::ParentDir))
}

struct Process(HANDLE);
impl Drop for Process {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.0);
        }
    }
}
fn created(handle: HANDLE) -> Result<u64> {
    let (mut creation, mut exit, mut kernel, mut user): (FILETIME, FILETIME, FILETIME, FILETIME) =
        unsafe { zeroed() };
    if unsafe { GetProcessTimes(handle, &mut creation, &mut exit, &mut kernel, &mut user) } == 0 {
        return Err(ERROR);
    }
    Ok((u64::from(creation.dwHighDateTime) << 32) | u64::from(creation.dwLowDateTime))
}
fn process_image(handle: HANDLE) -> Result<PathBuf> {
    let mut buffer = vec![0u16; 32768];
    let mut length = buffer.len() as u32;
    if unsafe { QueryFullProcessImageNameW(handle, 0, buffer.as_mut_ptr(), &mut length) } == 0 {
        return Err(ERROR);
    }
    buffer.truncate(length as usize);
    Ok(PathBuf::from(OsString::from_wide(&buffer)))
}
fn stage_root() -> Result<PathBuf> {
    use windows_sys::Win32::{
        System::Com::CoTaskMemFree,
        UI::Shell::{FOLDERID_LocalAppData, SHGetKnownFolderPath},
    };
    let mut path = ptr::null_mut();
    if unsafe { SHGetKnownFolderPath(&FOLDERID_LocalAppData, 0, ptr::null_mut(), &mut path) } != 0
        || path.is_null()
    {
        return Err(ERROR);
    }
    let mut length = 0;
    while unsafe { *path.add(length) } != 0 {
        length += 1;
    }
    let local = OsString::from_wide(unsafe { std::slice::from_raw_parts(path, length) });
    unsafe {
        CoTaskMemFree(path.cast());
    }
    let root = PathBuf::from(local)
        .join("app.routedeck.desktop")
        .join("updates");
    DirectoryLease::acquire(&root)?;
    Ok(root)
}
pub(super) fn launch(prepared: PreparedInstall) -> Result<()> {
    let token = prepared
        .stage
        .file_name()
        .and_then(|p| p.to_str())
        .ok_or(ERROR)?;
    unhex::<16>(token)?;
    if prepared.stage != stage_root()?.join(token)
        || std::env::current_exe().map_err(|_| ERROR)?.parent() != Some(prepared.target.as_path())
    {
        return Err(ERROR);
    }
    let creation = created(unsafe { GetCurrentProcess() })?;
    let nonce = random_token()?;
    let ready = prepared.stage.join(format!("ready-{nonce}"));
    if ready.try_exists().map_err(|_| ERROR)? {
        return Err(ERROR);
    }
    let child = Command::new(prepared.stage.join("routedeck-updater.exe"))
        .args([
            "--parent",
            &std::process::id().to_string(),
            "--created",
            &creation.to_string(),
            "--token",
            token,
            "--launch",
            &nonce,
        ])
        .current_dir(&prepared.stage)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .creation_flags(0x08000000)
        .spawn()
        .map_err(|_| ERROR)?;
    let mut pending = PendingChild {
        child,
        acknowledged: false,
    };
    // The updater authenticates and retains the exact parent before the GUI exits.
    let child_handle = unsafe {
        OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
            0,
            pending.child.id(),
        )
    };
    if child_handle.is_null() {
        pending.child.cancel();
        return Err(ERROR);
    }
    let exact_child = Process(child_handle);
    let child_creation = created(exact_child.0)?;
    let expected = format!("{}:{child_creation}:{nonce}", pending.child.id());
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if ready.try_exists().map_err(|_| ERROR)?
            && bounded_read(&ready, 128)? == expected.as_bytes()
            && unsafe { WaitForSingleObject(exact_child.0, 0) } == WAIT_TIMEOUT
        {
            pending.acknowledged = true;
            return Ok(());
        }
        if pending.child.try_wait().map_err(|_| ERROR)?.is_some() {
            return Err(ERROR);
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    // Never terminate by name; only the child launched by this invocation.
    pending.child.cancel();
    Err(ERROR)
}
pub(super) fn run() -> Result<()> {
    if crate::windows_process::current_process_is_elevated().map_err(|_| ERROR)? {
        return Err(ERROR);
    }
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.len() != 8
        || args[0] != "--parent"
        || args[2] != "--created"
        || args[4] != "--token"
        || args[6] != "--launch"
    {
        return Err(ERROR);
    }
    let pid = args[1].parse::<u32>().map_err(|_| ERROR)?;
    let creation = args[3].parse::<u64>().map_err(|_| ERROR)?;
    let token = &args[5];
    unhex::<16>(token)?;
    let nonce = &args[7];
    unhex::<16>(nonce)?;
    if pid == 0 || creation == 0 || actual_parent_pid()? != pid {
        return Err(ERROR);
    }
    let stage = stage_root()?.join(token);
    let executable = std::env::current_exe().map_err(|_| ERROR)?;
    if executable != stage.join("routedeck-updater.exe") {
        return Err(ERROR);
    }
    let _stage = DirectoryLease::observe(&stage)?;
    let handle = unsafe {
        OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
            0,
            pid,
        )
    };
    if handle.is_null() {
        return Err(ERROR);
    }
    let parent = Process(handle);
    if created(parent.0)? != creation || unsafe { WaitForSingleObject(parent.0, 0) } != WAIT_TIMEOUT
    {
        return Err(ERROR);
    }
    let image = process_image(parent.0)?;
    if image.file_name().and_then(|p| p.to_str()) != Some("routedeck.exe") {
        return Err(ERROR);
    }
    let target = image.parent().ok_or(ERROR)?;
    let target_parent = target.parent().ok_or(ERROR)?;
    let _ancestor = DirectoryLease::acquire(target_parent)?;
    // No UNC/network/protected-folder elevation fallback. Current user must own
    // a normal local portable folder, and target is derived only from parent.
    if target.to_str().is_none_or(|p| p.starts_with("\\\\")) {
        return Err(ERROR);
    }
    let current = signed_manifest(
        &bounded_read(&stage.join("current.json"), MANIFEST_LIMIT)?,
        &bounded_read(&stage.join("current.sig"), 64)?,
    )?;
    let next = signed_manifest(
        &bounded_read(&stage.join("next.json"), MANIFEST_LIMIT)?,
        &bounded_read(&stage.join("next.sig"), 64)?,
    )?;
    let gui = current
        .files
        .iter()
        .find(|f| f.path == "routedeck.exe")
        .ok_or(ERROR)?;
    let updater = current
        .files
        .iter()
        .find(|f| f.path == "routedeck-updater.exe")
        .ok_or(ERROR)?;
    digest_file(&image, gui)?;
    let _self_lease = digest_file(&executable, updater)?;
    verify_tree(target, &current, &[])?;
    verify_tree(&stage.join("payload"), &next, &[])?;
    let ack = format!(
        "{}:{}:{nonce}",
        std::process::id(),
        created(unsafe { GetCurrentProcess() })?
    );
    durable_new(&stage.join(format!("ready-{nonce}")), ack.as_bytes())?;
    if unsafe { WaitForSingleObject(parent.0, 60_000) } != WAIT_OBJECT_0 {
        return Err(ERROR);
    }
    drop(parent);
    drop(_ancestor);
    drop(_stage);
    replace_bundle(&stage, target, &next, &current, token, |_| Ok(()))?;
    // Verify all release bytes immediately before the fixed GUI launch. This
    // process never starts a helper, VPN engine, command or caller-selected exe.
    let _files = verify_tree(target, &next, &[])?;
    Command::new(target.join("routedeck.exe"))
        .current_dir(target)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .creation_flags(0x08000000)
        .spawn()
        .map_err(|_| ERROR)?;
    Ok(())
}
fn actual_parent_pid() -> Result<u32> {
    use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
        TH32CS_SNAPPROCESS,
    };
    let raw = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    if raw == INVALID_HANDLE_VALUE {
        return Err(ERROR);
    }
    let snapshot = Process(raw);
    let mut entry: PROCESSENTRY32W = unsafe { zeroed() };
    entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
    let mut ok = unsafe { Process32FirstW(snapshot.0, &mut entry) };
    while ok != 0 {
        if entry.th32ProcessID == std::process::id() {
            return Ok(entry.th32ParentProcessID);
        }
        ok = unsafe { Process32NextW(snapshot.0, &mut entry) };
    }
    Err(ERROR)
}
pub(crate) fn repair_notice() {
    let message: Vec<u16> = REPAIR.encode_utf16().chain(Some(0)).collect();
    let title: Vec<u16> = "RouteDeck: manual repair required"
        .encode_utf16()
        .chain(Some(0))
        .collect();
    unsafe {
        MessageBoxW(
            ptr::null_mut(),
            message.as_ptr(),
            title.as_ptr(),
            MB_OK | MB_ICONERROR,
        );
    }
}
pub(super) fn rename_directory(lease: &DirectoryLease, target: &Path) -> Result<()> {
    use std::os::windows::{ffi::OsStrExt, io::AsRawHandle};
    use windows_sys::Win32::Storage::FileSystem::{
        FileRenameInfo, SetFileInformationByHandle, FILE_RENAME_INFO,
    };
    let name: Vec<u16> = target.as_os_str().encode_wide().collect();
    let base = std::mem::offset_of!(FILE_RENAME_INFO, FileName);
    let bytes = base.checked_add(name.len() * 2).ok_or(ERROR)?;
    let mut storage = vec![0usize; bytes.div_ceil(std::mem::size_of::<usize>())];
    let info = storage.as_mut_ptr().cast::<FILE_RENAME_INFO>();
    unsafe {
        (*info).Anonymous.ReplaceIfExists = false;
        (*info).RootDirectory = ptr::null_mut();
        (*info).FileNameLength = (name.len() * 2) as u32;
        ptr::copy_nonoverlapping(name.as_ptr(), (*info).FileName.as_mut_ptr(), name.len());
        let file = lease._handles.last().ok_or(ERROR)?;
        if SetFileInformationByHandle(
            file.as_raw_handle(),
            FileRenameInfo,
            info.cast(),
            bytes as u32,
        ) == 0
        {
            return Err(ERROR);
        }
    }
    Ok(())
}
pub(super) fn verify_private_directory(
    lease: &DirectoryLease,
    require_protected: bool,
) -> Result<()> {
    verify_object_acl(lease._handles.last().ok_or(ERROR)?, require_protected)
}
pub(super) fn verify_file(file: &File) -> Result<()> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION,
    };
    let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { zeroed() };
    if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) } == 0
        || info.nNumberOfLinks != 1
    {
        return Err(ERROR);
    }
    verify_object_acl(file, false)
}
fn verify_object_acl(file: &File, require_protected: bool) -> Result<()> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::{
        Foundation::LocalFree,
        Security::{
            AclSizeInformation,
            Authorization::{GetSecurityInfo, SE_FILE_OBJECT},
            CreateWellKnownSid, EqualSid, GetAce, GetAclInformation, GetSecurityDescriptorControl,
            WinBuiltinAdministratorsSid, WinLocalSystemSid, ACCESS_ALLOWED_ACE,
            ACL_SIZE_INFORMATION, DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION,
            SE_DACL_PROTECTED,
        },
    };
    let current = crate::engine_runtime::current_user_sid().map_err(|_| ERROR)?;
    let mut system = [0u8; 68];
    let mut administrators = [0u8; 68];
    let mut system_len = 68;
    let mut admin_len = 68;
    if unsafe {
        CreateWellKnownSid(
            WinLocalSystemSid,
            ptr::null_mut(),
            system.as_mut_ptr().cast(),
            &mut system_len,
        )
    } == 0
        || unsafe {
            CreateWellKnownSid(
                WinBuiltinAdministratorsSid,
                ptr::null_mut(),
                administrators.as_mut_ptr().cast(),
                &mut admin_len,
            )
        } == 0
    {
        return Err(ERROR);
    }
    let mut owner = ptr::null_mut();
    let mut dacl = ptr::null_mut();
    let mut descriptor = ptr::null_mut();
    if unsafe {
        GetSecurityInfo(
            file.as_raw_handle(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            ptr::null_mut(),
            &mut dacl,
            ptr::null_mut(),
            &mut descriptor,
        )
    } != 0
        || descriptor.is_null()
    {
        return Err(ERROR);
    }
    let result = (|| {
        if owner.is_null()
            || dacl.is_null()
            || (unsafe { EqualSid(owner, current.as_ptr().cast_mut().cast()) } == 0
                && (require_protected
                    || unsafe { EqualSid(owner, administrators.as_mut_ptr().cast()) } == 0))
        {
            return Err(ERROR);
        }
        let mut control = 0;
        let mut revision = 0;
        if unsafe { GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) } == 0
            || (require_protected && control & SE_DACL_PROTECTED == 0)
        {
            return Err(ERROR);
        }
        let mut info: ACL_SIZE_INFORMATION = unsafe { zeroed() };
        if unsafe {
            GetAclInformation(
                dacl,
                (&mut info as *mut ACL_SIZE_INFORMATION).cast(),
                std::mem::size_of_val(&info) as u32,
                AclSizeInformation,
            )
        } == 0
        {
            return Err(ERROR);
        }
        for index in 0..info.AceCount {
            let mut ace = ptr::null_mut();
            if unsafe { GetAce(dacl, index, &mut ace) } == 0 {
                return Err(ERROR);
            }
            let allowed = unsafe { &*ace.cast::<ACCESS_ALLOWED_ACE>() };
            if allowed.Header.AceType != 0 {
                return Err(ERROR);
            }
            let sid = (&allowed.SidStart as *const u32).cast_mut().cast();
            let trusted = unsafe {
                EqualSid(sid, current.as_ptr().cast_mut().cast()) != 0
                    || EqualSid(sid, system.as_mut_ptr().cast()) != 0
                    || EqualSid(sid, administrators.as_mut_ptr().cast()) != 0
            };
            // Untrusted principals may read an installed folder, never mutate it.
            const WRITE_OR_DELETE: u32 = 0x40000000 | 0x10000000 | 0x000d0156;
            if !trusted && (require_protected || allowed.Mask & WRITE_OR_DELETE != 0) {
                return Err(ERROR);
            }
        }
        Ok(())
    })();
    unsafe {
        LocalFree(descriptor);
    };
    result
}

//! Bounded Windows DNS with callback-owned native buffers and cancellation.
use std::{
    cell::UnsafeCell,
    mem::size_of,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    ptr,
    sync::{
        atomic::{AtomicBool, AtomicI32, AtomicUsize, Ordering},
        Arc, OnceLock,
    },
    time::{Duration, Instant},
};

use windows_sys::Win32::{
    Foundation::{CloseHandle, HANDLE, WAIT_OBJECT_0, WAIT_TIMEOUT},
    Networking::WinSock::{
        FreeAddrInfoExW, GetAddrInfoExCancel, GetAddrInfoExW, WSACleanup, WSAStartup, ADDRINFOEXW,
        AF_INET, AF_INET6, AF_UNSPEC, IPPROTO_TCP, NS_DNS, SOCKADDR_IN, SOCKADDR_IN6, SOCK_STREAM,
        WSADATA, WSA_IO_PENDING,
    },
    System::{
        Threading::{CreateEventW, SetEvent, WaitForSingleObject},
        IO::OVERLAPPED,
    },
};

use super::{
    dns_fetch_error, policy_error, timeout_error_at, windows_dns_error, SubscriptionFetchError,
    SubscriptionFetchStage, MAX_RESOLVED_ADDRESSES,
};

const MAX_OUTSTANDING_DNS: usize = 4;
static OUTSTANDING: OnceLock<Arc<AtomicUsize>> = OnceLock::new();

trait DnsApi: Send + Sync {
    fn startup(&self) -> bool;
    fn cleanup(&self);
    fn create_event(&self) -> HANDLE;
    fn close_event(&self, event: HANDLE);
    fn signal(&self, event: HANDLE);
    fn begin(&self, query: &Query) -> i32;
    fn wait(&self, event: HANDLE, milliseconds: u32) -> u32;
    fn cancel(&self, handle: HANDLE) -> i32;
    unsafe fn free_results(&self, results: *mut ADDRINFOEXW);
}

struct NativeApi;
impl DnsApi for NativeApi {
    fn startup(&self) -> bool {
        unsafe { WSAStartup(0x0202, &mut WSADATA::default()) == 0 }
    }
    fn cleanup(&self) {
        unsafe { WSACleanup() };
    }
    fn create_event(&self) -> HANDLE {
        unsafe { CreateEventW(ptr::null(), 1, 0, ptr::null()) }
    }
    fn close_event(&self, event: HANDLE) {
        unsafe { CloseHandle(event) };
    }
    fn signal(&self, event: HANDLE) {
        unsafe { SetEvent(event) };
    }
    fn begin(&self, query: &Query) -> i32 {
        // Windows' documented asynchronous pattern: no native timeout pointer,
        // OVERLAPPED.hEvent remains NULL when a callback is supplied.
        unsafe {
            GetAddrInfoExW(
                query.name.as_ptr(),
                ptr::null(),
                NS_DNS,
                ptr::null(),
                &query.hints,
                query.results.get(),
                ptr::null(),
                query.overlapped.get(),
                Some(complete),
                query.cancel_handle.get(),
            )
        }
    }
    fn wait(&self, event: HANDLE, milliseconds: u32) -> u32 {
        unsafe { WaitForSingleObject(event, milliseconds) }
    }
    fn cancel(&self, handle: HANDLE) -> i32 {
        // Nonblocking. Even on cancellation failure, the completion reference
        // retains every native buffer and the outstanding-request permit.
        unsafe { GetAddrInfoExCancel(&handle) }
    }
    unsafe fn free_results(&self, results: *mut ADDRINFOEXW) {
        unsafe { FreeAddrInfoExW(results) };
    }
}

struct Permit(Arc<AtomicUsize>);
impl Permit {
    fn acquire(counter: Arc<AtomicUsize>) -> Option<Self> {
        counter
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                (count < MAX_OUTSTANDING_DNS).then_some(count + 1)
            })
            .ok()?;
        Some(Self(counter))
    }
}
impl Drop for Permit {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

#[repr(C)]
struct Query {
    // Must be first: the callback receives this pointer, not an application context.
    overlapped: UnsafeCell<OVERLAPPED>,
    results: UnsafeCell<*mut ADDRINFOEXW>,
    cancel_handle: UnsafeCell<HANDLE>,
    name: Vec<u16>,
    hints: ADDRINFOEXW,
    event: HANDLE,
    completed: AtomicBool,
    status: AtomicI32,
    api: Arc<dyn DnsApi>,
    _permit: Permit,
}

// Native writes are confined to UnsafeCells until the completion callback. The
// release/acquire completion flag publishes results before the caller reads them;
// an OS-owned Arc keeps buffers alive if the bounded caller has already returned.
unsafe impl Send for Query {}
unsafe impl Sync for Query {}

impl Drop for Query {
    fn drop(&mut self) {
        let results = *self.results.get_mut();
        if !results.is_null() {
            unsafe { self.api.free_results(results) };
        }
        self.api.close_event(self.event);
        self.api.cleanup();
    }
}

unsafe extern "system" fn complete(status: u32, _bytes: u32, overlapped: *const OVERLAPPED) {
    // Exactly one completion owns the raw Arc: Windows for WSA_IO_PENDING, or
    // the initiating thread for every other return code (per Microsoft's sample).
    let query = unsafe { Arc::from_raw(overlapped.cast::<Query>()) };
    query.status.store(status as i32, Ordering::Relaxed);
    query.completed.store(true, Ordering::Release);
    query.api.signal(query.event);
}

pub(super) fn resolve(
    host: &str,
    timeout: Duration,
) -> Result<Vec<IpAddr>, SubscriptionFetchError> {
    resolve_with(
        host,
        timeout,
        Arc::new(NativeApi),
        OUTSTANDING
            .get_or_init(|| Arc::new(AtomicUsize::new(0)))
            .clone(),
    )
}

fn resolve_with(
    host: &str,
    timeout: Duration,
    api: Arc<dyn DnsApi>,
    counter: Arc<AtomicUsize>,
) -> Result<Vec<IpAddr>, SubscriptionFetchError> {
    if timeout.is_zero() {
        return Err(timeout_error_at(SubscriptionFetchStage::Dns));
    }
    let started = Instant::now();
    let permit = Permit::acquire(counter).ok_or_else(dns_fetch_error)?;
    if !api.startup() {
        return Err(dns_fetch_error());
    }
    let event = api.create_event();
    if event.is_null() {
        api.cleanup();
        return Err(dns_fetch_error());
    }
    let query = Arc::new(Query {
        overlapped: UnsafeCell::new(OVERLAPPED::default()),
        results: UnsafeCell::new(ptr::null_mut()),
        cancel_handle: UnsafeCell::new(ptr::null_mut()),
        name: host.encode_utf16().chain(Some(0)).collect(),
        hints: ADDRINFOEXW {
            ai_family: AF_UNSPEC as i32,
            ai_socktype: SOCK_STREAM,
            ai_protocol: IPPROTO_TCP,
            ..Default::default()
        },
        event,
        completed: AtomicBool::new(false),
        status: AtomicI32::new(WSA_IO_PENDING),
        api,
        _permit: permit,
    });
    let completion_ref = Arc::into_raw(Arc::clone(&query));
    debug_assert_eq!(
        completion_ref.cast::<OVERLAPPED>(),
        query.overlapped.get().cast_const()
    );
    let status = query.api.begin(&query);
    if status != WSA_IO_PENDING {
        unsafe { complete(status as u32, 0, completion_ref.cast::<OVERLAPPED>()) };
    }
    let mut wait_status = WAIT_OBJECT_0;
    if !query.completed.load(Ordering::Acquire) {
        let remaining = timeout.saturating_sub(started.elapsed());
        let milliseconds = remaining.as_millis().min((u32::MAX - 1) as u128) as u32;
        wait_status = query.api.wait(query.event, milliseconds);
    }
    if !query.completed.load(Ordering::Acquire) {
        let cancel_handle = unsafe { *query.cancel_handle.get() };
        if !cancel_handle.is_null() {
            let _ = query.api.cancel(cancel_handle);
        }
        return Err(if wait_status == WAIT_TIMEOUT {
            timeout_error_at(SubscriptionFetchStage::Dns)
        } else {
            dns_fetch_error()
        });
    }
    let status = query.status.load(Ordering::Relaxed);
    if status != 0 {
        return Err(windows_dns_error(status));
    }
    // Completion has published the list. Query's caller Arc prevents its release
    // while copying addresses, even if the callback exits concurrently.
    unsafe { copy_addresses(*query.results.get()) }
}

unsafe fn copy_addresses(
    mut current: *mut ADDRINFOEXW,
) -> Result<Vec<IpAddr>, SubscriptionFetchError> {
    let mut addresses = Vec::new();
    while !current.is_null() {
        if addresses.len() == MAX_RESOLVED_ADDRESSES {
            return Err(policy_error(SubscriptionFetchStage::Dns));
        }
        let entry = unsafe { &*current };
        if entry.ai_addr.is_null() {
            return Err(policy_error(SubscriptionFetchStage::Dns));
        }
        match entry.ai_family as u16 {
            AF_INET if entry.ai_addrlen >= size_of::<SOCKADDR_IN>() => {
                let address = unsafe { &*entry.ai_addr.cast::<SOCKADDR_IN>() };
                let bytes = unsafe { address.sin_addr.S_un.S_un_b };
                addresses.push(IpAddr::V4(Ipv4Addr::new(
                    bytes.s_b1, bytes.s_b2, bytes.s_b3, bytes.s_b4,
                )));
            }
            AF_INET6 if entry.ai_addrlen >= size_of::<SOCKADDR_IN6>() => {
                let address = unsafe { &*entry.ai_addr.cast::<SOCKADDR_IN6>() };
                addresses.push(IpAddr::V6(Ipv6Addr::from(unsafe {
                    address.sin6_addr.u.Byte
                })));
            }
            _ => return Err(policy_error(SubscriptionFetchStage::Dns)),
        }
        current = entry.ai_next;
    }
    Ok(addresses)
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows_sys::Win32::{
        Foundation::WAIT_FAILED,
        Networking::WinSock::{IN_ADDR, IN_ADDR_0, WSAEINVAL, WSA_OPERATION_ABORTED},
    };

    #[derive(Clone, Copy)]
    enum Mode {
        ImmediateSuccess,
        ImmediateError,
        CallbackBeforeReturn,
        CallbackDuringWait,
        TimeoutLate,
        TimeoutCompletionRace,
        TimeoutCancelRace,
        CancelFailure,
        MissingCancelHandle,
        WaitFailure,
        StartupFailure,
        EventFailure,
    }

    struct FakeApi {
        mode: Mode,
        query: AtomicUsize,
        startups: AtomicUsize,
        cleanups: AtomicUsize,
        closes: AtomicUsize,
        frees: AtomicUsize,
        signals: AtomicUsize,
        waits: AtomicUsize,
        cancels: AtomicUsize,
    }

    #[repr(C)]
    struct FakeResult {
        node: ADDRINFOEXW,
        address: SOCKADDR_IN,
    }

    impl FakeApi {
        fn new(mode: Mode) -> Arc<Self> {
            Arc::new(Self {
                mode,
                query: AtomicUsize::new(0),
                startups: AtomicUsize::new(0),
                cleanups: AtomicUsize::new(0),
                closes: AtomicUsize::new(0),
                frees: AtomicUsize::new(0),
                signals: AtomicUsize::new(0),
                waits: AtomicUsize::new(0),
                cancels: AtomicUsize::new(0),
            })
        }

        fn put_result(query: &Query) {
            let mut result = Box::new(FakeResult {
                node: ADDRINFOEXW {
                    ai_family: AF_INET as i32,
                    ai_addrlen: size_of::<SOCKADDR_IN>(),
                    ..Default::default()
                },
                address: SOCKADDR_IN {
                    sin_family: AF_INET,
                    sin_addr: IN_ADDR {
                        S_un: IN_ADDR_0 {
                            S_addr: u32::from_ne_bytes([127, 0, 0, 1]),
                        },
                    },
                    ..Default::default()
                },
            });
            result.node.ai_addr = (&mut result.address as *mut SOCKADDR_IN).cast();
            unsafe { *query.results.get() = Box::into_raw(result).cast() };
        }

        fn finish(&self, status: i32) {
            let raw = self.query.swap(0, Ordering::AcqRel) as *const Query;
            assert!(
                !raw.is_null(),
                "completion must have exactly one live native reference"
            );
            let query = unsafe { &*raw };
            if status == 0 {
                Self::put_result(query);
            }
            unsafe { complete(status as u32, 0, query.overlapped.get()) };
        }

        fn assert_released(&self, counter: &AtomicUsize, results: usize) {
            assert_eq!(self.cleanups.load(Ordering::Acquire), 1);
            assert_eq!(self.closes.load(Ordering::Acquire), 1);
            assert_eq!(self.frees.load(Ordering::Acquire), results);
            assert_eq!(self.signals.load(Ordering::Acquire), 1);
            assert_eq!(counter.load(Ordering::Acquire), 0);
        }
    }

    impl DnsApi for FakeApi {
        fn startup(&self) -> bool {
            self.startups.fetch_add(1, Ordering::AcqRel);
            !matches!(self.mode, Mode::StartupFailure)
        }
        fn cleanup(&self) {
            self.cleanups.fetch_add(1, Ordering::AcqRel);
        }
        fn create_event(&self) -> HANDLE {
            if matches!(self.mode, Mode::EventFailure) {
                ptr::null_mut()
            } else {
                1usize as HANDLE
            }
        }
        fn close_event(&self, _event: HANDLE) {
            self.closes.fetch_add(1, Ordering::AcqRel);
        }
        fn signal(&self, _event: HANDLE) {
            self.signals.fetch_add(1, Ordering::AcqRel);
        }
        fn begin(&self, query: &Query) -> i32 {
            assert!(unsafe { (*query.overlapped.get()).hEvent.is_null() });
            assert_eq!(query.name.last(), Some(&0));
            match self.mode {
                Mode::ImmediateSuccess => {
                    Self::put_result(query);
                    0
                }
                Mode::ImmediateError => WSAEINVAL,
                _ => {
                    self.query
                        .store(query as *const Query as usize, Ordering::Release);
                    if !matches!(self.mode, Mode::MissingCancelHandle) {
                        unsafe { *query.cancel_handle.get() = 2usize as HANDLE };
                    }
                    if matches!(self.mode, Mode::CallbackBeforeReturn) {
                        self.finish(0);
                    }
                    WSA_IO_PENDING
                }
            }
        }
        fn wait(&self, _event: HANDLE, milliseconds: u32) -> u32 {
            self.waits.fetch_add(1, Ordering::AcqRel);
            assert_ne!(milliseconds, u32::MAX, "no infinite wait is permitted");
            match self.mode {
                Mode::CallbackDuringWait => {
                    self.finish(0);
                    WAIT_OBJECT_0
                }
                Mode::TimeoutCompletionRace => {
                    self.finish(0);
                    WAIT_TIMEOUT
                }
                Mode::WaitFailure => WAIT_FAILED,
                _ => WAIT_TIMEOUT,
            }
        }
        fn cancel(&self, _handle: HANDLE) -> i32 {
            self.cancels.fetch_add(1, Ordering::AcqRel);
            if matches!(self.mode, Mode::TimeoutCancelRace) {
                self.finish(0);
            }
            if matches!(self.mode, Mode::CancelFailure) {
                WSAEINVAL
            } else {
                0
            }
        }
        unsafe fn free_results(&self, results: *mut ADDRINFOEXW) {
            self.frees.fetch_add(1, Ordering::AcqRel);
            unsafe { drop(Box::from_raw(results.cast::<FakeResult>())) };
        }
    }

    fn run(
        api: &Arc<FakeApi>,
        counter: &Arc<AtomicUsize>,
    ) -> Result<Vec<IpAddr>, SubscriptionFetchError> {
        resolve_with(
            "fixture.invalid",
            Duration::from_millis(20),
            api.clone(),
            counter.clone(),
        )
    }

    #[test]
    fn immediate_and_pending_success_release_results_event_and_winsock_once() {
        for mode in [
            Mode::ImmediateSuccess,
            Mode::CallbackBeforeReturn,
            Mode::CallbackDuringWait,
            Mode::TimeoutCompletionRace,
        ] {
            let api = FakeApi::new(mode);
            let counter = Arc::new(AtomicUsize::new(0));
            assert_eq!(
                run(&api, &counter).unwrap(),
                vec![IpAddr::V4(Ipv4Addr::LOCALHOST)]
            );
            assert_eq!(api.cancels.load(Ordering::Acquire), 0);
            api.assert_released(&counter, 1);
        }
    }

    #[test]
    fn synchronous_error_completes_manually_without_wait_or_native_callback() {
        let api = FakeApi::new(Mode::ImmediateError);
        let counter = Arc::new(AtomicUsize::new(0));
        assert_eq!(
            run(&api, &counter).unwrap_err().stage(),
            SubscriptionFetchStage::Dns
        );
        assert_eq!(api.waits.load(Ordering::Acquire), 0);
        api.assert_released(&counter, 0);
    }

    #[test]
    fn timeout_and_cancel_failure_retain_buffers_until_late_callback() {
        for mode in [
            Mode::TimeoutLate,
            Mode::CancelFailure,
            Mode::WaitFailure,
            Mode::MissingCancelHandle,
        ] {
            let api = FakeApi::new(mode);
            let counter = Arc::new(AtomicUsize::new(0));
            let error = run(&api, &counter).unwrap_err();
            assert_eq!(error.stage(), SubscriptionFetchStage::Dns);
            assert_eq!(
                api.cancels.load(Ordering::Acquire),
                usize::from(!matches!(mode, Mode::MissingCancelHandle))
            );
            assert_eq!(api.cleanups.load(Ordering::Acquire), 0);
            assert_eq!(api.closes.load(Ordering::Acquire), 0);
            assert_eq!(counter.load(Ordering::Acquire), 1);
            api.finish(WSA_OPERATION_ABORTED);
            api.assert_released(&counter, 0);
        }
    }

    #[test]
    fn completion_during_cancel_never_double_frees_or_cleans_up_early() {
        let api = FakeApi::new(Mode::TimeoutCancelRace);
        let counter = Arc::new(AtomicUsize::new(0));
        assert_eq!(
            run(&api, &counter).unwrap_err().kind(),
            super::super::SubscriptionFetchErrorKind::Timeout
        );
        api.assert_released(&counter, 1);
    }

    #[test]
    fn late_success_after_caller_timeout_frees_the_result_once() {
        let api = FakeApi::new(Mode::TimeoutLate);
        let counter = Arc::new(AtomicUsize::new(0));
        assert!(run(&api, &counter).is_err());
        assert_eq!(api.cleanups.load(Ordering::Acquire), 0);
        api.finish(0);
        api.assert_released(&counter, 1);
    }

    #[test]
    fn outstanding_cap_survives_timeout_until_os_completion_releases_permit() {
        let counter = Arc::new(AtomicUsize::new(0));
        let pending = (0..MAX_OUTSTANDING_DNS)
            .map(|_| FakeApi::new(Mode::TimeoutLate))
            .collect::<Vec<_>>();
        for api in &pending {
            assert!(run(api, &counter).is_err());
        }
        let blocked = FakeApi::new(Mode::ImmediateSuccess);
        assert!(run(&blocked, &counter).is_err());
        assert_eq!(blocked.startups.load(Ordering::Acquire), 0);
        for api in &pending {
            api.finish(WSA_OPERATION_ABORTED);
        }
        assert_eq!(counter.load(Ordering::Acquire), 0);
        assert!(run(&blocked, &counter).is_ok());
        blocked.assert_released(&counter, 1);
    }

    #[test]
    fn construction_failures_release_permit_without_invalid_cleanup() {
        for mode in [Mode::StartupFailure, Mode::EventFailure] {
            let api = FakeApi::new(mode);
            let counter = Arc::new(AtomicUsize::new(0));
            assert!(run(&api, &counter).is_err());
            assert_eq!(counter.load(Ordering::Acquire), 0);
            assert_eq!(api.closes.load(Ordering::Acquire), 0);
            assert_eq!(
                api.cleanups.load(Ordering::Acquire),
                usize::from(matches!(mode, Mode::EventFailure))
            );
        }
    }

    #[test]
    fn native_async_localhost_resolution_uses_no_external_endpoint() {
        let result = resolve("localhost", Duration::from_secs(2)).unwrap();
        assert!(!result.is_empty());
        assert!(result.iter().all(IpAddr::is_loopback));
    }
}

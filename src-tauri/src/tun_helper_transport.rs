//! Bounded, private named-pipe transport. No privilege or network configuration API.

use crate::tun_helper_protocol::{self as protocol, Frame, MAX_FRAME_BYTES};
use std::{
    cell::{Cell, UnsafeCell},
    fmt,
    fs::File,
    io::Cursor,
    os::windows::io::{AsRawHandle, FromRawHandle},
    ptr,
    sync::{
        atomic::{AtomicUsize, Ordering},
        mpsc::{self, Sender},
        OnceLock,
    },
    thread,
    time::{Duration, Instant},
};
use windows_sys::Win32::{
    Foundation::{
        CloseHandle, DuplicateHandle, GetLastError, DUPLICATE_SAME_ACCESS, ERROR_IO_PENDING,
        ERROR_PIPE_CONNECTED, HANDLE, WAIT_OBJECT_0, WAIT_TIMEOUT,
    },
    Storage::FileSystem::{ReadFile, WriteFile},
    System::{
        Pipes::{ConnectNamedPipe, PeekNamedPipe},
        Threading::{CreateEventW, GetCurrentProcess, WaitForSingleObject},
        IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED},
    },
};

const MAX_OUTSTANDING: usize = 8;
const FRAME_TIMEOUT: Duration = Duration::from_secs(30);
const CANCEL_DRAIN: Duration = Duration::from_millis(100);
static OUTSTANDING: AtomicUsize = AtomicUsize::new(0);
static REAPER: OnceLock<Result<Sender<NativeOperation>, ()>> = OnceLock::new();

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TransportError {
    Io { operation: &'static str, code: u32 },
    Timeout,
    Busy,
    Poisoned,
    Protocol,
}
impl fmt::Display for TransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { operation, code } => {
                write!(f, "helper pipe {operation} failed (Windows error {code})")
            }
            Self::Timeout => f.write_str("helper pipe operation exceeded its deadline"),
            Self::Busy => f.write_str("helper pipe cancellation is still completing; retry later"),
            Self::Poisoned => f.write_str("helper pipe is closed after an incomplete operation"),
            Self::Protocol => f.write_str("helper pipe frame was rejected"),
        }
    }
}

struct Event(HANDLE);
impl Drop for Event {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.0);
        }
    }
}
struct Permit;
impl Permit {
    fn acquire() -> Result<Self, TransportError> {
        OUTSTANDING
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                (count < MAX_OUTSTANDING).then_some(count + 1)
            })
            .map(|_| Self)
            .map_err(|_| TransportError::Busy)
    }
}
impl Drop for Permit {
    fn drop(&mut self) {
        OUTSTANDING.fetch_sub(1, Ordering::AcqRel);
    }
}

// All pointers passed to Win32 refer to heap allocations owned by this object.
// Moving it into the bounded reaper never moves the OVERLAPPED or byte buffer.
struct NativeOperation {
    file: File,
    overlapped: Box<UnsafeCell<OVERLAPPED>>,
    bytes: Vec<u8>,
    event: Event,
    _permit: Permit,
}
unsafe impl Send for NativeOperation {}

fn reaper() -> Result<&'static Sender<NativeOperation>, TransportError> {
    REAPER.get_or_init(|| {
        let (sender, receiver) = mpsc::channel::<NativeOperation>();
        thread::Builder::new().name("routedeck-pipe-completion".into()).spawn(move || {
            let mut pending = Vec::<NativeOperation>::new();
            loop {
                match receiver.recv_timeout(Duration::from_millis(20)) {
                    Ok(operation) => pending.push(operation),
                    Err(mpsc::RecvTimeoutError::Timeout) => {},
                    Err(mpsc::RecvTimeoutError::Disconnected) if pending.is_empty() => break,
                    Err(mpsc::RecvTimeoutError::Disconnected) => thread::sleep(Duration::from_millis(20)),
                }
                // A signalled per-operation event is proof native I/O no longer uses the buffers.
                pending.retain(|operation| unsafe { WaitForSingleObject(operation.event.0, 0) } != WAIT_OBJECT_0);
            }
        }).map(|_| sender).map_err(|_| ())
    }).as_ref().map_err(|_| TransportError::Busy)
}

impl NativeOperation {
    fn new(file: &File, bytes: Vec<u8>) -> Result<Self, TransportError> {
        // Initialize the only reaper and reserve capacity before issuing native I/O.
        reaper()?;
        let permit = Permit::acquire()?;
        let mut duplicate = ptr::null_mut();
        if unsafe {
            DuplicateHandle(
                GetCurrentProcess(),
                file.as_raw_handle(),
                GetCurrentProcess(),
                &mut duplicate,
                0,
                0,
                DUPLICATE_SAME_ACCESS,
            )
        } == 0
        {
            return Err(TransportError::Io {
                operation: "duplicate",
                code: unsafe { GetLastError() },
            });
        }
        let file = unsafe { File::from_raw_handle(duplicate) };
        let event = unsafe { CreateEventW(ptr::null(), 1, 0, ptr::null()) };
        if event.is_null() {
            return Err(TransportError::Io {
                operation: "event",
                code: unsafe { GetLastError() },
            });
        }
        let overlapped = Box::new(UnsafeCell::new(OVERLAPPED {
            hEvent: event,
            ..Default::default()
        }));
        Ok(Self {
            file,
            overlapped,
            bytes,
            event: Event(event),
            _permit: permit,
        })
    }

    fn finish(
        self,
        immediate: bool,
        deadline: Instant,
        operation: &'static str,
    ) -> Result<(Self, usize), TransportError> {
        if !immediate {
            let left = deadline.saturating_duration_since(Instant::now());
            let milliseconds = left.as_millis().min((u32::MAX - 1) as u128) as u32;
            let wait = unsafe { WaitForSingleObject(self.event.0, milliseconds) };
            if wait != WAIT_OBJECT_0 {
                let wait_error = if wait == WAIT_TIMEOUT {
                    0
                } else {
                    unsafe { GetLastError() }
                };
                // Never free an in-flight OVERLAPPED, even if cancellation fails or completes late.
                unsafe {
                    CancelIoEx(self.file.as_raw_handle(), self.overlapped.get());
                }
                if unsafe { WaitForSingleObject(self.event.0, CANCEL_DRAIN.as_millis() as u32) }
                    != WAIT_OBJECT_0
                {
                    if let Err(error) = reaper().expect("reaper initialized before I/O").send(self)
                    {
                        // The cap remains held if the process-wide reaper unexpectedly died.
                        std::mem::forget(error.0);
                    }
                }
                return Err(if wait == WAIT_TIMEOUT {
                    TransportError::Timeout
                } else {
                    TransportError::Io {
                        operation: "wait",
                        code: wait_error,
                    }
                });
            }
        }
        let mut transferred = 0;
        if unsafe {
            GetOverlappedResult(
                self.file.as_raw_handle(),
                self.overlapped.get(),
                &mut transferred,
                0,
            )
        } == 0
        {
            return Err(TransportError::Io {
                operation,
                code: unsafe { GetLastError() },
            });
        }
        Ok((self, transferred as usize))
    }
}

pub(crate) struct PipeTransport {
    file: Option<File>,
    poisoned: Cell<bool>,
}
impl AsRawHandle for PipeTransport {
    fn as_raw_handle(&self) -> std::os::windows::io::RawHandle {
        self.file
            .as_ref()
            .map_or(ptr::null_mut(), AsRawHandle::as_raw_handle)
    }
}
impl PipeTransport {
    pub(crate) fn new(file: File) -> Self {
        Self {
            file: Some(file),
            poisoned: Cell::new(false),
        }
    }
    fn file(&self) -> Result<&File, TransportError> {
        self.file
            .as_ref()
            .filter(|_| !self.poisoned.get())
            .ok_or(TransportError::Poisoned)
    }
    fn poison<T>(&mut self, result: Result<T, TransportError>) -> Result<T, TransportError> {
        if result.is_err() {
            self.poisoned.set(true);
            self.file.take();
        }
        result
    }
    pub(crate) fn connect(&mut self, timeout: Duration) -> Result<(), TransportError> {
        let deadline = Instant::now() + timeout;
        let created = NativeOperation::new(self.file()?, vec![]);
        let operation = self.poison(created)?;
        let connected =
            unsafe { ConnectNamedPipe(operation.file.as_raw_handle(), operation.overlapped.get()) };
        let result = if connected != 0 {
            Ok(())
        } else {
            match unsafe { GetLastError() } {
                ERROR_PIPE_CONNECTED => Ok(()),
                ERROR_IO_PENDING => operation.finish(false, deadline, "connect").map(|_| ()),
                code => Err(TransportError::Io {
                    operation: "connect",
                    code,
                }),
            }
        };
        self.poison(result)
    }

    fn read_exact_until(
        &mut self,
        bytes: &mut [u8],
        deadline: Instant,
    ) -> Result<(), TransportError> {
        let mut offset = 0;
        while offset < bytes.len() {
            if Instant::now() >= deadline {
                return self.poison(Err(TransportError::Timeout));
            }
            let created = NativeOperation::new(self.file()?, vec![0; bytes.len() - offset]);
            let mut operation = self.poison(created)?;
            let done = unsafe {
                ReadFile(
                    operation.file.as_raw_handle(),
                    operation.bytes.as_mut_ptr(),
                    operation.bytes.len() as u32,
                    ptr::null_mut(),
                    operation.overlapped.get(),
                )
            };
            let result = if done != 0 {
                operation.finish(true, deadline, "read")
            } else {
                match unsafe { GetLastError() } {
                    ERROR_IO_PENDING => operation.finish(false, deadline, "read"),
                    code => Err(TransportError::Io {
                        operation: "read",
                        code,
                    }),
                }
            };
            let (operation, count) = self.poison(result)?;
            if count == 0 || count > bytes.len() - offset {
                return self.poison(Err(TransportError::Protocol));
            }
            bytes[offset..offset + count].copy_from_slice(&operation.bytes[..count]);
            offset += count;
        }
        Ok(())
    }

    fn write_all_until(&mut self, bytes: &[u8], deadline: Instant) -> Result<(), TransportError> {
        let mut offset = 0;
        while offset < bytes.len() {
            if Instant::now() >= deadline {
                return self.poison(Err(TransportError::Timeout));
            }
            let created = NativeOperation::new(self.file()?, bytes[offset..].to_vec());
            let operation = self.poison(created)?;
            let done = unsafe {
                WriteFile(
                    operation.file.as_raw_handle(),
                    operation.bytes.as_ptr(),
                    operation.bytes.len() as u32,
                    ptr::null_mut(),
                    operation.overlapped.get(),
                )
            };
            let result = if done != 0 {
                operation.finish(true, deadline, "write")
            } else {
                match unsafe { GetLastError() } {
                    ERROR_IO_PENDING => operation.finish(false, deadline, "write"),
                    code => Err(TransportError::Io {
                        operation: "write",
                        code,
                    }),
                }
            };
            let (_, count) = self.poison(result)?;
            if count == 0 || count > bytes.len() - offset {
                return self.poison(Err(TransportError::Protocol));
            }
            offset += count;
        }
        Ok(())
    }
    pub(crate) fn read_frame_until(&mut self, deadline: Instant) -> Result<Frame, TransportError> {
        let mut length = [0; 4];
        self.read_exact_until(&mut length, deadline)?;
        let count = u32::from_le_bytes(length) as usize;
        if count == 0 || count > MAX_FRAME_BYTES {
            return self.poison(Err(TransportError::Protocol));
        }
        let mut bytes = vec![0; count + 4];
        bytes[..4].copy_from_slice(&length);
        self.read_exact_until(&mut bytes[4..], deadline)?;
        let result =
            protocol::read_frame(&mut Cursor::new(bytes)).map_err(|_| TransportError::Protocol);
        self.poison(result)
    }

    // Healthy idle is not a lease expiry. Wait for the first byte while monitoring
    // the already-authenticated parent's process handle; once a byte arrives the
    // entire frame must complete within the normal transaction deadline.
    pub(crate) fn read_frame_from_peer(&mut self, peer: HANDLE) -> Result<Frame, TransportError> {
        self.read_frame_after_idle(peer, FRAME_TIMEOUT)
    }
    fn read_frame_after_idle(
        &mut self,
        peer: HANDLE,
        frame_timeout: Duration,
    ) -> Result<Frame, TransportError> {
        loop {
            self.file()?;
            let mut available = 0;
            if unsafe {
                PeekNamedPipe(
                    self.as_raw_handle(),
                    ptr::null_mut(),
                    0,
                    ptr::null_mut(),
                    &mut available,
                    ptr::null_mut(),
                )
            } == 0
            {
                let error = TransportError::Io {
                    operation: "idle read",
                    code: unsafe { GetLastError() },
                };
                return self.poison(Err(error));
            }
            if available > 0 {
                return self.read_frame_until(Instant::now() + frame_timeout);
            }
            match unsafe { WaitForSingleObject(peer, 50) } {
                WAIT_TIMEOUT => {}
                WAIT_OBJECT_0 => {
                    return self.poison(Err(TransportError::Io {
                        operation: "peer exited",
                        code: 0,
                    }))
                }
                _ => {
                    return self.poison(Err(TransportError::Io {
                        operation: "peer wait",
                        code: unsafe { GetLastError() },
                    }))
                }
            }
        }
    }
}

pub(crate) fn read_frame(pipe: &mut PipeTransport) -> Result<Frame, TransportError> {
    pipe.read_frame_until(Instant::now() + FRAME_TIMEOUT)
}
pub(crate) fn write_frame(pipe: &mut PipeTransport, frame: &Frame) -> Result<(), TransportError> {
    let mut bytes = Vec::new();
    protocol::write_frame(&mut bytes, frame).map_err(|_| TransportError::Protocol)?;
    pipe.write_all_until(&bytes, Instant::now() + FRAME_TIMEOUT)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use windows_sys::Win32::{
        Storage::FileSystem::FILE_FLAG_OVERLAPPED,
        System::{Pipes::PIPE_WAIT, Threading::SetEvent},
    };
    static SERIAL: Mutex<()> = Mutex::new(());
    use std::{
        fs::File,
        os::windows::io::{AsRawHandle, FromRawHandle},
        ptr,
    };
    use windows_sys::Win32::{
        Foundation::{
            GetLastError, ERROR_NO_DATA, ERROR_PIPE_CONNECTED, ERROR_PIPE_LISTENING, GENERIC_READ,
            GENERIC_WRITE, INVALID_HANDLE_VALUE,
        },
        Storage::FileSystem::{CreateFileW, OPEN_EXISTING, PIPE_ACCESS_DUPLEX},
        System::Pipes::{
            ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, PIPE_NOWAIT,
            PIPE_READMODE_BYTE, PIPE_TYPE_BYTE,
        },
    };

    fn pair_name() -> Vec<u16> {
        format!(
            r"\\.\pipe\RouteDeck.TransportFixture.{}",
            crate::engine_runtime::random_hex(16).unwrap()
        )
        .encode_utf16()
        .chain([0])
        .collect()
    }
    fn old_server(name: &[u16]) -> File {
        let handle = unsafe {
            CreateNamedPipeW(
                name.as_ptr(),
                PIPE_ACCESS_DUPLEX,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_NOWAIT,
                1,
                1024,
                1024,
                0,
                ptr::null(),
            )
        };
        assert_ne!(handle, INVALID_HANDLE_VALUE);
        unsafe { File::from_raw_handle(handle) }
    }
    fn client(name: &[u16]) -> File {
        let handle = unsafe {
            CreateFileW(
                name.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                0,
                ptr::null(),
                OPEN_EXISTING,
                0,
                ptr::null_mut(),
            )
        };
        assert_ne!(handle, INVALID_HANDLE_VALUE);
        unsafe { File::from_raw_handle(handle) }
    }
    #[test]
    fn nowait_without_peer_is_listening_not_connected() {
        let _serial = SERIAL.lock().unwrap();
        let name = pair_name();
        let server = old_server(&name);
        assert_eq!(
            unsafe { ConnectNamedPipe(server.as_raw_handle(), ptr::null_mut()) },
            0
        );
        assert_eq!(unsafe { GetLastError() }, ERROR_PIPE_LISTENING);
        drop(client(&name));
        assert_ne!(unsafe { DisconnectNamedPipe(server.as_raw_handle()) }, 0);
        let available = unsafe { ConnectNamedPipe(server.as_raw_handle(), ptr::null_mut()) };
        if available == 0 {
            assert_eq!(unsafe { GetLastError() }, ERROR_PIPE_LISTENING);
        }
        let _client = client(&name);
        assert_eq!(
            unsafe { ConnectNamedPipe(server.as_raw_handle(), ptr::null_mut()) },
            0
        );
        assert_eq!(unsafe { GetLastError() }, ERROR_PIPE_CONNECTED);
    }
    #[test]
    fn nowait_early_peer_close_reproduces_error_232() {
        let _serial = SERIAL.lock().unwrap();
        let name = pair_name();
        let server = old_server(&name);
        drop(client(&name));
        assert_eq!(
            unsafe { ConnectNamedPipe(server.as_raw_handle(), ptr::null_mut()) },
            0
        );
        assert_eq!(unsafe { GetLastError() }, ERROR_NO_DATA);
    }

    fn server(name: &[u16]) -> PipeTransport {
        let handle = unsafe {
            CreateNamedPipeW(
                name.as_ptr(),
                PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
                1,
                1024,
                1024,
                0,
                ptr::null(),
            )
        };
        assert_ne!(handle, INVALID_HANDLE_VALUE);
        PipeTransport::new(unsafe { File::from_raw_handle(handle) })
    }
    fn overlapped_client(name: &[u16]) -> PipeTransport {
        let handle = unsafe {
            CreateFileW(
                name.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                0,
                ptr::null(),
                OPEN_EXISTING,
                FILE_FLAG_OVERLAPPED,
                ptr::null_mut(),
            )
        };
        assert_ne!(handle, INVALID_HANDLE_VALUE);
        PipeTransport::new(unsafe { File::from_raw_handle(handle) })
    }
    fn connected_pair() -> (PipeTransport, PipeTransport) {
        let name = pair_name();
        let mut server = server(&name);
        let client = overlapped_client(&name);
        server.connect(Duration::from_secs(1)).unwrap();
        (server, client)
    }
    fn fixture_frame() -> Frame {
        Frame::Status {
            protocol_version: protocol::PROTOCOL_VERSION,
            session: "01".repeat(16),
            request_id: 3,
        }
    }
    fn wait_for_no_outstanding() {
        let deadline = Instant::now() + Duration::from_secs(2);
        while OUTSTANDING.load(Ordering::Acquire) != 0 && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(OUTSTANDING.load(Ordering::Acquire), 0);
    }
    #[test]
    fn overlapped_connect_waits_for_client_and_immediate_connected_case_round_trips() {
        let _serial = SERIAL.lock().unwrap();
        let name = pair_name();
        let mut server = server(&name);
        let writer = thread::spawn(move || {
            thread::sleep(Duration::from_millis(50));
            let mut client = overlapped_client(&name);
            write_frame(&mut client, &fixture_frame()).unwrap();
            client
        });
        server.connect(Duration::from_secs(2)).unwrap();
        assert_eq!(read_frame(&mut server).unwrap(), fixture_frame());
        drop(writer.join().unwrap());
        let (mut server, mut client) = connected_pair();
        write_frame(&mut server, &fixture_frame()).unwrap();
        assert_eq!(read_frame(&mut client).unwrap(), fixture_frame());
        wait_for_no_outstanding();
    }
    #[test]
    fn connect_timeout_cancels_exact_request_and_poison_prevents_reuse() {
        let _serial = SERIAL.lock().unwrap();
        let mut server = server(&pair_name());
        let started = Instant::now();
        assert_eq!(
            server.connect(Duration::from_millis(20)),
            Err(TransportError::Timeout)
        );
        assert!(started.elapsed() < Duration::from_secs(1));
        assert_eq!(
            server.connect(Duration::from_millis(20)),
            Err(TransportError::Poisoned)
        );
        wait_for_no_outstanding();
    }
    #[test]
    fn partial_frame_cannot_extend_deadline_or_reuse_channel() {
        let _serial = SERIAL.lock().unwrap();
        let (mut server, mut client) = connected_pair();
        client
            .write_all_until(&[1, 0], Instant::now() + Duration::from_secs(1))
            .unwrap();
        let started = Instant::now();
        assert_eq!(
            server.read_frame_until(started + Duration::from_millis(20)),
            Err(TransportError::Timeout)
        );
        assert!(started.elapsed() < Duration::from_secs(1));
        assert_eq!(read_frame(&mut server), Err(TransportError::Poisoned));
        wait_for_no_outstanding();
    }
    #[test]
    fn blocked_write_deadline_and_peer_close_are_bounded() {
        let _serial = SERIAL.lock().unwrap();
        let (mut server, client) = connected_pair();
        assert_eq!(
            server.write_all_until(
                &vec![0; MAX_FRAME_BYTES],
                Instant::now() + Duration::from_millis(20)
            ),
            Err(TransportError::Timeout)
        );
        drop(client);
        wait_for_no_outstanding();
        let (mut server, client) = connected_pair();
        drop(client);
        assert!(matches!(
            read_frame(&mut server),
            Err(TransportError::Io {
                operation: "read",
                ..
            })
        ));
        assert_eq!(read_frame(&mut server), Err(TransportError::Poisoned));
    }
    #[test]
    fn oversized_frame_poisoned_before_body_allocation() {
        let _serial = SERIAL.lock().unwrap();
        let (mut server, mut client) = connected_pair();
        client
            .write_all_until(
                &((MAX_FRAME_BYTES + 1) as u32).to_le_bytes(),
                Instant::now() + Duration::from_secs(1),
            )
            .unwrap();
        assert_eq!(read_frame(&mut server), Err(TransportError::Protocol));
        assert_eq!(read_frame(&mut server), Err(TransportError::Poisoned));
    }
    #[test]
    fn idle_does_not_start_frame_deadline_but_peer_exit_ends_idle() {
        let _serial = SERIAL.lock().unwrap();
        let (mut server, mut client) = connected_pair();
        let writer = thread::spawn(move || {
            thread::sleep(Duration::from_millis(120));
            write_frame(&mut client, &fixture_frame()).unwrap();
            client
        });
        let peer = Event(unsafe { CreateEventW(ptr::null(), 1, 0, ptr::null()) });
        assert!(!peer.0.is_null());
        assert_eq!(
            server
                .read_frame_after_idle(peer.0, Duration::from_millis(20))
                .unwrap(),
            fixture_frame()
        );
        let _client = writer.join().unwrap();
        unsafe {
            SetEvent(peer.0);
        }
        assert_eq!(
            server.read_frame_from_peer(peer.0),
            Err(TransportError::Io {
                operation: "peer exited",
                code: 0
            })
        );
    }
    #[test]
    fn failed_cancel_retains_bounded_resources_until_late_completion_signal() {
        let _serial = SERIAL.lock().unwrap();
        wait_for_no_outstanding();
        let server = server(&pair_name());
        let mut events = Vec::new();
        for _ in 0..MAX_OUTSTANDING {
            // No native request was issued: CancelIoEx must fail with NOT_FOUND.
            // The same timeout ownership path must nevertheless retain the request
            // until its completion event, not assume cancellation failure is safe.
            let operation = NativeOperation::new(server.file().unwrap(), vec![7; 64]).unwrap();
            events.push(operation.event.0);
            assert!(matches!(
                operation.finish(false, Instant::now(), "fixture"),
                Err(TransportError::Timeout)
            ));
        }
        assert_eq!(OUTSTANDING.load(Ordering::Acquire), MAX_OUTSTANDING);
        assert!(matches!(
            NativeOperation::new(server.file().unwrap(), vec![]),
            Err(TransportError::Busy)
        ));
        let mut blocked = self::server(&pair_name());
        assert_eq!(
            blocked.connect(Duration::from_millis(20)),
            Err(TransportError::Busy)
        );
        assert_eq!(
            blocked.connect(Duration::from_millis(20)),
            Err(TransportError::Poisoned)
        );
        for event in events {
            assert_ne!(unsafe { SetEvent(event) }, 0);
        }
        wait_for_no_outstanding();
    }

    #[test]
    fn overlapped_connect_preserves_early_close_as_error_not_success() {
        let _serial = SERIAL.lock().unwrap();
        let name = pair_name();
        let mut server = server(&name);
        drop(overlapped_client(&name));
        assert_eq!(
            server.connect(Duration::from_secs(1)),
            Err(TransportError::Io {
                operation: "connect",
                code: ERROR_NO_DATA
            })
        );
        assert_eq!(
            server.connect(Duration::from_secs(1)),
            Err(TransportError::Poisoned)
        );
    }
}

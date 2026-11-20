//! `extern "C"` FFI surface consumed by `soulseek/addon.c` (`BARE_MODULE`).
//!
//! Every async entrypoint spawns off-thread work and invokes its completion callback
//! asynchronously so the Bare event loop thread is never blocked.

use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::ptr;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use crate::client::{ClientState, LogEvent, LoggerHook, SoulseekClient};
use crate::proto::SharedFileRecord;
use crate::transfer::{DownloadOutcome, ProgressCallback, TransferPhase, TransferProgress};

pub struct SlskClientHandle {
    inner: Arc<SoulseekClient>,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SlskState {
    pub connected: u8,
    pub logged_in: u8,
    pub privileges: u32,
    pub listen_port: u16,
}

impl From<ClientState> for SlskState {
    fn from(s: ClientState) -> Self {
        Self {
            connected: u8::from(s.connected),
            logged_in: u8::from(s.logged_in),
            privileges: s.privileges,
            listen_port: s.listen_port,
        }
    }
}

#[repr(C)]
pub struct SlskFile {
    pub username: *mut c_char,
    pub slots: u8,
    pub queue: u32,
    pub speed: u32,
    pub filename: *mut c_char,
    pub size: u64,
    pub bitrate: i64,
    pub sample_rate: i64,
    pub bit_depth: i64,
    pub length_secs: i64,
}

#[repr(C)]
pub struct SlskFileList {
    pub items: *mut SlskFile,
    pub len: usize,
    pub cap: usize,
}

#[repr(C)]
pub struct SlskDownloadResult {
    pub path: *mut c_char,
    pub size: u64,
    pub resumed_from: u64,
}

pub type SlskLogCb = extern "C" fn(
    ctx: *mut std::ffi::c_void,
    level: *const c_char,
    event: *const c_char,
    message: *const c_char,
);

pub type SlskStateDoneCb =
    extern "C" fn(req_ctx: *mut std::ffi::c_void, err: *const c_char, state: SlskState);

pub type SlskFilesDoneCb =
    extern "C" fn(req_ctx: *mut std::ffi::c_void, err: *const c_char, list: *mut SlskFileList);

pub type SlskProgressCb = extern "C" fn(
    req_ctx: *mut std::ffi::c_void,
    bytes_downloaded: u64,
    total_bytes: u64,
    speed_bytes_per_sec: f64,
    queue_place: i64,
    phase: *const c_char,
);

pub type SlskDownloadDoneCb = extern "C" fn(
    req_ctx: *mut std::ffi::c_void,
    err: *const c_char,
    result: *mut SlskDownloadResult,
);

#[derive(Clone, Copy)]
struct SendPtr(usize);

fn to_cstring_lossy(s: &str) -> CString {
    match CString::new(s) {
        Ok(c) => c,
        Err(_) => {
            let cleaned: String = s.chars().filter(|&ch| ch != '\0').collect();
            CString::new(cleaned).unwrap_or_default()
        }
    }
}

unsafe fn cstr_to_string(ptr: *const c_char) -> String {
    if ptr.is_null() {
        return String::new();
    }
    // SAFETY: Caller passes a valid NUL-terminated UTF-8 buffer for the duration of the call.
    unsafe { CStr::from_ptr(ptr) }
        .to_string_lossy()
        .into_owned()
}

fn box_file_list(records: Vec<SharedFileRecord>) -> *mut SlskFileList {
    let mut vec: Vec<SlskFile> = records
        .into_iter()
        .map(|r| SlskFile {
            username: to_cstring_lossy(&r.username).into_raw(),
            slots: u8::from(r.slots),
            queue: r.queue,
            speed: r.speed,
            filename: to_cstring_lossy(&r.filename).into_raw(),
            size: r.size,
            bitrate: r.bitrate.map_or(-1, i64::from),
            sample_rate: r.sample_rate.map_or(-1, i64::from),
            bit_depth: r.bit_depth.map_or(-1, i64::from),
            length_secs: r.length_secs.map_or(-1, i64::from),
        })
        .collect();
    let len = vec.len();
    let cap = vec.capacity();
    let items = vec.as_mut_ptr();
    std::mem::forget(vec);
    Box::into_raw(Box::new(SlskFileList { items, len, cap }))
}

#[unsafe(no_mangle)]
pub extern "C" fn slsk_client_new(listen_port: u16) -> *mut SlskClientHandle {
    let client = SoulseekClient::with_listen_port(listen_port);
    Box::into_raw(Box::new(SlskClientHandle {
        inner: Arc::new(client),
    }))
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn slsk_client_free(client: *mut SlskClientHandle) {
    if !client.is_null() {
        // SAFETY: Pointer was allocated via `Box::into_raw` in `slsk_client_new`.
        let boxed = unsafe { Box::from_raw(client) };
        boxed.inner.close();
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn slsk_client_state(client: *const SlskClientHandle) -> SlskState {
    if client.is_null() {
        return SlskState {
            connected: 0,
            logged_in: 0,
            privileges: 0,
            listen_port: 0,
        };
    }
    // SAFETY: Caller passes valid handle pointer.
    let handle = unsafe { &*client };
    SlskState::from(handle.inner.state())
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn slsk_client_set_logger(
    client: *mut SlskClientHandle,
    cb: Option<SlskLogCb>,
    ctx: *mut std::ffi::c_void,
) {
    if client.is_null() {
        return;
    }
    // SAFETY: Caller passes valid handle pointer.
    let handle = unsafe { &*client };
    match cb {
        Some(func) => {
            let raw_ctx = SendPtr(ctx as usize);
            let hook: LoggerHook = Arc::new(move |ev: LogEvent| {
                let lvl = to_cstring_lossy(ev.level.as_str());
                let kind = to_cstring_lossy(&ev.event);
                let msg = to_cstring_lossy(&ev.message);
                func(
                    raw_ctx.0 as *mut std::ffi::c_void,
                    lvl.as_ptr(),
                    kind.as_ptr(),
                    msg.as_ptr(),
                );
            });
            handle.inner.set_logger(Some(hook));
        }
        None => handle.inner.set_logger(None),
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn slsk_client_login_async(
    client: *const SlskClientHandle,
    server: *const c_char,
    port: u16,
    username: *const c_char,
    password: *const c_char,
    done: SlskStateDoneCb,
    req_ctx: *mut std::ffi::c_void,
) {
    let raw_ctx = SendPtr(req_ctx as usize);
    if client.is_null() {
        let err = to_cstring_lossy("null client handle");
        done(
            raw_ctx.0 as *mut std::ffi::c_void,
            err.as_ptr(),
            SlskState {
                connected: 0,
                logged_in: 0,
                privileges: 0,
                listen_port: 0,
            },
        );
        return;
    }
    // SAFETY: Valid pointers during synchronous marshaling before spawning.
    let inner = unsafe { Arc::clone(&(*client).inner) };
    let server = unsafe { cstr_to_string(server) };
    let username = unsafe { cstr_to_string(username) };
    let password = unsafe { cstr_to_string(password) };

    let _ = thread::Builder::new()
        .name("slsk-ffi-login".to_string())
        .spawn(move || match inner.login(&server, port, &username, &password) {
            Ok(st) => done(
                raw_ctx.0 as *mut std::ffi::c_void,
                ptr::null(),
                SlskState::from(st),
            ),
            Err(e) => {
                let c_err = to_cstring_lossy(&e.to_string());
                done(
                    raw_ctx.0 as *mut std::ffi::c_void,
                    c_err.as_ptr(),
                    SlskState::from(inner.state()),
                );
            }
        });
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn slsk_client_search_async(
    client: *const SlskClientHandle,
    query: *const c_char,
    timeout_ms: u64,
    done: SlskFilesDoneCb,
    req_ctx: *mut std::ffi::c_void,
) {
    let raw_ctx = SendPtr(req_ctx as usize);
    if client.is_null() {
        let err = to_cstring_lossy("null client handle");
        done(raw_ctx.0 as *mut std::ffi::c_void, err.as_ptr(), ptr::null_mut());
        return;
    }
    let inner = unsafe { Arc::clone(&(*client).inner) };
    let query = unsafe { cstr_to_string(query) };

    let _ = thread::Builder::new()
        .name("slsk-ffi-search".to_string())
        .spawn(move || match inner.search(&query, timeout_ms) {
            Ok(records) => {
                let list = box_file_list(records);
                done(raw_ctx.0 as *mut std::ffi::c_void, ptr::null(), list);
            }
            Err(e) => {
                let c_err = to_cstring_lossy(&e.to_string());
                done(
                    raw_ctx.0 as *mut std::ffi::c_void,
                    c_err.as_ptr(),
                    ptr::null_mut(),
                );
            }
        });
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn slsk_client_browse_async(
    client: *const SlskClientHandle,
    username: *const c_char,
    timeout_ms: u64,
    done: SlskFilesDoneCb,
    req_ctx: *mut std::ffi::c_void,
) {
    let raw_ctx = SendPtr(req_ctx as usize);
    if client.is_null() {
        let err = to_cstring_lossy("null client handle");
        done(raw_ctx.0 as *mut std::ffi::c_void, err.as_ptr(), ptr::null_mut());
        return;
    }
    let inner = unsafe { Arc::clone(&(*client).inner) };
    let username = unsafe { cstr_to_string(username) };
    let timeout = if timeout_ms == 0 {
        Duration::from_secs(30)
    } else {
        Duration::from_millis(timeout_ms)
    };

    let _ = thread::Builder::new()
        .name("slsk-ffi-browse".to_string())
        .spawn(move || match inner.browse_with_timeout(&username, timeout) {
            Ok(records) => {
                let list = box_file_list(records);
                done(raw_ctx.0 as *mut std::ffi::c_void, ptr::null(), list);
            }
            Err(e) => {
                let c_err = to_cstring_lossy(&e.to_string());
                done(
                    raw_ctx.0 as *mut std::ffi::c_void,
                    c_err.as_ptr(),
                    ptr::null_mut(),
                );
            }
        });
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn slsk_client_download_async(
    client: *const SlskClientHandle,
    username: *const c_char,
    filename: *const c_char,
    dest_path: *const c_char,
    on_progress: Option<SlskProgressCb>,
    done: SlskDownloadDoneCb,
    req_ctx: *mut std::ffi::c_void,
) {
    let raw_ctx = SendPtr(req_ctx as usize);
    if client.is_null() {
        let err = to_cstring_lossy("null client handle");
        done(raw_ctx.0 as *mut std::ffi::c_void, err.as_ptr(), ptr::null_mut());
        return;
    }
    let inner = unsafe { Arc::clone(&(*client).inner) };
    let username = unsafe { cstr_to_string(username) };
    let filename = unsafe { cstr_to_string(filename) };
    let dest_path = unsafe { cstr_to_string(dest_path) };

    let progress_hook: Option<ProgressCallback> = on_progress.map(|cb| {
        let p_ctx = raw_ctx;
        let arc_cb: ProgressCallback = Arc::new(move |prog: TransferProgress| {
            let phase_str = match &prog.phase {
                TransferPhase::Queued { .. } => "queued",
                TransferPhase::Connecting => "connecting",
                TransferPhase::Transferring => "transferring",
                TransferPhase::Completed => "completed",
                TransferPhase::Failed(_) => "failed",
                TransferPhase::Cancelled => "cancelled",
            };
            let c_phase = to_cstring_lossy(phase_str);
            let place = prog.queue_place.map_or(-1, i64::from);
            cb(
                p_ctx.0 as *mut std::ffi::c_void,
                prog.bytes_downloaded,
                prog.total_bytes,
                prog.speed_bytes_per_sec,
                place,
                c_phase.as_ptr(),
            );
        });
        arc_cb
    });

    let _ = thread::Builder::new()
        .name("slsk-ffi-download".to_string())
        .spawn(move || {
            match inner.download(&username, &filename, dest_path, progress_hook) {
                Ok(DownloadOutcome {
                    path,
                    size,
                    resumed_from,
                }) => {
                    let c_path = to_cstring_lossy(&path.to_string_lossy()).into_raw();
                    let boxed = Box::into_raw(Box::new(SlskDownloadResult {
                        path: c_path,
                        size,
                        resumed_from,
                    }));
                    done(raw_ctx.0 as *mut std::ffi::c_void, ptr::null(), boxed);
                }
                Err(e) => {
                    let c_err = to_cstring_lossy(&e.to_string());
                    done(
                        raw_ctx.0 as *mut std::ffi::c_void,
                        c_err.as_ptr(),
                        ptr::null_mut(),
                    );
                }
            }
        });
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn slsk_file_list_free(list: *mut SlskFileList) {
    if list.is_null() {
        return;
    }
    // SAFETY: Allocated by `box_file_list`.
    unsafe {
        let boxed = Box::from_raw(list);
        let vec = Vec::from_raw_parts(boxed.items, boxed.len, boxed.cap);
        for item in vec {
            if !item.username.is_null() {
                let _ = CString::from_raw(item.username);
            }
            if !item.filename.is_null() {
                let _ = CString::from_raw(item.filename);
            }
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn slsk_download_result_free(res: *mut SlskDownloadResult) {
    if res.is_null() {
        return;
    }
    // SAFETY: Allocated in `slsk_client_download_async`.
    unsafe {
        let boxed = Box::from_raw(res);
        if !boxed.path.is_null() {
            let _ = CString::from_raw(boxed.path);
        }
    }
}

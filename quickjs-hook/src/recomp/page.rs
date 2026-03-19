//! Recomp 页管理回调桥

use std::sync::Mutex;

type RecompHandler = fn(usize) -> Result<usize, String>;

static HANDLER: Mutex<Option<RecompHandler>> = Mutex::new(None);

pub fn set_handler(handler: RecompHandler) {
    *HANDLER.lock().unwrap() = Some(handler);
}

pub fn ensure_and_translate(orig_addr: usize) -> Result<usize, String> {
    let guard = HANDLER.lock().unwrap();
    let handler = match guard.as_ref() {
        Some(h) => h,
        None => return Err("recomp handler not set".into()),
    };
    handler(orig_addr)
}

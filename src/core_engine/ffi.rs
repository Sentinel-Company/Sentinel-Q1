//! FFI Layer - C ABI exports for C++ Strategy Engine
//! 
//! Zero-copy, near-zero latency data handoff.
//! All types #[repr(C)] for ABI compatibility.

use std::ptr;
use std::sync::{Arc, Mutex, OnceLock};

use super::ring_buffer::{MarketTick, TickRingBuffer};
use super::data_listener::DataListener;

// Thread-safe global state
static RING_BUFFER: OnceLock<Arc<TickRingBuffer>> = OnceLock::new();
static DATA_LISTENER: Mutex<Option<DataListener>> = Mutex::new(None);

/// C-compatible MarketTick - must match C++ struct
#[repr(C)]
pub struct CMarketTick {
    pub symbol_id: u64,
    pub price: f64,
    pub quantity: f64,
    pub timestamp_ns: i64,
    pub side: u8,
    pub msg_type: u8,
    _padding: [u8; 6], // Align to 8 bytes for C++ ABI
}

impl From<MarketTick> for CMarketTick {
    fn from(t: MarketTick) -> Self {
        Self {
            symbol_id: t.symbol_id,
            price: t.price,
            quantity: t.quantity,
            timestamp_ns: t.timestamp_ns,
            side: t.side,
            msg_type: t.msg_type,
            _padding: [0; 6],
        }
    }
}

/// Initialize the Rust core engine. Call once from C++ main.
#[no_mangle]
pub extern "C" fn nova_core_init(buffer_capacity: usize) -> i32 {
    if buffer_capacity == 0 {
        return -1;
    }
    if RING_BUFFER.get().is_some() {
        return 0; // Already initialized
    }
    let buffer = Arc::new(TickRingBuffer::new(buffer_capacity));
    let mut listener = DataListener::new(Arc::clone(&buffer));
    listener.start();
    let _ = RING_BUFFER.set(buffer);
    let _ = DATA_LISTENER.lock().map(|mut g| *g = Some(listener));
    0
}

/// Shutdown - call from C++ before exit
#[no_mangle]
pub extern "C" fn nova_core_shutdown() {
    if let Ok(mut guard) = DATA_LISTENER.lock() {
        if let Some(mut listener) = guard.take() {
            listener.stop();
        }
    }
}

/// Poll next tick from buffer. Returns 1 if tick available, 0 if empty, -1 on error.
/// C++ calls this in tight loop - zero allocation, zero syscalls.
#[no_mangle]
pub extern "C" fn nova_poll_tick(out: *mut CMarketTick) -> i32 {
    if out.is_null() {
        return -1;
    }
    if let Some(buffer) = RING_BUFFER.get() {
        if let Some(tick) = buffer.pop() {
            unsafe { ptr::write(out, tick.into()); }
            return 1;
        }
        return 0;
    }
    -1
}

/// Get pending tick count (non-destructive)
#[no_mangle]
pub extern "C" fn nova_pending_ticks() -> usize {
    RING_BUFFER.get().map(|b| b.len()).unwrap_or(0)
}


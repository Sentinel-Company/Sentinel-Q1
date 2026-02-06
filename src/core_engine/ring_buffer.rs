//! Lock-free SPSC (Single Producer Single Consumer) Ring Buffer
//! 
//! Zero-copy, cache-line friendly design for minimal latency FFI.
//! No mutex, no syscalls - pure atomic operations.

use std::sync::atomic::{AtomicUsize, Ordering};

/// C-compatible market tick structure - #[repr(C)] ensures ABI stability
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct MarketTick {
    pub symbol_id: u64,
    pub price: f64,
    pub quantity: f64,
    pub timestamp_ns: i64,
    pub side: u8,      // 0=bid, 1=ask
    pub msg_type: u8,  // 0=trade, 1=quote, 2=book_update
}

impl Default for MarketTick {
    fn default() -> Self {
        Self {
            symbol_id: 0,
            price: 0.0,
            quantity: 0.0,
            timestamp_ns: 0,
            side: 0,
            msg_type: 0,
        }
    }
}

/// Lock-free SPSC ring buffer for MarketTick
/// Capacity must be power of 2 for fast modulo via bitmask
pub struct TickRingBuffer {
    buffer: Box<[MarketTick]>,
    capacity: usize,
    mask: usize,
    write_pos: AtomicUsize,
    read_pos: AtomicUsize,
}

impl TickRingBuffer {
    pub fn new(capacity: usize) -> Self {
        let cap = capacity.next_power_of_two();
        let mut buffer = Vec::with_capacity(cap);
        buffer.resize_with(cap, MarketTick::default);
        
        Self {
            buffer: buffer.into_boxed_slice(),
            capacity: cap,
            mask: cap - 1,
            write_pos: AtomicUsize::new(0),
            read_pos: AtomicUsize::new(0),
        }
    }

    /// Producer: Push tick - returns false if full (backpressure)
    #[inline(always)]
    pub fn push(&self, tick: MarketTick) -> bool {
        let write = self.write_pos.load(Ordering::Acquire);
        let read = self.read_pos.load(Ordering::Acquire);
        
        if write.wrapping_sub(read) >= self.capacity {
            return false; // Buffer full
        }
        
        // SAFETY: Single producer, we own this slot
        unsafe {
            let ptr = self.buffer.as_ptr().add(write & self.mask) as *mut MarketTick;
            std::ptr::write(ptr, tick);
        }
        
        self.write_pos.store(write.wrapping_add(1), Ordering::Release);
        true
    }

    /// Consumer: Pop tick - returns None if empty
    #[inline(always)]
    pub fn pop(&self) -> Option<MarketTick> {
        let read = self.read_pos.load(Ordering::Acquire);
        let write = self.write_pos.load(Ordering::Acquire);
        
        if read >= write {
            return None;
        }
        
        // SAFETY: Single consumer, we own this slot
        let tick = unsafe {
            let ptr = self.buffer.as_ptr().add(read & self.mask);
            std::ptr::read(ptr)
        };
        
        self.read_pos.store(read.wrapping_add(1), Ordering::Release);
        Some(tick)
    }

    /// Non-destructive peek for C++ side
    #[inline(always)]
    pub fn len(&self) -> usize {
        let read = self.read_pos.load(Ordering::Acquire);
        let write = self.write_pos.load(Ordering::Acquire);
        write.saturating_sub(read)
    }
}

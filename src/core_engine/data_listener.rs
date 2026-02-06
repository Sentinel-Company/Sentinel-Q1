//! Data Listener - Low-level market data ingestion
//! 
//! Kernel-level networking, first point of data entry.
//! Writes to lock-free ring buffer for zero-copy handoff to C++ Strategy Engine.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use super::ring_buffer::{MarketTick, TickRingBuffer};

/// Data Listener - spawns background thread, ingests data into ring buffer
pub struct DataListener {
    buffer: Arc<TickRingBuffer>,
    running: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
}

impl DataListener {
    pub fn new(buffer: Arc<TickRingBuffer>) -> Self {
        Self {
            buffer,
            running: Arc::new(AtomicBool::new(false)),
            handle: None,
        }
    }

    /// Start data ingestion (spawns background thread)
    /// In production: replace with real TCP/UDP/multicast socket
    pub fn start(&mut self) {
        if self.running.load(Ordering::Acquire) {
            return;
        }
        self.running.store(true, Ordering::Release);
        
        let buffer = Arc::clone(&self.buffer);
        let running = Arc::clone(&self.running);
        
        let handle = thread::spawn(move || {
            let mut seq: i64 = 0;
            while running.load(Ordering::Acquire) {
                // Simulate high-frequency market data (100k ticks/sec)
                let tick = MarketTick {
                    symbol_id: 1, // BTC-USD
                    price: 42000.0 + (seq as f64 * 0.01),
                    quantity: 0.001,
                    timestamp_ns: seq * 10_000, // 100µs between ticks
                    side: (seq % 2) as u8,  // 0=bid, 1=ask
                    msg_type: (seq % 3) as u8,
                };
                
                while !buffer.push(tick) {
                    // Backpressure: buffer full, spin briefly
                    std::hint::spin_loop();
                }
                
                seq += 1;
                if seq % 100_000 == 0 {
                    thread::sleep(Duration::from_micros(100));
                }
            }
        });
        
        self.handle = Some(handle);
    }

    pub fn stop(&mut self) {
        self.running.store(false, Ordering::Release);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }

    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::Acquire)
    }
}

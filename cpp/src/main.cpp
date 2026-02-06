/**
 * Hybrid Titan - Main Entry Point
 * 
 * C++ main links against Rust static library.
 * Data flow: Rust Data Listener -> Ring Buffer -> C++ Strategy Engine
 */

#include "strategy_engine/strategy_engine.hpp"
#include "core_ffi.h"
#include <iostream>
#include <chrono>
#include <thread>
#include <csignal>

static volatile std::sig_atomic_t g_running = 1;

void signal_handler(int) {
    g_running = 0;
}

int main() {
    std::signal(SIGINT, signal_handler);

    // 1. Initialize Rust Core (Data Listener starts, begins ingesting)
    constexpr std::size_t BUFFER_CAPACITY = 65536;  // 2^16 - power of 2
    if (nova_core_init(BUFFER_CAPACITY) != 0) {
        std::cerr << "Failed to init Rust core\n";
        return 1;
    }
    std::cout << "[OK] Rust Core initialized, Data Listener running\n";

    // 2. C++ Strategy Engine
    nova::StrategyEngine engine(1024);

    // 3. Main loop - zero-latency tick processing
    auto start = std::chrono::high_resolution_clock::now();
    std::uint64_t last_count = 0;
    auto last_stats = start;

    while (g_running) {
        engine.process_ticks();

        // Stats every second
        auto now = std::chrono::high_resolution_clock::now();
        auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(now - last_stats).count();
        if (elapsed_ms >= 1000) {
            auto count = engine.processed_count();
            auto rate = (count - last_count) * 1000 / static_cast<std::uint64_t>(elapsed_ms);
            std::cout << "\r[Strategy] Processed: " << count 
                      << " | Rate: " << rate << " ticks/sec"
                      << " | Pending: " << nova_pending_ticks() << "    " << std::flush;
            last_count = count;
            last_stats = now;
        }
    }

    // 4. Shutdown
    nova_core_shutdown();
    std::cout << "\n[OK] Shutdown complete. Total processed: " 
              << engine.processed_count() << "\n";

    return 0;
}

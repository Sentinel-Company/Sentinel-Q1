/**
 * Strategy Engine - C++ Business Logic Layer
 * 
 * Modern C++20/23, receives data from Rust Core via FFI.
 * Order book logic, strategy management, signal generation.
 */

#pragma once

#include "../../include/core_ffi.h"
#include <cstddef>
#include <cstdint>
#include <memory>
#include <vector>
#include <atomic>
#include <optional>

namespace nova {

/**
 * Strategy Engine - processes market ticks from Rust Data Listener
 * Uses custom allocator-friendly design (std::vector can be swapped)
 */
class StrategyEngine {
public:
    explicit StrategyEngine(std::size_t batch_size = 1024);
    ~StrategyEngine();

    // Non-copyable, movable
    StrategyEngine(const StrategyEngine&) = delete;
    StrategyEngine& operator=(const StrategyEngine&) = delete;
    StrategyEngine(StrategyEngine&&) noexcept = default;
    StrategyEngine& operator=(StrategyEngine&&) noexcept = default;

    /**
     * Process ticks - call in tight loop from main
     * Drains Rust ring buffer, processes each tick
     */
    void process_ticks();

    /**
     * Get processed tick count
     */
    std::uint64_t processed_count() const noexcept {
        return processed_count_.load(std::memory_order_relaxed);
    }

private:
    void on_tick(const NovaMarketTick& tick);

    std::size_t batch_size_;
    std::vector<NovaMarketTick> batch_buffer_;  // Pre-allocated, no alloc in hot path
    std::atomic<std::uint64_t> processed_count_{0};
};

} // namespace nova

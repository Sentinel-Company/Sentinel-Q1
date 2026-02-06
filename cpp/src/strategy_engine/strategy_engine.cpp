/**
 * Strategy Engine Implementation
 * 
 * Zero-latency tick consumption from Rust Core.
 */

#include "strategy_engine.hpp"
#include <iostream>
#include <chrono>

namespace nova {

StrategyEngine::StrategyEngine(std::size_t batch_size)
    : batch_size_(batch_size)
{
    batch_buffer_.reserve(batch_size);
}

StrategyEngine::~StrategyEngine() = default;

void StrategyEngine::process_ticks() {
    batch_buffer_.clear();
    
    // Drain Rust buffer - batch for cache efficiency
    NovaMarketTick tick;
    while (nova_poll_tick(&tick) == 1) {
        batch_buffer_.push_back(tick);
        if (batch_buffer_.size() >= batch_size_) {
            break;
        }
    }
    
    // Process batch - business logic here
    for (const auto& t : batch_buffer_) {
        on_tick(t);
        processed_count_.fetch_add(1, std::memory_order_relaxed);
    }
}

void StrategyEngine::on_tick(const NovaMarketTick& tick) {
    // Placeholder: Order book update, signal generation, etc.
    // In production: custom allocator, SIMD price levels, etc.
    (void)tick;  // Suppress unused warning in prototype
}

} // namespace nova

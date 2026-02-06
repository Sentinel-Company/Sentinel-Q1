/**
 * NOVA Core FFI - C Header for C++ Strategy Engine
 * 
 * Generated from Rust #[repr(C)] types.
 * Zero-copy, near-zero latency data handoff.
 */

#ifndef NOVA_CORE_FFI_H
#define NOVA_CORE_FFI_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Market tick - must match Rust MarketTick layout exactly */
typedef struct NovaMarketTick {
    uint64_t symbol_id;
    double   price;
    double   quantity;
    int64_t  timestamp_ns;
    uint8_t  side;       /* 0=bid, 1=ask */
    uint8_t  msg_type;   /* 0=trade, 1=quote, 2=book_update */
    uint8_t  _padding[6];
} NovaMarketTick;

/**
 * Initialize Rust core engine. Call once from main().
 * @param buffer_capacity Ring buffer size (power of 2 recommended)
 * @return 0 on success, -1 on error
 */
int nova_core_init(size_t buffer_capacity);

/**
 * Shutdown - call before exit
 */
void nova_core_shutdown(void);

/**
 * Poll next tick from buffer. Zero-copy, lock-free.
 * @param out Pointer to write tick (must be valid)
 * @return 1 if tick available, 0 if empty, -1 on error
 */
int nova_poll_tick(NovaMarketTick* out);

/**
 * Get pending tick count (non-destructive peek)
 */
size_t nova_pending_ticks(void);

#ifdef __cplusplus
}
#endif

#endif /* NOVA_CORE_FFI_H */

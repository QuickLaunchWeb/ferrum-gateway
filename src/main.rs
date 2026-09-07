// Reuse gateway modules from the library without compiling CLI startup into it.
use ferrum_edge::*;

// Keep startup at the binary crate root, preserving its tracing target.
include!("gateway_entry.rs");

// Use jemalloc as the global allocator on non-Windows platforms.
// jemalloc significantly reduces memory fragmentation under high-concurrency
// workloads compared to the system allocator, which matters for a proxy that
// creates/destroys many small allocations (headers, buffers) per request.
#[cfg(not(windows))]
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

fn main() {
    // SAFETY: this is the process entry point. No application worker or runtime
    // has started; the shared pipeline owns initialization and thread startup.
    unsafe {
        run_gateway_cli();
    }
}

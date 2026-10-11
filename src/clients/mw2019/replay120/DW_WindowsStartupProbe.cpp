#include <stdint.h>

extern "C"
{
    void *func_14223AD14(uint64_t size); // Replay's native CRT malloc base.
    extern uintptr_t gl_14E5C2A58;
}

// Retain the complete native startup bootstrap and its thread/join/cleanup.
// This worker alone emits MOV CR0 in user mode. Its supported result is zero,
// but it must still publish the allocation consumed by the parent's native
// free(base + 4096). Use the same CRT allocator and exact native ownership.

extern "C" unsigned long func_141489DA0(void *)
{
    void *allocation = func_14223AD14(0x20000);
    gl_14E5C2A58 = reinterpret_cast<uintptr_t>(allocation) - 4096;
    // Allocation failure also recovers null in the parent's native free.
    return 0;
}

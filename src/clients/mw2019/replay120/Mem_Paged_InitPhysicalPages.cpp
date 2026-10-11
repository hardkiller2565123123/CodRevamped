#include <stddef.h>
#include <stdint.h>

// Replay 1.20, native function 23557 / 0x140F12E20. These are the complete
// page-table, free-tree and address-hash layouts used by its native consumers.
struct ReplayMemoryStatus
{
    uint32_t length, memoryLoad;
    uint64_t totalPhysical, availablePhysical;
    uint64_t totalPageFile, availablePageFile;
    uint64_t totalVirtual, availableVirtual, availableExtendedVirtual;
};
static_assert(sizeof(ReplayMemoryStatus) == 64);
static_assert(offsetof(ReplayMemoryStatus, totalPhysical) == 8);
static_assert(offsetof(ReplayMemoryStatus, availablePhysical) == 16);

struct ReplayFreePageGroup
{
    uint64_t occupied;
    uint64_t pages[64];
};
struct ReplayFreePageBranch
{
    uint64_t occupied;
    ReplayFreePageGroup groups[64];
};
struct ReplayMemPagedPhysical
{
    uint8_t nativeVirtualReservations[0xe0];
    uint64_t reservedBytes;
    uint32_t pageCount, pageTableCapacity;
    uint64_t *pageTable;
    uint64_t occupiedBranches;
    ReplayFreePageBranch branches[2];
    uint32_t freePages, reserved;
    uint32_t addressHashHeads[1024];
};
static_assert(sizeof(ReplayFreePageGroup) == 520);
static_assert(sizeof(ReplayFreePageBranch) == 33288);
static_assert(offsetof(ReplayMemPagedPhysical, reservedBytes) == 0xe0);
static_assert(offsetof(ReplayMemPagedPhysical, pageCount) == 0xe8);
static_assert(offsetof(ReplayMemPagedPhysical, pageTable) == 0xf0);
static_assert(offsetof(ReplayMemPagedPhysical, occupiedBranches) == 0xf8);
static_assert(offsetof(ReplayMemPagedPhysical, branches) == 0x100);
static_assert(offsetof(ReplayMemPagedPhysical, freePages) == 0x10510);
static_assert(offsetof(ReplayMemPagedPhysical, addressHashHeads) == 0x10518);
static_assert(sizeof(ReplayMemPagedPhysical) == 0x11518);

extern "C"
{
    extern ReplayMemPagedPhysical gl_14B493780;
    __declspec(dllimport) void *__stdcall VirtualAlloc(void *, size_t, uint32_t, uint32_t);
    __declspec(dllimport) int __stdcall GlobalMemoryStatusEx(ReplayMemoryStatus *);
    void *memset(void *, int, size_t);
    int64_t func_1412B0820(int channel, const char *, ...);
    void Mem_Error_CannotAlloc_Dev(int, const char *, const char *, int, const char *, ...);
}

extern "C" int64_t func_140F12E20()
{
    constexpr uint32_t pageSize = 0x10000;
    constexpr uint32_t tableCapacity = 0x80000;
    constexpr size_t tableBytes = sizeof(uint64_t) * tableCapacity;
    auto &state = gl_14B493780;
    state.pageTableCapacity = tableCapacity;
    __atomic_fetch_add(&state.reservedBytes, tableBytes, __ATOMIC_SEQ_CST);
    state.pageTable = static_cast<uint64_t *>(VirtualAlloc(nullptr, tableBytes, 0x2000, 4));
    if (!state.pageTable || !VirtualAlloc(state.pageTable, tableBytes, 0x1000, 4))
    {
        Mem_Error_CannotAlloc_Dev(0, "Mem_Paged_InitPhysicalPages", "memory/mem_paged.cpp", 0,
                                 "page table size=%zu", tableBytes);
        return 0;
    }
    memset(state.pageTable, 0xff, tableBytes);
    for (auto &head : state.addressHashHeads)
        head = 0x7ffff;

    ReplayMemoryStatus memory{};
    memory.length = sizeof(memory);
    GlobalMemoryStatusEx(&memory);
    // This is a lifetime bookkeeping limit, not an up-front RAM allocation.
    // Startup free RAM counted existing allocations against it and could
    // leave a 16-GB host at the 5-GB floor for the entire match. Use the
    // same two-thirds policy on installed RAM; native eviction, OS commit and
    // the original 5-GB floor / 32-GB page-table ceiling remain authoritative.
    uint64_t pages = memory.totalPhysical / (pageSize * 3 / 2);
    if (pages > tableCapacity)
        pages = tableCapacity;
    if (pages < 0x14000)
        pages = 0x14000;
    state.pageCount = static_cast<uint32_t>(pages);
    for (uint32_t page = 0; page < state.pageCount; ++page)
    {
        const auto branch = page >> 18;
        const auto group = (page >> 12) & 63;
        const auto word = (page >> 6) & 63;
        state.occupiedBranches |= uint64_t{1} << branch;
        state.branches[branch].occupied |= uint64_t{1} << group;
        auto &freeGroup = state.branches[branch].groups[group];
        freeGroup.occupied |= uint64_t{1} << word;
        freeGroup.pages[word] |= uint64_t{1} << (page & 63);
        ++state.freePages;
    }
    const auto bytes = uint64_t{state.pageCount} * pageSize;
    return func_1412B0820(16,
        "Mem_Paged allocated %u physical pages (%zu bytes, %.1f MBs, %.1f GBs) with a page table for %u pages (page table size: %zu bytes, unused overhead: %zu bytes)\n",
        state.pageCount, static_cast<size_t>(bytes),
        static_cast<double>(bytes) / (1024 * 1024),
        static_cast<double>(bytes) / (1024 * 1024 * 1024), state.pageTableCapacity,
        tableBytes + size_t{66592}, sizeof(uint64_t) * (state.pageTableCapacity - state.pageCount));
}

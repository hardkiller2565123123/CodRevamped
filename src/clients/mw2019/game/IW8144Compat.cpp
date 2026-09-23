#include "IW8144Compat.h"
#include "IW8Addresses.h"
#include "../../../shared/common/utils/MinHook.hpp"
#include "../diagnostics/MW2019MemoryScanner.hpp"
#include "../diagnostics/MW2019Shared.hpp"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

namespace iw8_144
{
    namespace
    {
        enum class PatchFenceState { active = 0, success = 1, success_restart = 2, failure = 3, update_needed = 4, disabled = 5 };
        enum class OCDSState { inactive = 0, requested = 1, downloading = 2, success = 3, failure = 4, queued = 5, registering = 6, queued_retry = 7 };
        enum class FenceOnlineDataState { inactive = 0, requested = 1, downloading = 2, success = 3, failure = 4 };
        enum class BattleNetFenceState { block = 0, pass = 1, fail = 2 };
        enum class SignInExchangeState { IDLE = -1, WAITING_FOR_INVENTORY = 0, WORKING = 1, GOOD = 2, ERRORS = 3, SHOWN_POPUP = 4 };

        struct PatternByte { unsigned char value = 0; bool wildcard = false; };
        struct BoolOverride { const char* token; const char* label; bool value; };

        constexpr BoolOverride kFrontendOverrides[] = {
            {"MTSTMKPMRM", "ui_onlineRequired", false},
            {"LPNMMPKRL", "com_lan_lobby_enabled", true},
            {"RLSPOOTTT", "com_checkIfGameModeInstalled", false},
            {"MPSSOTQQPM", "force_offline_enabled", true},
            {"LSTQOKLTRN", "force_offline_menus", true},
            {"LMMRONPQMO", "lui_force_online_menus", false},
            {"LLOKQOSPPP", "xblive_loggedin", true},
            {"LTSNLQNRKO", "onlinegame", true},
            {"MROLPRPTPO", "com_force_premium", true},
            {"LTOQRQMMLQ", "online_lan_cross_play", true},
            {"NOSONNPTLM", "online_auth_skip_auth", true},
            {"MNMLRKRSSL", "enable_cod_account", true},
            {"online_store_catalog_fence_enabled", "online_store_catalog_fence_enabled", false},
            {"LNKTTMTOMR", "lui_tournament_allow_warzone_players", false},
            {"LOQQOSNQKN", "wz_private_match_enabled", true},
            {"wz_enable_blades_refresh", "wz_enable_blades_refresh", true},
            {"LKSKPKTOON", "text_chat_enabled", true},
            {"NQPKQNMQSR", "display_ng_blade_enabled", true},
            {"LQQNTKTLQK", "battlenet_modify_install_enabled", true},
            {"LKSTRMKTML", "checkReleaseDLC", true},
            {"challenge_summary_test", "challenge_summary_test", true},
            {"LKQRNQSSQS", "online_challenge_fence_enabled", false},
            {"LQKTNLONLP", "mp_private_match_enabled", true},
            {"LOMSTMNPRR", "mp_trials_enabled", true},
        };

        constexpr std::size_t kFrontendOverrideCount = sizeof(kFrontendOverrides) / sizeof(kFrontendOverrides[0]);

        struct DvarBoolView
        {
            const char* name;
            std::uint32_t checksum;
            std::uint32_t pad0C;
            const char* description;
            std::uint32_t flags;
            std::uint8_t level;
            std::uint8_t type;
            bool modified;
            std::uint8_t pad1F;
            std::uint16_t hashNext;
            std::uint8_t pad22[6];
            union { bool enabled; std::uint64_t qword; } current;
            std::uint8_t currentPad[8];
            union { bool enabled; std::uint64_t qword; } latched;
            std::uint8_t latchedPad[8];
            union { bool enabled; std::uint64_t qword; } reset;
        };

        std::atomic<void*> g_capturedFrontendDvars[kFrontendOverrideCount]{};


        std::atomic_bool g_initialized{ false };
        std::atomic_bool g_optionalResolved{ false };
        Detection g_detection{};
        HMODULE g_module = nullptr;
        std::uintptr_t g_base = 0;
        unsigned g_installedHooks = 0;
        unsigned long long g_lastInstallRetry = 0;
        unsigned long long g_lastSelectorPass = 0;
        unsigned long long g_lastCommandScan = 0;
        unsigned g_selectorPasses = 0;
        unsigned g_lastReportedRenderSelectorPass = 0;
        bool g_autoRenderSelectorStarted = false;
        bool g_renderSelectorFaultLogged = false;
        std::atomic_bool g_renderSelectorEnabled{ false };
        std::atomic_bool g_renderSelectorFaulted{ false };
        std::atomic_uint g_renderSelectorFaultCode{ 0 };
        std::atomic_uint g_renderSelectorIndex{ 0 };
        std::atomic_uint g_renderSelectorMatched{ 0 };
        std::atomic_uint g_renderSelectorCompletedPass{ 0 };
        std::atomic<unsigned long long> g_renderSelectorNextPassTick{ 0 };
        bool g_autoSignInStarted = false;
        bool g_autoSignInStage = false;
        bool g_autoContentStarted = false;
        bool g_autoContentStage = false;
        bool g_autoLuiStarted = false;
        bool g_autoLuiStage = false;
        bool g_autoPatchStarted = false;
        bool g_autoPatchStage = false;
        bool g_autoReadyLogged = false;
        bool g_autoLuaWaitLogged = false;
        std::atomic_bool g_luiSelectorArmed{ false };
        std::atomic_bool g_luiDispatchSeen{ false };
        std::atomic_bool g_autoOfflineMenuQueued{ false };
        std::atomic_bool g_luiGateReadyLogged{ false };
        std::atomic_uint g_luiDispatchCalls{ 0 };
        std::atomic_bool g_luiMenuPending{ false };
        char g_luiMenuName[128]{};

        // 1.44 fence + sign-in profile based on the supplied, independently-tested
        // 1.36/1.44 fence component plus the exact 1.44 sign-in/status RVAs that
        // were already validated in earlier stable runs.  Keep content/LUI/patch
        // truth overrides manual so this test changes only the Blizzard sign-in layer.
        constexpr bool kFenceOnlyAutoProfile = true;
        constexpr bool kServerEmulationMode = true;
        std::atomic_bool g_menuFenceResolveStarted{ false };
        std::atomic_bool g_menuFenceBundleReady{ false };
        std::atomic_bool g_exchangeStateReady{ false };
        std::atomic_uint g_exchangeWrites{ 0 };
        std::atomic_uint g_exchangeResolveAttempts{ 0 };
        std::atomic<std::uintptr_t> g_exchangeArrayBase{ 0 };
        std::atomic_uint g_exchangeArrayDepth{ 0 };
        unsigned long long g_lastFenceResolve = 0;
        unsigned long long g_lastExchangeWrite = 0;
        bool g_fenceOnlyReadyLogged = false;

        using PatchFenceFn = PatchFenceState(*)(void*);
        using OnlineServicesFenceFn = OCDSState(*)(int);
        using SyncOnlineDataFenceFn = FenceOnlineDataState(*)(int, int);
        using BattleNetFenceFn = BattleNetFenceState(*)(std::uintptr_t, BattleNetFenceState);
        using GetUtcFn = std::uint32_t(*)();
        using DvarRegisterBoolFn = void*(__fastcall*)(const char*, bool, unsigned int, const char*);
        using SignInStateFn = int(__fastcall*)(int);
        using DwStatusFn = int(__fastcall*)(int);
        using SignedInFn = bool(__fastcall*)(int);
        using BnetSignedInFn = bool(__fastcall*)(int, int*);
        using ContentPackFn = bool(__fastcall*)(int);
        using LuaBoolFn = int(__fastcall*)(void*);
        using LuaPushBooleanFn = void(__fastcall*)(void*, int);
        using DvarFindFn = void*(__fastcall*)(const char*);
        using LUIOpenMenuFn = void(__fastcall*)(int, const char*, int, int, int);
        using LuaPCallFn = int(__fastcall*)(void*, int, int);
        using REndFrameFn = void(__fastcall*)();

        PatchFenceFn g_patchFenceOriginal = nullptr;
        OnlineServicesFenceFn g_onlineServicesOriginal = nullptr;
        SyncOnlineDataFenceFn g_syncOnlineDataOriginal = nullptr;
        BattleNetFenceFn g_bnetFenceOriginal = nullptr;
        GetUtcFn g_getUtcOriginal = nullptr;
        DvarRegisterBoolFn g_dvarRegisterBoolOriginal = nullptr;
        SignInStateFn g_signInOriginal = nullptr;
        DwStatusFn g_dwStatusOriginal = nullptr;
        SignedInFn g_demonwareSignedInOriginal = nullptr;
        BnetSignedInFn g_bnetSignedInOriginal = nullptr;
        ContentPackFn g_contentPackOriginal = nullptr;
        LuaPCallFn g_luaPCallOriginal = nullptr;
        REndFrameFn g_rEndFrameOriginal = nullptr;

        bool g_patchHook = false;
        bool g_onlineHook = false;
        bool g_syncHook = false;
        bool g_bnetFenceHook = false;
        bool g_utcHook = false;
        bool g_dvarBoolHook = false;
        bool g_signInHook = false;
        bool g_dwHook = false;
        bool g_demonwareHook = false;
        bool g_bnetSignedHook = false;
        bool g_contentHook = false;
        bool g_luiAuthHook = false;
        bool g_luiConnectedHook = false;
        bool g_luiOnlineAreaHook = false;
        bool g_luiOfflineDataHook = false;
        bool g_luaPCallHook = false;
        bool g_rEndFrameHook = false;

        PatchFenceState PatchFenceDetour(void*) { return PatchFenceState::success; }
        OCDSState OnlineServicesDetour(int) { return OCDSState::success; }
        FenceOnlineDataState SyncOnlineDataDetour(int, int) { return FenceOnlineDataState::success; }
        BattleNetFenceState BattleNetFenceDetour(std::uintptr_t, BattleNetFenceState) { return BattleNetFenceState::pass; }
        int __fastcall SignInStateDetour(int) { return 2; }
        int __fastcall DwStatusDetour(int) { return 2; }
        bool __fastcall DemonwareSignedInDetour(int) { return true; }
        bool __fastcall ContentPackDetour(int) { return true; }

        void ClearFailureReason(int* reason) noexcept
        {
            if (!reason) return;
            __try { *reason = 0; }
            __except (EXCEPTION_EXECUTE_HANDLER) {}
        }

        bool __fastcall BnetSignedInDetour(int, int* failReason)
        {
            ClearFailureReason(failReason);
            return true;
        }

        void PushLuaTrue(void* luaState) noexcept
        {
            if (!luaState || !g_base) return;
            const auto address = g_base + iw8_addresses::MW2019_1_44_Rvas.lua_pushboolean;
            auto fn = reinterpret_cast<LuaPushBooleanFn>(address);
            fn(luaState, 1);
        }

        void ProcessLuiThreadWork(void* luaState) noexcept;

        int __fastcall LuaTrueDetour(void* luaState)
        {
            PushLuaTrue(luaState);

            // These three validated LUI gate hooks are invoked by the game's own
            // frontend Lua path.  Use that existing callback thread as the menu
            // queue seam instead of re-hooking LuaShared_PCall (which crashed on
            // this protected 1.44 build).  Guard recursion because opening a menu
            // may synchronously evaluate additional LUI predicates.
            static thread_local bool servicing = false;
            if (!servicing && luaState)
            {
                servicing = true;
                ProcessLuiThreadWork(luaState);
                servicing = false;
            }
            return 1;
        }

        std::uint32_t GetUtcDetour()
        {
            const auto now = std::chrono::system_clock::now();
            const auto seconds = std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch());
            return static_cast<std::uint32_t>(seconds.count());
        }

        bool IsWritableAddress(std::uintptr_t address) noexcept;
        bool CodeLooksReady(std::uintptr_t address) noexcept;

        const BoolOverride* FindOverride(const char* name) noexcept
        {
            if (!name || !*name) return nullptr;
            for (const auto& entry : kFrontendOverrides)
                if (std::strcmp(name, entry.token) == 0 || std::strcmp(name, entry.label) == 0)
                    return &entry;
            return nullptr;
        }

        std::size_t OverrideIndex(const BoolOverride* entry) noexcept
        {
            if (!entry || entry < kFrontendOverrides || entry >= kFrontendOverrides + kFrontendOverrideCount)
                return kFrontendOverrideCount;
            return static_cast<std::size_t>(entry - kFrontendOverrides);
        }

        bool ApplyCapturedBool(void* raw, const BoolOverride& entry) noexcept
        {
            if (!raw || !IsWritableAddress(reinterpret_cast<std::uintptr_t>(raw)))
                return false;
            __try
            {
                auto* dvar = reinterpret_cast<DvarBoolView*>(raw);
                dvar->current.enabled = entry.value;
                dvar->latched.enabled = entry.value;
                dvar->reset.enabled = entry.value;
                dvar->modified = true;
                return true;
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                return false;
            }
        }

        unsigned ApplyCapturedFrontendSelectors(bool verbose) noexcept
        {
            unsigned matched = 0;
            for (std::size_t i = 0; i < kFrontendOverrideCount; ++i)
            {
                void* raw = g_capturedFrontendDvars[i].load(std::memory_order_acquire);
                if (!raw)
                    continue;
                if (ApplyCapturedBool(raw, kFrontendOverrides[i]))
                {
                    ++matched;
                    if (verbose)
                        mw2019_diag::Log("[DVAR] cached %-38s = %s ptr=%p\r\n",
                            kFrontendOverrides[i].label, kFrontendOverrides[i].value ? "true" : "false", raw);
                }
            }
            if (verbose)
                mw2019_diag::Log("[DVAR] cached selector pass matched=%u/%u; no Dvar_FindVarByName calls were made\r\n",
                    matched, static_cast<unsigned>(kFrontendOverrideCount));
            return matched;
        }

        void* FindDvarOnRenderThread(const char* name) noexcept
        {
            if (!g_base || !name || !*name)
                return nullptr;

            const auto address = g_base + iw8_addresses::MW2019_1_44_Rvas.Dvar_FindVarByName;
            if (!CodeLooksReady(address))
                return nullptr;

            auto fn = reinterpret_cast<DvarFindFn>(address);
            void* result = nullptr;
            __try
            {
                result = fn(name);
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                g_renderSelectorFaultCode.store(GetExceptionCode(), std::memory_order_release);
                g_renderSelectorFaulted.store(true, std::memory_order_release);
                g_renderSelectorEnabled.store(false, std::memory_order_release);
                return nullptr;
            }
            return result;
        }

        void ProcessRenderSelectorStep() noexcept
        {
            if (!g_renderSelectorEnabled.load(std::memory_order_acquire) ||
                g_renderSelectorFaulted.load(std::memory_order_acquire))
                return;

            const unsigned long long now = GetTickCount64();
            const unsigned long long nextPass = g_renderSelectorNextPassTick.load(std::memory_order_relaxed);
            if (nextPass && now < nextPass)
                return;

            unsigned index = g_renderSelectorIndex.load(std::memory_order_relaxed);
            if (index >= kFrontendOverrideCount)
                index = 0;

            const auto& entry = kFrontendOverrides[index];
            void* raw = g_capturedFrontendDvars[index].load(std::memory_order_acquire);
            if (!raw)
            {
                raw = FindDvarOnRenderThread(entry.token);
                if (!raw && std::strcmp(entry.token, entry.label) != 0)
                    raw = FindDvarOnRenderThread(entry.label);
                if (raw)
                    g_capturedFrontendDvars[index].store(raw, std::memory_order_release);
            }

            if (raw)
                (void)ApplyCapturedBool(raw, entry);

            ++index;
            if (index >= kFrontendOverrideCount)
            {
                unsigned matched = 0;
                for (std::size_t i = 0; i < kFrontendOverrideCount; ++i)
                {
                    if (g_capturedFrontendDvars[i].load(std::memory_order_acquire))
                        ++matched;
                }
                g_renderSelectorMatched.store(matched, std::memory_order_release);
                g_renderSelectorCompletedPass.fetch_add(1, std::memory_order_acq_rel);
                g_renderSelectorIndex.store(0, std::memory_order_relaxed);
                g_renderSelectorNextPassTick.store(now + 3000ull, std::memory_order_relaxed);
            }
            else
            {
                g_renderSelectorIndex.store(index, std::memory_order_relaxed);
            }
        }

        void ProcessLuiThreadWork(void* luaState) noexcept
        {
            if (!luaState)
                return;

            const unsigned callback = g_luiDispatchCalls.fetch_add(1, std::memory_order_relaxed) + 1;
            if (!g_luiDispatchSeen.exchange(true, std::memory_order_acq_rel))
                mw2019_diag::Log("[LUI144] validated frontend gate callback active; callback-thread menu seam is live\r\n");

            if (g_luiSelectorArmed.load(std::memory_order_acquire))
                ProcessRenderSelectorStep();

            if (!g_luiMenuPending.exchange(false, std::memory_order_acq_rel))
                return;

            char menuName[sizeof(g_luiMenuName)]{};
            strncpy_s(menuName, g_luiMenuName, _TRUNCATE);
            g_luiMenuName[0] = '\0';
            if (!menuName[0] || !g_base)
                return;

            mw2019_diag::Log("[LUI144] callback #%u consumed pending menu -> %s\r\n", callback, menuName);

            const auto address = g_base + iw8_addresses::MW2019_1_44_Rvas.LUI_OpenMenu;
            if (!CodeLooksReady(address))
            {
                mw2019_diag::Log("[MENU144] '%s' not opened: LUI_OpenMenu is not ready\r\n", menuName);
                return;
            }

            auto openFn = reinterpret_cast<LUIOpenMenuFn>(address);
            __try
            {
                openFn(0, menuName, 0, 0, 1);
                mw2019_diag::Log("[MENU144] LUI_OpenMenu returned name='%s' callback=%u\r\n", menuName, callback);
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                mw2019_diag::Log("[MENU144] LUI_OpenMenu fault name='%s' callback=%u code=0x%08X\r\n",
                    menuName, callback, static_cast<unsigned>(GetExceptionCode()));
            }
        }

        bool IsLiveFrontendLuaState(void* luaState) noexcept
        {
            if (!luaState)
                return false;

            const auto vmGlobal = mw2019_scanner::GetAddress("LUI_luaVM");
            const auto frontendFlag = mw2019_scanner::GetAddress("s_luaInFrontend");
            if (!vmGlobal || !frontendFlag)
                return false;

            __try
            {
                const auto liveVm = *reinterpret_cast<void**>(vmGlobal);
                const bool inFrontend = *reinterpret_cast<unsigned char*>(frontendFlag) != 0;
                return inFrontend && liveVm == luaState;
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                return false;
            }
        }

        int __fastcall LuaPCallDetour(void* luaState, int nargs, int nresults)
        {
            auto original = g_luaPCallOriginal;
            const int result = original ? original(luaState, nargs, nresults) : -1;

            // LuaShared_PCall can recurse when menu work causes Lua to execute more
            // script.  Only the outermost call is allowed to service our queue.
            static thread_local bool servicing = false;
            if (!servicing && result == 0 && IsLiveFrontendLuaState(luaState))
            {
                servicing = true;
                ProcessLuiThreadWork(luaState);
                servicing = false;
            }
            return result;
        }

        void __fastcall REndFrameDetour()
        {
            auto original = g_rEndFrameOriginal;
            if (original)
                original();
            ProcessRenderSelectorStep();
        }

        void* __fastcall DvarRegisterBoolDetour(
            const char* name, bool value, unsigned int flags, const char* description)
        {
            const BoolOverride* entry = FindOverride(name);
            const bool replacement = entry ? entry->value : value;
            auto original = g_dvarRegisterBoolOriginal;
            if (!original) return nullptr;
            void* result = original(name, replacement, flags, description);
            if (entry)
            {
                const std::size_t index = OverrideIndex(entry);
                if (index < kFrontendOverrideCount && result)
                    g_capturedFrontendDvars[index].store(result, std::memory_order_release);
                mw2019_diag::Log("[DVAR] register %-38s %s -> %s ptr=%p\r\n",
                    entry->label, value ? "true" : "false", replacement ? "true" : "false", result);
            }
            return result;
        }

        bool GetImageRange(HMODULE module, std::uintptr_t& begin, std::size_t& size) noexcept
        {
            begin = reinterpret_cast<std::uintptr_t>(module);
            size = 0;
            if (!begin) return false;
            __try
            {
                const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(begin);
                if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
                const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(begin + static_cast<std::uintptr_t>(dos->e_lfanew));
                if (nt->Signature != IMAGE_NT_SIGNATURE) return false;
                size = nt->OptionalHeader.SizeOfImage;
                return size > 0 && size < 1024ull * 1024ull * 1024ull;
            }
            __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
        }

        bool IsExecutableAddress(std::uintptr_t address) noexcept
        {
            if (!address) return false;
            MEMORY_BASIC_INFORMATION mbi{};
            if (!VirtualQuery(reinterpret_cast<const void*>(address), &mbi, sizeof(mbi))) return false;
            if (mbi.State != MEM_COMMIT || (mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS))) return false;
            const DWORD p = mbi.Protect & 0xFFu;
            return p == PAGE_EXECUTE || p == PAGE_EXECUTE_READ || p == PAGE_EXECUTE_READWRITE || p == PAGE_EXECUTE_WRITECOPY;
        }

        bool IsReadableAddress(std::uintptr_t address) noexcept
        {
            if (!address) return false;
            MEMORY_BASIC_INFORMATION mbi{};
            if (!VirtualQuery(reinterpret_cast<const void*>(address), &mbi, sizeof(mbi))) return false;
            if (mbi.State != MEM_COMMIT || (mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS))) return false;
            const DWORD p = mbi.Protect & 0xFFu;
            return p == PAGE_READONLY || p == PAGE_READWRITE || p == PAGE_WRITECOPY ||
                p == PAGE_EXECUTE_READ || p == PAGE_EXECUTE_READWRITE || p == PAGE_EXECUTE_WRITECOPY;
        }

        bool IsWritableAddress(std::uintptr_t address) noexcept
        {
            if (!address) return false;
            MEMORY_BASIC_INFORMATION mbi{};
            if (!VirtualQuery(reinterpret_cast<const void*>(address), &mbi, sizeof(mbi))) return false;
            if (mbi.State != MEM_COMMIT || (mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS))) return false;
            const DWORD p = mbi.Protect & 0xFFu;
            return p == PAGE_READWRITE || p == PAGE_WRITECOPY || p == PAGE_EXECUTE_READWRITE || p == PAGE_EXECUTE_WRITECOPY;
        }

        bool CodeLooksReady(std::uintptr_t address) noexcept
        {
            if (!IsExecutableAddress(address)) return false;
            unsigned char bytes[8]{};
            SIZE_T got = 0;
            if (!ReadProcessMemory(GetCurrentProcess(), reinterpret_cast<const void*>(address), bytes, sizeof(bytes), &got) || got != sizeof(bytes))
                return false;
            bool allZero = true;
            bool allCc = true;
            for (unsigned char b : bytes)
            {
                allZero = allZero && b == 0;
                allCc = allCc && b == 0xCC;
            }
            return !allZero && !allCc;
        }

        std::vector<PatternByte> ParsePattern(const char* text)
        {
            std::vector<PatternByte> result;
            if (!text) return result;
            const char* p = text;
            while (*p)
            {
                while (*p == ' ') ++p;
                if (!*p) break;
                if (*p == '?')
                {
                    ++p; if (*p == '?') ++p;
                    result.push_back({0, true});
                }
                else
                {
                    char token[3]{};
                    token[0] = *p++;
                    if (!*p) break;
                    token[1] = *p++;
                    result.push_back({static_cast<unsigned char>(std::strtoul(token, nullptr, 16)), false});
                }
                while (*p == ' ') ++p;
            }
            return result;
        }

        std::uintptr_t FindPattern(HMODULE module, const char* signature)
        {
            std::uintptr_t imageBegin = 0;
            std::size_t imageSize = 0;
            if (!GetImageRange(module, imageBegin, imageSize)) return 0;
            const auto pattern = ParsePattern(signature);
            if (pattern.empty()) return 0;
            const auto imageEnd = imageBegin + static_cast<std::uintptr_t>(imageSize);
            auto address = imageBegin;
            while (address < imageEnd)
            {
                MEMORY_BASIC_INFORMATION mbi{};
                if (!VirtualQuery(reinterpret_cast<const void*>(address), &mbi, sizeof(mbi))) break;
                const auto regionBegin = reinterpret_cast<std::uintptr_t>(mbi.BaseAddress);
                const auto regionEnd = (std::min)(imageEnd, regionBegin + static_cast<std::uintptr_t>(mbi.RegionSize));
                const DWORD protect = mbi.Protect & 0xFFu;
                const bool executable = protect == PAGE_EXECUTE || protect == PAGE_EXECUTE_READ ||
                    protect == PAGE_EXECUTE_READWRITE || protect == PAGE_EXECUTE_WRITECOPY;
                if (mbi.State == MEM_COMMIT && executable && !(mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)) && regionEnd > regionBegin)
                {
                    const auto regionSize = static_cast<std::size_t>(regionEnd - regionBegin);
                    std::vector<unsigned char> bytes(regionSize);
                    SIZE_T got = 0;
                    if (ReadProcessMemory(GetCurrentProcess(), reinterpret_cast<const void*>(regionBegin), bytes.data(), bytes.size(), &got) && got >= pattern.size())
                    {
                        for (std::size_t i = 0; i + pattern.size() <= got; ++i)
                        {
                            bool match = true;
                            for (std::size_t j = 0; j < pattern.size(); ++j)
                            {
                                if (!pattern[j].wildcard && bytes[i + j] != pattern[j].value) { match = false; break; }
                            }
                            if (match) return regionBegin + i;
                        }
                    }
                }
                const auto next = regionBegin + static_cast<std::uintptr_t>(mbi.RegionSize);
                if (next <= address) break;
                address = next;
            }
            return 0;
        }


        bool IsReadableRegion(const MEMORY_BASIC_INFORMATION& mbi) noexcept
        {
            if (mbi.State != MEM_COMMIT || (mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)))
                return false;
            const DWORD protect = mbi.Protect & 0xFFu;
            return protect == PAGE_READONLY || protect == PAGE_READWRITE || protect == PAGE_WRITECOPY ||
                protect == PAGE_EXECUTE || protect == PAGE_EXECUTE_READ ||
                protect == PAGE_EXECUTE_READWRITE || protect == PAGE_EXECUTE_WRITECOPY;
        }

        bool IsExecutableRegion(const MEMORY_BASIC_INFORMATION& mbi) noexcept
        {
            if (mbi.State != MEM_COMMIT || (mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)))
                return false;
            const DWORD protect = mbi.Protect & 0xFFu;
            return protect == PAGE_EXECUTE || protect == PAGE_EXECUTE_READ ||
                protect == PAGE_EXECUTE_READWRITE || protect == PAGE_EXECUTE_WRITECOPY;
        }

        std::uintptr_t FindPatternReadableInImage(HMODULE module, const char* signature)
        {
            std::uintptr_t imageBegin = 0;
            std::size_t imageSize = 0;
            if (!GetImageRange(module, imageBegin, imageSize)) return 0;
            const auto pattern = ParsePattern(signature);
            if (pattern.empty()) return 0;

            const auto imageEnd = imageBegin + static_cast<std::uintptr_t>(imageSize);
            auto address = imageBegin;
            while (address < imageEnd)
            {
                MEMORY_BASIC_INFORMATION mbi{};
                if (!VirtualQuery(reinterpret_cast<const void*>(address), &mbi, sizeof(mbi))) break;
                const auto regionBegin = (std::max)(imageBegin, reinterpret_cast<std::uintptr_t>(mbi.BaseAddress));
                const auto regionEnd = (std::min)(imageEnd,
                    reinterpret_cast<std::uintptr_t>(mbi.BaseAddress) + static_cast<std::uintptr_t>(mbi.RegionSize));
                const DWORD codeProtect = mbi.Protect & 0xFFu;
                const bool codeLike = IsExecutableRegion(mbi) || codeProtect == PAGE_READWRITE ||
                    codeProtect == PAGE_WRITECOPY;
                if (IsReadableRegion(mbi) && codeLike && regionEnd > regionBegin)
                {
                    const auto regionSize = static_cast<std::size_t>(regionEnd - regionBegin);
                    std::vector<unsigned char> bytes(regionSize);
                    SIZE_T got = 0;
                    if (ReadProcessMemory(GetCurrentProcess(), reinterpret_cast<const void*>(regionBegin),
                        bytes.data(), bytes.size(), &got) && got >= pattern.size())
                    {
                        for (std::size_t i = 0; i + pattern.size() <= got; ++i)
                        {
                            bool match = true;
                            for (std::size_t j = 0; j < pattern.size(); ++j)
                            {
                                if (!pattern[j].wildcard && bytes[i + j] != pattern[j].value)
                                {
                                    match = false;
                                    break;
                                }
                            }
                            if (match) return regionBegin + i;
                        }
                    }
                }
                const auto next = reinterpret_cast<std::uintptr_t>(mbi.BaseAddress) +
                    static_cast<std::uintptr_t>(mbi.RegionSize);
                if (next <= address) break;
                address = next;
            }
            return 0;
        }

        bool DecodeRipRelativeLea(std::uintptr_t leaAddress, std::uintptr_t& targetOut,
            unsigned* registerOut = nullptr) noexcept
        {
            targetOut = 0;
            if (!leaAddress) return false;
            __try
            {
                const auto* code = reinterpret_cast<const unsigned char*>(leaAddress);
                // Accept any 64-bit RIP-relative LEA, not only the original
                // `4C 8D 05` (r8) encoding. Arxan/compiler rewriting can move
                // the same global into another register while preserving the
                // surrounding exchange-state conversion.
                if ((code[0] & 0xF8u) != 0x48u || code[1] != 0x8D ||
                    (code[2] & 0xC7u) != 0x05u)
                    return false;

                const auto disp = *reinterpret_cast<const std::int32_t*>(leaAddress + 3);
                targetOut = leaAddress + 7 + static_cast<std::intptr_t>(disp);
                if (registerOut)
                    *registerOut = ((code[0] & 0x04u) ? 8u : 0u) + ((code[2] >> 3) & 7u);
                return true;
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                targetOut = 0;
                return false;
            }
        }

        bool ProbeExchangeArrayBase(std::uintptr_t base, int* slotValue = nullptr,
            unsigned* clusterOut = nullptr) noexcept
        {
            if (!base) return false;
            __try
            {
                const int index = iw8_addresses::MW2019_1_44_Signatures.SignInExchangeControllerOffset;
                const auto slot = base + static_cast<std::uintptr_t>(index) * sizeof(SignInExchangeState);
                if (!IsWritableAddress(slot))
                    return false;

                const int value = *reinterpret_cast<volatile int*>(slot);
                if (value < static_cast<int>(SignInExchangeState::IDLE) ||
                    value > static_cast<int>(SignInExchangeState::SHOWN_POPUP))
                    return false;

                unsigned cluster = 0;
                for (unsigned i = 0; i < 4; ++i)
                {
                    const auto probe = slot + static_cast<std::uintptr_t>(i) * sizeof(SignInExchangeState);
                    if (!IsWritableAddress(probe)) break;
                    const int v = *reinterpret_cast<volatile int*>(probe);
                    if (v < static_cast<int>(SignInExchangeState::IDLE) ||
                        v > static_cast<int>(SignInExchangeState::SHOWN_POPUP))
                        break;
                    ++cluster;
                }

                if (slotValue) *slotValue = value;
                if (clusterOut) *clusterOut = cluster;
                return true;
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                return false;
            }
        }

        bool ResolveExchangeArrayFromLea(std::uintptr_t leaAddress, std::uintptr_t& arrayBaseOut,
            int* slotValue = nullptr, unsigned* registerOut = nullptr,
            unsigned* clusterOut = nullptr, unsigned* depthOut = nullptr) noexcept
        {
            arrayBaseOut = 0;
            std::uintptr_t rawTarget = 0;
            unsigned reg = 0;
            if (!DecodeRipRelativeLea(leaAddress, rawTarget, &reg))
                return false;

            struct Candidate { std::uintptr_t base; unsigned depth; };
            Candidate candidates[3] = {
                {rawTarget, 0},
                {0, 1},
                {0, 2}
            };

            __try
            {
                if (IsReadableAddress(rawTarget))
                {
                    candidates[1].base = *reinterpret_cast<const std::uintptr_t*>(rawTarget);
                    if (candidates[1].base && IsReadableAddress(candidates[1].base))
                        candidates[2].base = *reinterpret_cast<const std::uintptr_t*>(candidates[1].base);
                }
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                candidates[1].base = 0;
                candidates[2].base = 0;
            }

            int bestValue = 0;
            unsigned bestCluster = 0;
            std::uintptr_t bestBase = 0;
            unsigned bestDepth = 0;
            unsigned bestScore = 0;

            for (const auto& candidate : candidates)
            {
                if (!candidate.base) continue;
                int value = 0;
                unsigned cluster = 0;
                if (!ProbeExchangeArrayBase(candidate.base, &value, &cluster))
                    continue;

                unsigned score = cluster * 2u;
                if (value == static_cast<int>(SignInExchangeState::WORKING)) score += 2u;
                if (value == static_cast<int>(SignInExchangeState::ERRORS) ||
                    value == static_cast<int>(SignInExchangeState::SHOWN_POPUP)) score += 5u;
                if (candidate.depth == 0) score += 2u;
                else if (candidate.depth == 1) score += 1u;

                if (!bestBase || score > bestScore)
                {
                    bestBase = candidate.base;
                    bestDepth = candidate.depth;
                    bestValue = value;
                    bestCluster = cluster;
                    bestScore = score;
                }
            }

            if (!bestBase)
                return false;

            arrayBaseOut = bestBase;
            if (slotValue) *slotValue = bestValue;
            if (registerOut) *registerOut = reg;
            if (clusterOut) *clusterOut = bestCluster;
            if (depthOut) *depthOut = bestDepth;
            return true;
        }

        bool IsPlausibleExchangeTarget(std::uintptr_t leaAddress, int* slotValue = nullptr,
            std::uintptr_t* targetOut = nullptr, unsigned* registerOut = nullptr,
            unsigned* clusterOut = nullptr, unsigned* depthOut = nullptr) noexcept
        {
            if (!leaAddress) return false;
            std::uintptr_t arrayBase = 0;
            if (!ResolveExchangeArrayFromLea(leaAddress, arrayBase, slotValue, registerOut,
                clusterOut, depthOut))
                return false;
            if (targetOut) *targetOut = arrayBase;
            return true;
        }

        struct ExchangeDataflowCandidate
        {
            std::uintptr_t lea = 0;
            std::uintptr_t target = 0;
            std::uintptr_t convert = 0;
            int value = 0;
            unsigned reg = 0;
            unsigned cluster = 0;
            unsigned depth = 0;
            unsigned score = 0;
        };

        bool IsCvttsd2siRegister(const unsigned char* p) noexcept
        {
            if (!p) return false;
            // F2 0F 2C /r, register source form. The original source uses C8
            // (ecx,xmm0), but protected 1.44 code may rename either register.
            return p[0] == 0xF2 && p[1] == 0x0F && p[2] == 0x2C && (p[3] & 0xC0u) == 0xC0u;
        }

        void ConsiderExchangeDataflowRegion(std::uintptr_t regionBegin, std::size_t regionSize,
            const char* source, ExchangeDataflowCandidate& best, unsigned& plausibleCount,
            unsigned& convertCount, bool verbose) noexcept
        {
            if (!regionBegin || regionSize < 16) return;
            std::vector<unsigned char> bytes(regionSize);
            SIZE_T got = 0;
            if (!ReadProcessMemory(GetCurrentProcess(), reinterpret_cast<const void*>(regionBegin),
                bytes.data(), bytes.size(), &got) || got < 16)
                return;

            for (std::size_t i = 0; i + 4 <= got; ++i)
            {
                if (!IsCvttsd2siRegister(bytes.data() + i)) continue;
                ++convertCount;

                const std::size_t begin = (i > 384) ? i - 384 : 0;
                const std::size_t finish = (std::min)(got, i + static_cast<std::size_t>(192));
                for (std::size_t j = begin; j + 7 <= finish; ++j)
                {
                    const unsigned char rex = bytes[j];
                    if ((rex & 0xF8u) != 0x48u || bytes[j + 1] != 0x8D ||
                        (bytes[j + 2] & 0xC7u) != 0x05u)
                        continue;

                    const auto lea = regionBegin + j;
                    int value = 0;
                    std::uintptr_t target = 0;
                    unsigned reg = 0, cluster = 0, depth = 0;
                    if (!IsPlausibleExchangeTarget(lea, &value, &target, &reg, &cluster, &depth))
                        continue;

                    ++plausibleCount;
                    const unsigned distance = static_cast<unsigned>(j > i ? j - i : i - j);
                    unsigned score = 2;
                    if (rex == 0x4C && bytes[j + 2] == 0x05) score += 5;
                    if (distance <= 16) score += 4;
                    else if (distance <= 48) score += 3;
                    else if (distance <= 96) score += 2;
                    else if (distance <= 192) score += 1;
                    if (j <= i) score += 1;
                    if (cluster >= 4) score += 4;
                    else if (cluster >= 2) score += 2;
                    if (value == static_cast<int>(SignInExchangeState::WORKING)) score += 3;
                    if (value == static_cast<int>(SignInExchangeState::ERRORS) ||
                        value == static_cast<int>(SignInExchangeState::SHOWN_POPUP)) score += 5;
                    if (depth == 0) score += 2;
                    else if (depth == 1) score += 1;

                    if (score > best.score)
                    {
                        best.lea = lea;
                        best.target = target;
                        best.convert = regionBegin + i;
                        best.value = value;
                        best.reg = reg;
                        best.cluster = cluster;
                        best.depth = depth;
                        best.score = score;
                    }

                    if (verbose && (score >= 10 || plausibleCount <= 8))
                    {
                        mw2019_diag::Log(
                            "[FENCE144] exchange dataflow candidate source=%s lea=%p array=%p cvtt=%p reg=r%u depth=%u index=%d value=%d cluster=%u distance=%u score=%u\r\n",
                            source ? source : "unknown", reinterpret_cast<void*>(lea),
                            reinterpret_cast<void*>(target), reinterpret_cast<void*>(regionBegin + i),
                            reg, depth, iw8_addresses::MW2019_1_44_Signatures.SignInExchangeControllerOffset,
                            value, cluster, distance, score);
                    }
                }
            }
        }

        std::uintptr_t FindExchangeStateRefDataflow(bool verbose) noexcept
        {
            if (!g_module) return 0;

            ExchangeDataflowCandidate best{};
            unsigned plausibleCount = 0;
            unsigned convertCount = 0;

            std::uintptr_t imageBegin = 0;
            std::size_t imageSize = 0;
            if (GetImageRange(g_module, imageBegin, imageSize))
            {
                const auto imageEnd = imageBegin + static_cast<std::uintptr_t>(imageSize);
                auto address = imageBegin;
                while (address < imageEnd)
                {
                    MEMORY_BASIC_INFORMATION mbi{};
                    if (!VirtualQuery(reinterpret_cast<const void*>(address), &mbi, sizeof(mbi))) break;
                    const auto regionBegin = (std::max)(imageBegin, reinterpret_cast<std::uintptr_t>(mbi.BaseAddress));
                    const auto regionEnd = (std::min)(imageEnd,
                        reinterpret_cast<std::uintptr_t>(mbi.BaseAddress) + static_cast<std::uintptr_t>(mbi.RegionSize));
                    const DWORD protect = mbi.Protect & 0xFFu;
                    const bool codeLike = IsExecutableRegion(mbi) || protect == PAGE_READWRITE || protect == PAGE_WRITECOPY;
                    if (IsReadableRegion(mbi) && codeLike && regionEnd > regionBegin &&
                        regionEnd - regionBegin <= 64ull * 1024ull * 1024ull)
                    {
                        ConsiderExchangeDataflowRegion(regionBegin, static_cast<std::size_t>(regionEnd - regionBegin),
                            "main-image", best, plausibleCount, convertCount, verbose);
                    }
                    const auto next = reinterpret_cast<std::uintptr_t>(mbi.BaseAddress) +
                        static_cast<std::uintptr_t>(mbi.RegionSize);
                    if (next <= address) break;
                    address = next;
                }
            }

            // Also inspect executable private/mapped code generated by the
            // protector. We only accept candidates whose LEA resolves to a
            // writable +1642 enum slot, so this remains much narrower than a
            // blind process-wide data patch.
            SYSTEM_INFO si{};
            GetSystemInfo(&si);
            auto address = reinterpret_cast<std::uintptr_t>(si.lpMinimumApplicationAddress);
            const auto maximum = reinterpret_cast<std::uintptr_t>(si.lpMaximumApplicationAddress);
            while (address < maximum)
            {
                MEMORY_BASIC_INFORMATION mbi{};
                if (!VirtualQuery(reinterpret_cast<const void*>(address), &mbi, sizeof(mbi))) break;
                const auto regionBegin = reinterpret_cast<std::uintptr_t>(mbi.BaseAddress);
                const auto regionEnd = regionBegin + static_cast<std::uintptr_t>(mbi.RegionSize);
                if (IsExecutableRegion(mbi) && (mbi.Type == MEM_PRIVATE || mbi.Type == MEM_MAPPED) &&
                    mbi.RegionSize <= 32ull * 1024ull * 1024ull)
                {
                    ConsiderExchangeDataflowRegion(regionBegin, static_cast<std::size_t>(mbi.RegionSize),
                        "protected-private", best, plausibleCount, convertCount, verbose);
                }
                if (regionEnd <= address) break;
                address = regionEnd;
            }

            if (verbose || best.lea)
            {
                mw2019_diag::Log(
                    "[FENCE144] exchange dataflow summary cvtt=%u plausible=%u bestScore=%u bestLea=%p bestTarget=%p bestValue=%d bestCluster=%u bestDepth=%u\r\n",
                    convertCount, plausibleCount, best.score, reinterpret_cast<void*>(best.lea),
                    reinterpret_cast<void*>(best.target), best.value, best.cluster, best.depth);
            }

            // Require several independent signals before writing anything.
            // Exact-source register+distance is already strong; alternatively a
            // controller-state cluster plus a live WORKING/ERROR state is enough.
            if (best.lea && best.score >= 10)
            {
                mw2019_diag::Log(
                    "[FENCE144] exchange resolver source=dataflow ACCEPT lea=%p array=%p cvtt=%p reg=r%u depth=%u index=%d value=%d cluster=%u score=%u\r\n",
                    reinterpret_cast<void*>(best.lea), reinterpret_cast<void*>(best.target),
                    reinterpret_cast<void*>(best.convert), best.reg, best.depth,
                    iw8_addresses::MW2019_1_44_Signatures.SignInExchangeControllerOffset,
                    best.value, best.cluster, best.score);
                g_exchangeArrayBase.store(best.target, std::memory_order_release);
                g_exchangeArrayDepth.store(best.depth, std::memory_order_release);
                return best.lea;
            }
            return 0;
        }

        std::uintptr_t FindExchangeStateRefFallback(bool verbose) noexcept
        {
            if (!g_module) return 0;
            const char* signature = iw8_addresses::MW2019_1_44_Signatures.SignInExchangeStateRef;
            const unsigned attempt = g_exchangeResolveAttempts.fetch_add(1, std::memory_order_acq_rel) + 1;
            const bool deepImagePass = verbose || (attempt % 6u) == 0u;

            // Arxan/protected 1.44 pages are not always executable at the moment
            // our helper thread scans them. First retry the exact supplied
            // signature across every readable committed page in the main image.
            if (deepImagePass)
            {
                if (const auto readableHit = FindPatternReadableInImage(g_module, signature))
                {
                    int value = 0;
                    std::uintptr_t target = 0;
                    if (IsPlausibleExchangeTarget(readableHit, &value, &target))
                    {
                        if (verbose)
                            mw2019_diag::Log(
                                "[FENCE144] exchange resolver source=main-image-readable lea=%p target=%p index=%d value=%d\r\n",
                                reinterpret_cast<void*>(readableHit), reinterpret_cast<void*>(target),
                                iw8_addresses::MW2019_1_44_Signatures.SignInExchangeControllerOffset, value);
                        return readableHit;
                    }
                }
            }

            // Protected code can also execute from MEM_PRIVATE pages. Search
            // only executable private/mapped regions, and accept a match only
            // when its RIP target leads to a writable +1642 enum slot.
            const auto pattern = ParsePattern(signature);
            if (pattern.empty()) return 0;

            SYSTEM_INFO si{};
            GetSystemInfo(&si);
            auto address = reinterpret_cast<std::uintptr_t>(si.lpMinimumApplicationAddress);
            const auto maximum = reinterpret_cast<std::uintptr_t>(si.lpMaximumApplicationAddress);
            unsigned candidates = 0;

            while (address < maximum)
            {
                MEMORY_BASIC_INFORMATION mbi{};
                if (!VirtualQuery(reinterpret_cast<const void*>(address), &mbi, sizeof(mbi))) break;
                const auto regionBegin = reinterpret_cast<std::uintptr_t>(mbi.BaseAddress);
                const auto regionEnd = regionBegin + static_cast<std::uintptr_t>(mbi.RegionSize);

                if (IsExecutableRegion(mbi) && (mbi.Type == MEM_PRIVATE || mbi.Type == MEM_MAPPED) &&
                    mbi.RegionSize <= 64ull * 1024ull * 1024ull)
                {
                    const auto regionSize = static_cast<std::size_t>(mbi.RegionSize);
                    std::vector<unsigned char> bytes(regionSize);
                    SIZE_T got = 0;
                    if (ReadProcessMemory(GetCurrentProcess(), reinterpret_cast<const void*>(regionBegin),
                        bytes.data(), bytes.size(), &got) && got >= pattern.size())
                    {
                        for (std::size_t i = 0; i + pattern.size() <= got; ++i)
                        {
                            bool match = true;
                            for (std::size_t j = 0; j < pattern.size(); ++j)
                            {
                                if (!pattern[j].wildcard && bytes[i + j] != pattern[j].value)
                                {
                                    match = false;
                                    break;
                                }
                            }
                            if (!match) continue;

                            const auto hit = regionBegin + i;
                            int value = 0;
                            std::uintptr_t target = 0;
                            if (!IsPlausibleExchangeTarget(hit, &value, &target))
                                continue;

                            ++candidates;
                            if (verbose || value == static_cast<int>(SignInExchangeState::ERRORS) ||
                                value == static_cast<int>(SignInExchangeState::SHOWN_POPUP))
                            {
                                mw2019_diag::Log(
                                    "[FENCE144] exchange resolver source=protected-private lea=%p target=%p index=%d value=%d candidates=%u\r\n",
                                    reinterpret_cast<void*>(hit), reinterpret_cast<void*>(target),
                                    iw8_addresses::MW2019_1_44_Signatures.SignInExchangeControllerOffset,
                                    value, candidates);
                            }
                            return hit;
                        }
                    }
                }

                if (regionEnd <= address) break;
                address = regionEnd;
            }

            // Final relaxed pass: keep the supplied LEA opcode, but permit a few
            // protected instructions between the LEA and CVTTSD2SI. This avoids
            // guessing a different global/register while tolerating 1.44 code
            // rewriting around the exact signature.
            std::uintptr_t imageBegin = 0;
            std::size_t imageSize = 0;
            if (deepImagePass && GetImageRange(g_module, imageBegin, imageSize))
            {
                const auto imageEnd = imageBegin + static_cast<std::uintptr_t>(imageSize);
                auto scan = imageBegin;
                while (scan < imageEnd)
                {
                    MEMORY_BASIC_INFORMATION mbi{};
                    if (!VirtualQuery(reinterpret_cast<const void*>(scan), &mbi, sizeof(mbi))) break;
                    const auto regionBegin = (std::max)(imageBegin, reinterpret_cast<std::uintptr_t>(mbi.BaseAddress));
                    const auto regionEnd = (std::min)(imageEnd,
                        reinterpret_cast<std::uintptr_t>(mbi.BaseAddress) + static_cast<std::uintptr_t>(mbi.RegionSize));
                    const DWORD codeProtect = mbi.Protect & 0xFFu;
                    const bool codeLike = IsExecutableRegion(mbi) || codeProtect == PAGE_READWRITE ||
                        codeProtect == PAGE_WRITECOPY;
                    if (IsReadableRegion(mbi) && codeLike && regionEnd > regionBegin)
                    {
                        const auto regionSize = static_cast<std::size_t>(regionEnd - regionBegin);
                        std::vector<unsigned char> bytes(regionSize);
                        SIZE_T got = 0;
                        if (ReadProcessMemory(GetCurrentProcess(), reinterpret_cast<const void*>(regionBegin),
                            bytes.data(), bytes.size(), &got) && got >= 11)
                        {
                            for (std::size_t i = 0; i + 11 <= got; ++i)
                            {
                                if (bytes[i] != 0x4C || bytes[i + 1] != 0x8D || bytes[i + 2] != 0x05)
                                    continue;
                                bool hasConvert = false;
                                const std::size_t maxAhead = (std::min)(got - i, static_cast<std::size_t>(32));
                                for (std::size_t k = 7; k + 3 < maxAhead; ++k)
                                {
                                    if (bytes[i + k] == 0xF2 && bytes[i + k + 1] == 0x0F &&
                                        bytes[i + k + 2] == 0x2C && bytes[i + k + 3] == 0xC8)
                                    {
                                        hasConvert = true;
                                        break;
                                    }
                                }
                                if (!hasConvert) continue;

                                const auto hit = regionBegin + i;
                                int value = 0;
                                std::uintptr_t target = 0;
                                if (!IsPlausibleExchangeTarget(hit, &value, &target))
                                    continue;
                                if (verbose)
                                    mw2019_diag::Log(
                                        "[FENCE144] exchange resolver source=relaxed-main-image lea=%p target=%p index=%d value=%d\r\n",
                                        reinterpret_cast<void*>(hit), reinterpret_cast<void*>(target),
                                        iw8_addresses::MW2019_1_44_Signatures.SignInExchangeControllerOffset, value);
                                return hit;
                            }
                        }
                    }
                    const auto next = reinterpret_cast<std::uintptr_t>(mbi.BaseAddress) +
                        static_cast<std::uintptr_t>(mbi.RegionSize);
                    if (next <= scan) break;
                    scan = next;
                }
            }

            if (verbose)
                mw2019_diag::Log("[FENCE144] exchange resolver still waiting; exact + protected + relaxed scans found no validated +1642 slot; trying +1642/0x19A8 indexing resolver before LEA/CVTT fallback\r\n");
            return 0;
        }

        bool DecodeRipRelativeDataReference(std::uintptr_t instruction, std::uintptr_t& targetOut,
            unsigned* registerOut = nullptr, bool* isLeaOut = nullptr) noexcept
        {
            targetOut = 0;
            if (!instruction) return false;
            __try
            {
                const auto* code = reinterpret_cast<const unsigned char*>(instruction);
                if ((code[0] & 0xF8u) != 0x48u)
                    return false;
                if (code[1] != 0x8D && code[1] != 0x8B)
                    return false;
                if ((code[2] & 0xC7u) != 0x05u)
                    return false;

                const auto disp = *reinterpret_cast<const std::int32_t*>(instruction + 3);
                targetOut = instruction + 7 + static_cast<std::intptr_t>(disp);
                if (registerOut)
                    *registerOut = ((code[0] & 0x04u) ? 8u : 0u) + ((code[2] >> 3) & 7u);
                if (isLeaOut)
                    *isLeaOut = code[1] == 0x8D;
                return true;
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                targetOut = 0;
                return false;
            }
        }

        bool ProbeExchangeBaseFromReference(std::uintptr_t rawTarget, bool isLea,
            std::uintptr_t& bestBase, unsigned& bestDepth, int& bestValue,
            unsigned& bestCluster, unsigned& bestScore) noexcept
        {
            bestBase = 0;
            bestDepth = 0;
            bestValue = 0;
            bestCluster = 0;
            bestScore = 0;
            if (!rawTarget) return false;

            std::uintptr_t candidates[3] = { rawTarget, 0, 0 };
            __try
            {
                if (IsReadableAddress(rawTarget))
                {
                    candidates[1] = *reinterpret_cast<const std::uintptr_t*>(rawTarget);
                    if (candidates[1] && IsReadableAddress(candidates[1]))
                        candidates[2] = *reinterpret_cast<const std::uintptr_t*>(candidates[1]);
                }
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                candidates[1] = 0;
                candidates[2] = 0;
            }

            for (unsigned depth = 0; depth < 3; ++depth)
            {
                const auto base = candidates[depth];
                if (!base) continue;
                int value = 0;
                unsigned cluster = 0;
                if (!ProbeExchangeArrayBase(base, &value, &cluster))
                    continue;

                unsigned score = cluster * 2u;
                if (cluster >= 4) score += 4u;
                if (value == static_cast<int>(SignInExchangeState::WORKING)) score += 2u;
                if (value == static_cast<int>(SignInExchangeState::ERRORS) ||
                    value == static_cast<int>(SignInExchangeState::SHOWN_POPUP)) score += 5u;

                // LEA commonly gives the base directly; MOV commonly gives a pointer
                // loaded from a global slot. Prefer the form that matches that shape.
                if (isLea && depth == 0) score += 3u;
                if (!isLea && depth == 1) score += 3u;
                if (depth <= 1) score += 1u;

                if (!bestBase || score > bestScore)
                {
                    bestBase = base;
                    bestDepth = depth;
                    bestValue = value;
                    bestCluster = cluster;
                    bestScore = score;
                }
            }
            return bestBase != 0;
        }

        struct Exchange1642Candidate
        {
            std::uintptr_t marker = 0;
            std::uintptr_t reference = 0;
            std::uintptr_t target = 0;
            std::uintptr_t arrayBase = 0;
            unsigned markerKind = 0; // 1 = index 1642 (0x66A), 2 = byte offset 0x19A8
            unsigned reg = 0;
            unsigned depth = 0;
            unsigned cluster = 0;
            unsigned distance = 0;
            unsigned score = 0;
            int value = 0;
            bool isLea = false;
        };

        bool IsImmediate32(const unsigned char* p, std::uint32_t value) noexcept
        {
            if (!p) return false;
            return p[0] == static_cast<unsigned char>(value & 0xFFu) &&
                p[1] == static_cast<unsigned char>((value >> 8) & 0xFFu) &&
                p[2] == static_cast<unsigned char>((value >> 16) & 0xFFu) &&
                p[3] == static_cast<unsigned char>((value >> 24) & 0xFFu);
        }

        void ConsiderExchange1642Region(std::uintptr_t regionBegin, std::size_t regionSize,
            const char* source, Exchange1642Candidate& best, unsigned& markerCount,
            unsigned& plausibleCount, bool verbose) noexcept
        {
            if (!regionBegin || regionSize < 16) return;
            std::vector<unsigned char> bytes(regionSize);
            SIZE_T got = 0;
            if (!ReadProcessMemory(GetCurrentProcess(), reinterpret_cast<const void*>(regionBegin),
                bytes.data(), bytes.size(), &got) || got < 16)
                return;

            constexpr std::uint32_t kControllerIndex = 1642u; // 0x66A
            constexpr std::uint32_t kByteOffset = 1642u * sizeof(SignInExchangeState); // 0x19A8

            for (std::size_t i = 0; i + 4 <= got; ++i)
            {
                unsigned markerKind = 0;
                if (IsImmediate32(bytes.data() + i, kControllerIndex)) markerKind = 1;
                else if (IsImmediate32(bytes.data() + i, kByteOffset)) markerKind = 2;
                if (!markerKind) continue;
                ++markerCount;

                const std::size_t begin = i > 512 ? i - 512 : 0;
                const std::size_t finish = (std::min)(got, i + static_cast<std::size_t>(512));
                for (std::size_t j = begin; j + 7 <= finish; ++j)
                {
                    const auto instruction = regionBegin + j;
                    std::uintptr_t rawTarget = 0;
                    unsigned reg = 0;
                    bool isLea = false;
                    if (!DecodeRipRelativeDataReference(instruction, rawTarget, &reg, &isLea))
                        continue;

                    std::uintptr_t arrayBase = 0;
                    unsigned depth = 0, cluster = 0, baseScore = 0;
                    int value = 0;
                    if (!ProbeExchangeBaseFromReference(rawTarget, isLea, arrayBase, depth,
                        value, cluster, baseScore))
                        continue;

                    ++plausibleCount;
                    const unsigned distance = static_cast<unsigned>(j > i ? j - i : i - j);
                    unsigned score = baseScore;
                    score += markerKind == 2 ? 7u : 6u;
                    if (distance <= 24) score += 6u;
                    else if (distance <= 64) score += 5u;
                    else if (distance <= 128) score += 4u;
                    else if (distance <= 256) score += 2u;
                    else score += 1u;
                    if (j <= i) score += 1u;

                    // Seeing the old conversion opcode nearby is supporting evidence,
                    // but unlike v2/v3 it is no longer required.
                    const std::size_t cvttBegin = i > 96 ? i - 96 : 0;
                    const std::size_t cvttEnd = (std::min)(got, i + static_cast<std::size_t>(96));
                    bool nearbyCvtt = false;
                    for (std::size_t k = cvttBegin; k + 4 <= cvttEnd; ++k)
                    {
                        if (IsCvttsd2siRegister(bytes.data() + k))
                        {
                            nearbyCvtt = true;
                            break;
                        }
                    }
                    if (nearbyCvtt) score += 3u;

                    if (score > best.score)
                    {
                        best.marker = regionBegin + i;
                        best.reference = instruction;
                        best.target = rawTarget;
                        best.arrayBase = arrayBase;
                        best.markerKind = markerKind;
                        best.reg = reg;
                        best.depth = depth;
                        best.cluster = cluster;
                        best.distance = distance;
                        best.score = score;
                        best.value = value;
                        best.isLea = isLea;
                    }

                    if (verbose && (score >= 18u || plausibleCount <= 8u))
                    {
                        mw2019_diag::Log(
                            "[FENCE144] exchange1642 candidate source=%s marker=%p kind=%s ref=%p op=%s raw=%p array=%p reg=r%u depth=%u index=%u value=%d cluster=%u distance=%u score=%u\r\n",
                            source ? source : "unknown", reinterpret_cast<void*>(regionBegin + i),
                            markerKind == 2 ? "0x19A8" : "0x66A",
                            reinterpret_cast<void*>(instruction), isLea ? "LEA" : "MOV",
                            reinterpret_cast<void*>(rawTarget), reinterpret_cast<void*>(arrayBase),
                            reg, depth, kControllerIndex, value, cluster, distance, score);
                    }
                }
            }
        }

        std::uintptr_t FindExchangeStateRefBy1642(bool verbose) noexcept
        {
            if (!g_module) return 0;

            Exchange1642Candidate best{};
            unsigned markerCount = 0;
            unsigned plausibleCount = 0;

            std::uintptr_t imageBegin = 0;
            std::size_t imageSize = 0;
            if (GetImageRange(g_module, imageBegin, imageSize))
            {
                const auto imageEnd = imageBegin + static_cast<std::uintptr_t>(imageSize);
                auto address = imageBegin;
                while (address < imageEnd)
                {
                    MEMORY_BASIC_INFORMATION mbi{};
                    if (!VirtualQuery(reinterpret_cast<const void*>(address), &mbi, sizeof(mbi))) break;
                    const auto regionBegin = (std::max)(imageBegin,
                        reinterpret_cast<std::uintptr_t>(mbi.BaseAddress));
                    const auto regionEnd = (std::min)(imageEnd,
                        reinterpret_cast<std::uintptr_t>(mbi.BaseAddress) + static_cast<std::uintptr_t>(mbi.RegionSize));
                    const DWORD p = mbi.Protect & 0xFFu;
                    const bool codeLike = IsExecutableRegion(mbi) || p == PAGE_READWRITE || p == PAGE_WRITECOPY;
                    if (IsReadableRegion(mbi) && codeLike && regionEnd > regionBegin &&
                        regionEnd - regionBegin <= 64ull * 1024ull * 1024ull)
                    {
                        ConsiderExchange1642Region(regionBegin,
                            static_cast<std::size_t>(regionEnd - regionBegin), "main-image",
                            best, markerCount, plausibleCount, verbose);
                    }
                    const auto next = reinterpret_cast<std::uintptr_t>(mbi.BaseAddress) +
                        static_cast<std::uintptr_t>(mbi.RegionSize);
                    if (next <= address) break;
                    address = next;
                }
            }

            SYSTEM_INFO si{};
            GetSystemInfo(&si);
            auto address = reinterpret_cast<std::uintptr_t>(si.lpMinimumApplicationAddress);
            const auto maximum = reinterpret_cast<std::uintptr_t>(si.lpMaximumApplicationAddress);
            while (address < maximum)
            {
                MEMORY_BASIC_INFORMATION mbi{};
                if (!VirtualQuery(reinterpret_cast<const void*>(address), &mbi, sizeof(mbi))) break;
                const auto regionBegin = reinterpret_cast<std::uintptr_t>(mbi.BaseAddress);
                const auto regionEnd = regionBegin + static_cast<std::uintptr_t>(mbi.RegionSize);
                if (IsExecutableRegion(mbi) && (mbi.Type == MEM_PRIVATE || mbi.Type == MEM_MAPPED) &&
                    mbi.RegionSize <= 64ull * 1024ull * 1024ull)
                {
                    ConsiderExchange1642Region(regionBegin, static_cast<std::size_t>(mbi.RegionSize),
                        "protected-private", best, markerCount, plausibleCount, verbose);
                }
                if (regionEnd <= address) break;
                address = regionEnd;
            }

            if (verbose || best.reference)
            {
                mw2019_diag::Log(
                    "[FENCE144] exchange1642 summary markers=%u plausible=%u bestScore=%u marker=%p kind=%s ref=%p raw=%p array=%p value=%d cluster=%u depth=%u distance=%u\r\n",
                    markerCount, plausibleCount, best.score, reinterpret_cast<void*>(best.marker),
                    best.markerKind == 2 ? "0x19A8" : (best.markerKind == 1 ? "0x66A" : "none"),
                    reinterpret_cast<void*>(best.reference), reinterpret_cast<void*>(best.target),
                    reinterpret_cast<void*>(best.arrayBase), best.value, best.cluster,
                    best.depth, best.distance);
            }

            // Marker + valid writable enum array + nearby RIP data reference are
            // independent signals. Keep the threshold deliberately high because
            // this path writes one integer into the stock frontend state array.
            if (best.reference && best.arrayBase && best.score >= 18u)
            {
                mw2019_diag::Log(
                    "[FENCE144] exchange resolver source=1642-index ACCEPT marker=%p kind=%s ref=%p op=%s array=%p depth=%u index=1642 value=%d cluster=%u score=%u\r\n",
                    reinterpret_cast<void*>(best.marker), best.markerKind == 2 ? "0x19A8" : "0x66A",
                    reinterpret_cast<void*>(best.reference), best.isLea ? "LEA" : "MOV",
                    reinterpret_cast<void*>(best.arrayBase), best.depth, best.value,
                    best.cluster, best.score);
                g_exchangeArrayBase.store(best.arrayBase, std::memory_order_release);
                g_exchangeArrayDepth.store(best.depth, std::memory_order_release);
                return best.reference;
            }
            return 0;
        }

        std::uintptr_t ResolveExchangeStateRef(bool verbose) noexcept
        {
            if (g_detection.SignInExchangeStateRef)
                return g_detection.SignInExchangeStateRef;

            if (const auto exact = FindPattern(g_module,
                iw8_addresses::MW2019_1_44_Signatures.SignInExchangeStateRef))
            {
                int value = 0;
                std::uintptr_t target = 0;
                unsigned depth = 0;
                if (IsPlausibleExchangeTarget(exact, &value, &target, nullptr, nullptr, &depth))
                {
                    if (verbose)
                        mw2019_diag::Log(
                            "[FENCE144] exchange resolver source=main-image-exec lea=%p array=%p depth=%u index=%d value=%d\r\n",
                            reinterpret_cast<void*>(exact), reinterpret_cast<void*>(target), depth,
                            iw8_addresses::MW2019_1_44_Signatures.SignInExchangeControllerOffset, value);
                    g_exchangeArrayBase.store(target, std::memory_order_release);
                    g_exchangeArrayDepth.store(depth, std::memory_order_release);
                    g_detection.SignInExchangeStateRef = exact;
                    return exact;
                }
            }

            g_detection.SignInExchangeStateRef = FindExchangeStateRefFallback(verbose);
            // v4 no longer depends on the public LEA/CVTT signature. For 1.44 the
            // invariant is controllerIndex + 1642. Because SignInExchangeState is
            // an int-sized enum, optimized code commonly exposes either immediate
            // 0x66A (the index) or 0x19A8 (the byte displacement). Resolve from
            // those indexing sites first, then retain v3 dataflow as a fallback.
            const unsigned attempts = g_exchangeResolveAttempts.load(std::memory_order_acquire);
            const bool heavyPass = verbose || (attempts != 0 && (attempts % 6u) == 0u);
            if (!g_detection.SignInExchangeStateRef && heavyPass)
                g_detection.SignInExchangeStateRef = FindExchangeStateRefBy1642(verbose);
            if (!g_detection.SignInExchangeStateRef && heavyPass)
                g_detection.SignInExchangeStateRef = FindExchangeStateRefDataflow(verbose);
            return g_detection.SignInExchangeStateRef;
        }

        bool HookIfReady(std::uintptr_t target, void* detour, void** original) noexcept
        {
            if (!CodeLooksReady(target)) return false;
            const auto init = MH_Initialize();
            if (init != MH_OK && init != MH_ERROR_ALREADY_INITIALIZED) return false;
            const auto create = MH_CreateHook(reinterpret_cast<void*>(target), detour, original);
            if (create != MH_OK && create != MH_ERROR_ALREADY_CREATED) return false;
            const auto enable = MH_EnableHook(reinterpret_cast<void*>(target));
            return enable == MH_OK || enable == MH_ERROR_ENABLED;
        }

        void SeedScannerAddresses() noexcept
        {
            if (!g_base) return;
            const auto& r = iw8_addresses::MW2019_1_44_Rvas;
            const auto seedExec = [&](const char* name, std::uintptr_t rva)
            {
                const auto address = g_base + rva;
                if (CodeLooksReady(address)) mw2019_scanner::SeedAddress(name, address);
            };

            // Pure server-emulation mode only keeps the small set of stock
            // login/auth correlation points. Lua/LUI/menu/dvar addresses are
            // intentionally not seeded or used by this profile.
            seedExec("CL_GetLocalClientSignInState", r.CL_GetLocalClientSignInState);
            seedExec("dwGetLogOnStatus", r.dwGetLogOnStatus);
            seedExec("Live_IsUserSignedInToDemonware", r.Live_IsUserSignedInToDemonware);
            seedExec("unk_IsUserSignedInToBNet", r.unk_IsUserSignedInToBNet);
            if (kServerEmulationMode)
                return;

            seedExec("Dvar_RegisterBool", r.Dvar_RegisterBool);
            seedExec("Dvar_RegisterString", r.Dvar_RegisterString);
            seedExec("Dvar_FindVarByName", r.Dvar_FindVarByName);
            seedExec("Cmd_Exec_Internal", r.Cmd_Exec_Internal);
            seedExec("Content_DoWeHaveContentPack", r.Content_DoWeHaveContentPack);
            seedExec("Live_OnlineServicesFence_GetState", r.Live_OnlineServicesFence_GetState);
            seedExec("Live_SyncOnlineDataFence_GetState", r.Live_SyncOnlineDataFence_GetState);
            seedExec("LUI_CoD_LuaCall_IsBattleNetAuthReady", r.LUI_CoD_LuaCall_IsBattleNetAuthReady);
            seedExec("LUI_CoD_LuaCall_IsConnectedToGameServer", r.LUI_CoD_LuaCall_IsConnectedToGameServer);
            seedExec("LUI_CoD_LuaCall_ShouldBeInOnlineArea", r.LUI_CoD_LuaCall_ShouldBeInOnlineArea);
            seedExec("LUI_CoD_LuaCall_OfflineDataFetched", r.LUI_CoD_LuaCall_OfflineDataFetched);
            seedExec("OnlineErrorManager_GetFenceState", r.OnlineErrorManager_GetFenceState);
            seedExec("OnlineErrorManager_IsMpNotAllowed", r.OnlineErrorManager_IsMpNotAllowed);
            seedExec("lua_pushboolean", r.lua_pushboolean);
            seedExec("LUI_OpenMenu", r.LUI_OpenMenu);
            seedExec("R_EndFrame", r.R_EndFrame);
            const auto state = g_base + r.s_OnlineServicesFenceData_state;
            if (IsWritableAddress(state)) mw2019_scanner::SeedAddress("s_OnlineServicesFenceData_state", state);
        }

        bool InstallOne(const char* label, std::uintptr_t address, void* detour, void** original, bool& flag) noexcept
        {
            if (flag) return true;
            if (!HookIfReady(address, detour, original)) return false;
            flag = true;
            ++g_installedHooks;
            mw2019_diag::Log("[HOOK] %-42s installed rva=0x%llX\r\n",
                label, static_cast<unsigned long long>(address - g_base));
            return true;
        }

        void InstallFastExactHooks() noexcept
        {
            if (!g_base) return;
            const auto& r = iw8_addresses::MW2019_1_44_Rvas;

            // Startup-safe set only.  The previous test died immediately after
            // arming 11 hooks, before either the command scan or blade selector
            // pass ran.  Older successful 1.44 runs proved Dvar_RegisterBool and
            // the two core fence-state functions can be present during startup.
            // Sign-in/content/LUI hooks stay available, but are armed manually
            // with `hooks144` after the stock splash/frontend is alive.
            InstallOne("Dvar_RegisterBool", g_base + r.Dvar_RegisterBool,
                reinterpret_cast<void*>(&DvarRegisterBoolDetour), reinterpret_cast<void**>(&g_dvarRegisterBoolOriginal), g_dvarBoolHook);
            InstallOne("Live_OnlineServicesFence_GetState", g_base + r.Live_OnlineServicesFence_GetState,
                reinterpret_cast<void*>(&OnlineServicesDetour), reinterpret_cast<void**>(&g_onlineServicesOriginal), g_onlineHook);
            InstallOne("Live_SyncOnlineDataFence_GetState", g_base + r.Live_SyncOnlineDataFence_GetState,
                reinterpret_cast<void*>(&SyncOnlineDataDetour), reinterpret_cast<void**>(&g_syncOnlineDataOriginal), g_syncHook);
        }

        void InstallSignInHooks() noexcept
        {
            if (!g_base) return;
            const auto& r = iw8_addresses::MW2019_1_44_Rvas;
            InstallOne("CL_GetLocalClientSignInState", g_base + r.CL_GetLocalClientSignInState,
                reinterpret_cast<void*>(&SignInStateDetour), reinterpret_cast<void**>(&g_signInOriginal), g_signInHook);
            InstallOne("dwGetLogOnStatus", g_base + r.dwGetLogOnStatus,
                reinterpret_cast<void*>(&DwStatusDetour), reinterpret_cast<void**>(&g_dwStatusOriginal), g_dwHook);
            InstallOne("Live_IsUserSignedInToDemonware", g_base + r.Live_IsUserSignedInToDemonware,
                reinterpret_cast<void*>(&DemonwareSignedInDetour), reinterpret_cast<void**>(&g_demonwareSignedInOriginal), g_demonwareHook);
            InstallOne("unk_IsUserSignedInToBNet", g_base + r.unk_IsUserSignedInToBNet,
                reinterpret_cast<void*>(&BnetSignedInDetour), reinterpret_cast<void**>(&g_bnetSignedInOriginal), g_bnetSignedHook);
        }

        void InstallContentHook() noexcept
        {
            if (!g_base) return;
            const auto& r = iw8_addresses::MW2019_1_44_Rvas;
            InstallOne("Content_DoWeHaveContentPack", g_base + r.Content_DoWeHaveContentPack,
                reinterpret_cast<void*>(&ContentPackDetour), reinterpret_cast<void**>(&g_contentPackOriginal), g_contentHook);
        }

        void InstallLuiHooks() noexcept
        {
            if (!g_base) return;
            const auto& r = iw8_addresses::MW2019_1_44_Rvas;
            if (!CodeLooksReady(g_base + r.lua_pushboolean))
            {
                mw2019_diag::Log("[HOOK] lua_pushboolean is not ready; LUI hooks left untouched\r\n");
                return;
            }

            // The 1.44 live run proved the first three LUI gates install cleanly
            // and are enough to advance the stock sign-in screen into the normal
            // "Connecting to Online Services" flow.  MinHook stalls inside the
            // OfflineDataFetched target on this protected build, which previously
            // blocked this worker forever and prevented stages 4/5 from running.
            // Keep that target discovered/printed for research, but do not arm it
            // automatically (or through the normal grouped hook commands) yet.
            InstallOne("LUI_IsBattleNetAuthReady", g_base + r.LUI_CoD_LuaCall_IsBattleNetAuthReady,
                reinterpret_cast<void*>(&LuaTrueDetour), nullptr, g_luiAuthHook);
            InstallOne("LUI_IsConnectedToGameServer", g_base + r.LUI_CoD_LuaCall_IsConnectedToGameServer,
                reinterpret_cast<void*>(&LuaTrueDetour), nullptr, g_luiConnectedHook);
            InstallOne("LUI_ShouldBeInOnlineArea", g_base + r.LUI_CoD_LuaCall_ShouldBeInOnlineArea,
                reinterpret_cast<void*>(&LuaTrueDetour), nullptr, g_luiOnlineAreaHook);
        }

        bool LuaFrontendReadyForSelectors() noexcept
        {
            const auto vmGlobal = mw2019_scanner::GetAddress("LUI_luaVM");
            const auto frontendFlag = mw2019_scanner::GetAddress("s_luaInFrontend");
            if (!vmGlobal || !frontendFlag)
                return false;

            __try
            {
                const auto vm = *reinterpret_cast<void**>(vmGlobal);
                const bool inFrontend = *reinterpret_cast<unsigned char*>(frontendFlag) != 0;
                return vm != nullptr && inFrontend;
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                return false;
            }
        }

        bool InstallLuaPCallDispatchHook() noexcept
        {
            if (g_luaPCallHook)
                return true;

            const auto address = mw2019_scanner::GetAddress("LuaShared_PCall");
            if (!address || !CodeLooksReady(address))
                return false;

            return InstallOne("LuaShared_PCall(frontend dispatcher)", address,
                reinterpret_cast<void*>(&LuaPCallDetour),
                reinterpret_cast<void**>(&g_luaPCallOriginal), g_luaPCallHook);
        }

        void InstallRenderSelectorHook() noexcept
        {
            if (!g_base) return;
            const auto& r = iw8_addresses::MW2019_1_44_Rvas;
            if (!CodeLooksReady(g_base + r.Dvar_FindVarByName))
                return;
            InstallOne("R_EndFrame(selector worker)", g_base + r.R_EndFrame,
                reinterpret_cast<void*>(&REndFrameDetour), reinterpret_cast<void**>(&g_rEndFrameOriginal), g_rEndFrameHook);
            if (g_rEndFrameHook && !g_renderSelectorFaulted.load(std::memory_order_acquire))
                g_renderSelectorEnabled.store(true, std::memory_order_release);
        }

        void InstallLateExactHooks() noexcept
        {
            InstallSignInHooks();
            InstallContentHook();
            InstallLuiHooks();
        }

        bool SetExchangeGood144(std::uintptr_t signatureAddress, bool verbose = false) noexcept
        {
            if (!signatureAddress) return false;
            __try
            {
                std::uintptr_t arrayBase = g_exchangeArrayBase.load(std::memory_order_acquire);
                unsigned depth = g_exchangeArrayDepth.load(std::memory_order_acquire);

                if (!arrayBase)
                {
                    int probedValue = 0;
                    unsigned cluster = 0;
                    if (!ResolveExchangeArrayFromLea(signatureAddress, arrayBase, &probedValue,
                        nullptr, &cluster, &depth))
                        return false;
                    g_exchangeArrayBase.store(arrayBase, std::memory_order_release);
                    g_exchangeArrayDepth.store(depth, std::memory_order_release);
                }

                auto* states = reinterpret_cast<volatile SignInExchangeState*>(arrayBase);
                const int index = iw8_addresses::MW2019_1_44_Signatures.SignInExchangeControllerOffset;
                const auto slotAddress = arrayBase +
                    static_cast<std::uintptr_t>(index) * sizeof(SignInExchangeState);
                if (!IsWritableAddress(slotAddress))
                    return false;

                const auto before = states[index];
                states[index] = SignInExchangeState::GOOD;
                const auto after = states[index];
                if (after != SignInExchangeState::GOOD)
                    return false;

                g_exchangeStateReady.store(true, std::memory_order_release);
                const unsigned writes = g_exchangeWrites.fetch_add(1, std::memory_order_acq_rel) + 1;
                if (verbose || writes == 1 || before != SignInExchangeState::GOOD)
                {
                    mw2019_diag::Log(
                        "[FENCE144] exchange state array=%p depth=%u index=%d before=%d after=%d writes=%u\r\n",
                        reinterpret_cast<void*>(arrayBase), depth, index,
                        static_cast<int>(before), static_cast<int>(after), writes);
                }
                return true;
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                if (verbose)
                    mw2019_diag::Log("[FENCE144] exchange-state write fault code=0x%08X\r\n",
                        static_cast<unsigned>(GetExceptionCode()));
                return false;
            }
        }

        bool MenuFenceBundleReady() noexcept
        {
            return g_patchHook && g_onlineHook && g_syncHook && g_bnetFenceHook &&
                g_exchangeStateReady.load(std::memory_order_acquire);
        }

        void ResolveAndInstallMenuFenceBundle(bool verbose) noexcept
        {
            if (!g_module || !g_base) return;

            if (!g_menuFenceResolveStarted.exchange(true, std::memory_order_acq_rel) && verbose)
            {
                mw2019_diag::Log(
                    "[FENCE144] resolving supplied 1.44 main-menu fence bundle (patch/online/sync/bnet/exchange)\r\n");
                mw2019_diag::Log(
                    "[FENCE144] exchange resolver v4: +1642/0x19A8 indexing resolver enabled; LEA/CVTT is fallback only\r\n");
            }

            // Two core fence functions have exact validated RVAs and are already
            // installed by InstallFastExactHooks. Resolve only the three supplied
            // 1.44 pattern targets that do not yet have validated static RVAs.
            if (!g_detection.Live_PatchGetState)
                g_detection.Live_PatchGetState = FindPattern(
                    g_module, iw8_addresses::MW2019_1_44_Signatures.Live_PatchGetState);
            if (!g_detection.GetBattleNetFenceState)
                g_detection.GetBattleNetFenceState = FindPattern(
                    g_module, iw8_addresses::MW2019_1_44_Signatures.GetBattleNetFenceState);
            if (!g_detection.SignInExchangeStateRef)
                g_detection.SignInExchangeStateRef = ResolveExchangeStateRef(verbose);

            if (g_detection.Live_PatchGetState)
                InstallOne("Live_PatchGetState(menu fence)", g_detection.Live_PatchGetState,
                    reinterpret_cast<void*>(&PatchFenceDetour),
                    reinterpret_cast<void**>(&g_patchFenceOriginal), g_patchHook);

            if (g_detection.GetBattleNetFenceState)
                InstallOne("GetBattleNetFenceState(menu fence)", g_detection.GetBattleNetFenceState,
                    reinterpret_cast<void*>(&BattleNetFenceDetour),
                    reinterpret_cast<void**>(&g_bnetFenceOriginal), g_bnetFenceHook);

            if (g_detection.SignInExchangeStateRef)
                (void)SetExchangeGood144(g_detection.SignInExchangeStateRef, verbose);

            const bool ready = MenuFenceBundleReady();
            g_menuFenceBundleReady.store(ready, std::memory_order_release);

            if (verbose || ready)
            {
                if (verbose && !g_detection.SignInExchangeStateRef)
                    mw2019_diag::Log("[FENCE144] missing piece: SignInExchangeState reference unresolved; +1642 GOOD write has NOT happened yet\r\n");
                mw2019_diag::Log(
                    "[FENCE144] bundle patch=%s online=%s sync=%s bnet=%s exchange=%s ready=%s\r\n",
                    g_patchHook ? "yes" : "no",
                    g_onlineHook ? "yes" : "no",
                    g_syncHook ? "yes" : "no",
                    g_bnetFenceHook ? "yes" : "no",
                    g_exchangeStateReady.load(std::memory_order_acquire) ? "GOOD" : "wait",
                    ready ? "YES" : "NO");
            }
        }

        void ResolveOptionalPatternTargets() noexcept
        {
            if (g_optionalResolved.exchange(true) || !g_module) return;
            mw2019_diag::Log("[SCAN] resolving optional 1.44 patch/time candidates after protected startup\r\n");

            if (!g_detection.Live_PatchGetState)
                g_detection.Live_PatchGetState = FindPattern(g_module, iw8_addresses::MW2019_1_44_Signatures.Live_PatchGetState);
            if (!g_detection.GetBattleNetFenceState)
                g_detection.GetBattleNetFenceState = FindPattern(g_module, iw8_addresses::MW2019_1_44_Signatures.GetBattleNetFenceState);
            if (!g_detection.SignInExchangeStateRef)
                g_detection.SignInExchangeStateRef = ResolveExchangeStateRef(false);
            if (!g_detection.LiveStorage_GetUTC)
                g_detection.LiveStorage_GetUTC = FindPattern(g_module, iw8_addresses::MW2019_1_44_Signatures.LiveStorage_GetUTC);

            if (g_detection.Live_PatchGetState)
                InstallOne("Live_PatchGetState", g_detection.Live_PatchGetState,
                    reinterpret_cast<void*>(&PatchFenceDetour), reinterpret_cast<void**>(&g_patchFenceOriginal), g_patchHook);
            if (g_detection.GetBattleNetFenceState)
                InstallOne("GetBattleNetFenceState", g_detection.GetBattleNetFenceState,
                    reinterpret_cast<void*>(&BattleNetFenceDetour), reinterpret_cast<void**>(&g_bnetFenceOriginal), g_bnetFenceHook);
            if (g_detection.LiveStorage_GetUTC)
                InstallOne("LiveStorage_GetUTC", g_detection.LiveStorage_GetUTC,
                    reinterpret_cast<void*>(&GetUtcDetour), reinterpret_cast<void**>(&g_getUtcOriginal), g_utcHook);
            if (g_detection.SignInExchangeStateRef)
                SetExchangeGood144(g_detection.SignInExchangeStateRef);

            PrintOffsets();
        }

        void WriteReport() noexcept
        {
            wchar_t path[32768]{};
            if (!mw2019_diag::BuildOutputPath(L"iw8_144_profile.log", path, sizeof(path) / sizeof(path[0]))) return;
            FILE* f = nullptr;
            if (_wfopen_s(&f, path, L"wb") != 0 || !f) return;
            std::fprintf(f, "profile=MW2019 1.44 server-emulation/login\nbase=0x%llX\ninstalled_client_state_hooks=%u\n",
                static_cast<unsigned long long>(g_base), g_installedHooks);
            const auto& r = iw8_addresses::MW2019_1_44_Rvas;

            if (kServerEmulationMode)
            {
                const struct { const char* name; std::uintptr_t rva; } authRows[] = {
                    {"CL_GetLocalClientSignInState", r.CL_GetLocalClientSignInState},
                    {"dwGetLogOnStatus", r.dwGetLogOnStatus},
                    {"Live_IsUserSignedInToDemonware", r.Live_IsUserSignedInToDemonware},
                    {"unk_IsUserSignedInToBNet", r.unk_IsUserSignedInToBNet}
                };
                for (const auto& row : authRows)
                    std::fprintf(f, "%s=0x%llX rva=0x%llX\n", row.name,
                        static_cast<unsigned long long>(g_base + row.rva),
                        static_cast<unsigned long long>(row.rva));
                std::fclose(f);
                return;
            }

            const struct { const char* name; std::uintptr_t rva; } rows[] = {
                {"Dvar_RegisterBool", r.Dvar_RegisterBool}, {"Dvar_RegisterString", r.Dvar_RegisterString},
                {"Dvar_FindVarByName", r.Dvar_FindVarByName}, {"Cmd_Exec_Internal", r.Cmd_Exec_Internal},
                {"CL_GetLocalClientSignInState", r.CL_GetLocalClientSignInState}, {"dwGetLogOnStatus", r.dwGetLogOnStatus},
                {"Live_IsUserSignedInToDemonware", r.Live_IsUserSignedInToDemonware}, {"unk_IsUserSignedInToBNet", r.unk_IsUserSignedInToBNet},
                {"Content_DoWeHaveContentPack", r.Content_DoWeHaveContentPack}, {"Live_OnlineServicesFence_GetState", r.Live_OnlineServicesFence_GetState},
                {"Live_SyncOnlineDataFence_GetState", r.Live_SyncOnlineDataFence_GetState},
                {"LUI_CoD_LuaCall_IsBattleNetAuthReady", r.LUI_CoD_LuaCall_IsBattleNetAuthReady},
                {"LUI_CoD_LuaCall_IsConnectedToGameServer", r.LUI_CoD_LuaCall_IsConnectedToGameServer},
                {"LUI_CoD_LuaCall_ShouldBeInOnlineArea", r.LUI_CoD_LuaCall_ShouldBeInOnlineArea},
                {"LUI_CoD_LuaCall_OfflineDataFetched", r.LUI_CoD_LuaCall_OfflineDataFetched},
                {"OnlineErrorManager_GetFenceState", r.OnlineErrorManager_GetFenceState},
                {"OnlineErrorManager_IsMpNotAllowed", r.OnlineErrorManager_IsMpNotAllowed},
                {"s_OnlineServicesFenceData_state", r.s_OnlineServicesFenceData_state},
                {"lua_pushboolean", r.lua_pushboolean}, {"LUI_OpenMenu", r.LUI_OpenMenu}, {"R_EndFrame", r.R_EndFrame}
            };
            for (const auto& row : rows)
                std::fprintf(f, "%s=0x%llX rva=0x%llX\n", row.name,
                    static_cast<unsigned long long>(g_base + row.rva), static_cast<unsigned long long>(row.rva));
            std::fclose(f);
        }
    }

    bool IsPureServerEmulationMode() noexcept
    {
        return kServerEmulationMode;
    }

    bool IsExactBuild(HMODULE module) noexcept
    {
        if (!module) return false;
        const auto base = reinterpret_cast<std::uintptr_t>(module);
        __try
        {
            const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
            if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew <= 0) return false;
            const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(base + static_cast<std::uintptr_t>(dos->e_lfanew));
            const auto& fingerprint = iw8_addresses::MW2019_1_44;
            const bool entryPointMatches =
                fingerprint.entryPointRva == 0 ||
                nt->OptionalHeader.AddressOfEntryPoint == fingerprint.entryPointRva;

            return nt->Signature == IMAGE_NT_SIGNATURE &&
                nt->FileHeader.TimeDateStamp == fingerprint.timestamp &&
                nt->OptionalHeader.SizeOfImage == fingerprint.imageSize &&
                entryPointMatches;
        }
        __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
    }

    bool Detect(HMODULE module, Detection& result)
    {
        result = {};
        if (!IsExactBuild(module)) return false;
        const auto base = reinterpret_cast<std::uintptr_t>(module);
        const auto& r = iw8_addresses::MW2019_1_44_Rvas;
        result.Live_OnlineServicesFence_GetState = base + r.Live_OnlineServicesFence_GetState;
        result.Live_SyncOnlineDataFence_GetState = base + r.Live_SyncOnlineDataFence_GetState;
        result.matchedSignatures =
            (CodeLooksReady(result.Live_OnlineServicesFence_GetState) ? 1u : 0u) +
            (CodeLooksReady(result.Live_SyncOnlineDataFence_GetState) ? 1u : 0u);
        result.matched = true; // Exact PE fingerprint is the activation gate.
        return true;
    }

    bool Initialize(HMODULE module, std::string& message)
    {
        if (!IsExactBuild(module))
        {
            message = "1.44 exact executable fingerprint not matched";
            return false;
        }

        g_module = module;
        g_base = reinterpret_cast<std::uintptr_t>(module);
        Detect(module, g_detection);
        SeedScannerAddresses();

        if (kServerEmulationMode)
        {
            // Pure server-emulation baseline.  The client is never told that
            // sign-in/fences/content/LUI succeeded.  This profile only seeds
            // read-only addresses; MW2019 must advance its own stock state from
            // replies produced by the Revamped server.
            mw2019_diag::Log("[SERVER-EMU144] PURE EMULATION mode active: client truth/state patches are disabled\r\n");
            mw2019_diag::Log("[SERVER-EMU144] exact 1.44 RVAs are seeded read-only for scanners/correlation only\r\n");
            WriteReport();
            g_initialized.store(true);
            message = "1.44 pure server-emulation research profile active";
            return true;
        }

        // Legacy patch-driven path retained for manual comparison/recovery.
        mw2019_diag::Log("[EARLY144] arming exact sign-in/status + core fence hooks before protected settle\r\n");
        InstallSignInHooks();
        InstallFastExactHooks();
        mw2019_diag::Log(
            "[EARLY144] immediate hooks signin=%s dw=%s demonware=%s bnetSignin=%s onlineFence=%s syncFence=%s hooks=%u\r\n",
            g_signInHook ? "yes" : "wait",
            g_dwHook ? "yes" : "wait",
            g_demonwareHook ? "yes" : "wait",
            g_bnetSignedHook ? "yes" : "wait",
            g_onlineHook ? "yes" : "wait",
            g_syncHook ? "yes" : "wait",
            g_installedHooks);

        mw2019_diag::Log("[EARLY144] exact hooks are live as early as possible; settling 3.5s only before pattern/exchange research\r\n");
        Sleep(3500);
        InstallSignInHooks();
        InstallFastExactHooks();
        ResolveAndInstallMenuFenceBundle(true);

        WriteReport();
        g_initialized.store(true);
        message = "1.44 legacy patch-driven profile active";
        return true;
    }

    void Tick(unsigned long long uptimeMs) noexcept
    {
        if (!g_initialized.load() || !g_base) return;

        if (kServerEmulationMode)
        {
            // Pure emulation stays observation-only for the entire run.  Keep
            // scanner seeds fresh as protected pages settle, but never install
            // sign-in/fence/content/LUI/menu/dvar truth hooks here.
            if (uptimeMs - g_lastInstallRetry >= 1000)
            {
                g_lastInstallRetry = uptimeMs;
                SeedScannerAddresses();
            }
            return;
        }

        if (uptimeMs - g_lastInstallRetry >= 1000)
        {
            g_lastInstallRetry = uptimeMs;
            SeedScannerAddresses();
            InstallFastExactHooks();
            // Keep retrying the exact 1.44 sign-in/status group until all four
            // protected targets are hookable. InstallOne is idempotent once armed.
            if (kFenceOnlyAutoProfile)
                InstallSignInHooks();
        }

        // Fence-first 1.44 path. Retry only the three pattern-derived targets
        // until the complete supplied fence bundle is armed. Once the exchange
        // location is known, keep it at GOOD while the stock frontend performs
        // its startup transitions; the game may rewrite this byte during login.
        if (kFenceOnlyAutoProfile)
        {
            const unsigned long long fenceRetryMs = uptimeMs < 15000 ? 700ull : 1500ull;
            if (!MenuFenceBundleReady() && uptimeMs - g_lastFenceResolve >= fenceRetryMs)
            {
                g_lastFenceResolve = uptimeMs;
                ResolveAndInstallMenuFenceBundle(false);
            }

            if (g_detection.SignInExchangeStateRef && uptimeMs - g_lastExchangeWrite >= 500)
            {
                g_lastExchangeWrite = uptimeMs;
                (void)SetExchangeGood144(g_detection.SignInExchangeStateRef, false);
            }

            // v8 ordering matters: queue MainMenuOffline BEFORE arming the three
            // LUI predicate hooks.  In v7 those hooks were installed first and the
            // game evaluated them immediately; by the time the menu was queued no
            // later callback arrived to consume it.  With the request pending first,
            // the next real game-owned LUI predicate callback can service the menu.
            if (uptimeMs >= 4000 && LuaFrontendReadyForSelectors())
            {
                InstallContentHook();

                if (g_contentHook && !g_autoOfflineMenuQueued.load(std::memory_order_acquire))
                {
                    const unsigned captured = ApplyCapturedFrontendSelectors(true);
                    mw2019_diag::Log(
                        "[OFFLINE144] frontend Lua live; content armed; cached offline dvars=%u/%u\r\n",
                        captured, static_cast<unsigned>(kFrontendOverrideCount));
                    if (QueueFrontendMenu("MainMenuOffline"))
                    {
                        g_autoOfflineMenuQueued.store(true, std::memory_order_release);
                        mw2019_diag::Log("[OFFLINE144] MainMenuOffline queued BEFORE LUI gate hooks\r\n");
                    }
                    else
                    {
                        mw2019_diag::Log("[OFFLINE144] MainMenuOffline queue not ready; will retry\r\n");
                    }
                }

                InstallLuiHooks();
                if (g_luiAuthHook && g_luiConnectedHook && g_luiOnlineAreaHook &&
                    !g_luiGateReadyLogged.exchange(true, std::memory_order_acq_rel))
                {
                    mw2019_diag::Log(
                        "[OFFLINE144] LUI gates armed after menu queue; waiting for a game-owned callback to consume MainMenuOffline\r\n");
                }
            }

            if (MenuFenceBundleReady() && !g_fenceOnlyReadyLogged)
            {
                g_fenceOnlyReadyLogged = true;
                const unsigned captured = ApplyCapturedFrontendSelectors(false);
                mw2019_diag::Log(
                    "[FENCE144] MAIN-MENU fence bundle READY; cached dvars=%u/%u. "
                    "Exact sign-in/status hooks are active; content/LUI are staged only after frontend Lua becomes live.\r\n",
                    captured, static_cast<unsigned>(kFrontendOverrideCount));
                mw2019_diag::Log(
                    "[FENCE144] manual fallbacks remain: content144 | lui144 | patch144 | hooks144 | blades | menu offline\r\n");
            }
        }

        // The old aggressive staged path is retained for manual/research builds,
        // but disabled in the fence-first profile because the supplied 1.44 code
        // explicitly reaches the main menu with the fence layer alone.
        if (!kFenceOnlyAutoProfile)
        {
        // The three startup-safe hooks are installed first.  Then automatically
        // stage the remaining frontend gates instead of requiring console input.
        // Each stage retries until every hook in that group is actually armed,
        // so a temporarily protected/not-yet-unpacked target does not get skipped.
        if (!g_autoSignInStage && uptimeMs >= 500)
        {
            if (!g_autoSignInStarted)
            {
                g_autoSignInStarted = true;
                mw2019_diag::Log("[AUTO] stage 1/5: arming sign-in/status hooks\r\n");
            }
            InstallSignInHooks();
            if (g_signInHook && g_dwHook && g_demonwareHook && g_bnetSignedHook)
            {
                g_autoSignInStage = true;
                WriteReport();
                mw2019_diag::Log("[AUTO] stage 1/5 complete; hooks=%u\r\n", g_installedHooks);
            }
        }

        if (g_autoSignInStage && !g_autoContentStage && uptimeMs >= 1000)
        {
            if (!g_autoContentStarted)
            {
                g_autoContentStarted = true;
                mw2019_diag::Log("[AUTO] stage 2/5: arming local content ownership hook\r\n");
            }
            InstallContentHook();
            if (g_contentHook)
            {
                g_autoContentStage = true;
                WriteReport();
                mw2019_diag::Log("[AUTO] stage 2/5 complete; hooks=%u\r\n", g_installedHooks);
            }
        }

        if (g_autoContentStage && !g_autoLuiStage && uptimeMs >= 1500)
        {
            if (!g_autoLuiStarted)
            {
                g_autoLuiStarted = true;
                mw2019_diag::Log("[AUTO] stage 3/5: arming LUI frontend gate hooks\r\n");
            }
            InstallLuiHooks();
            if (g_luiAuthHook && g_luiConnectedHook && g_luiOnlineAreaHook)
            {
                g_autoLuiStage = true;
                WriteReport();
                mw2019_diag::Log("[AUTO] stage 3/5 complete; hooks=%u; OfflineDataFetched deferred (protected target stalls hook install)\r\n", g_installedHooks);
            }
        }

        // Crash-safe stage 4:
        // - helper-thread Dvar_FindVarByName calls have already faulted on this build;
        // - R_EndFrame dispatch also led back into that protected lookup path;
        // - the latest LuaShared_PCall inline detour intermittently terminates the
        //   process immediately after hook installation.
        //
        // Keep LuaShared_PCall scanner-visible for research, but DO NOT patch it.
        // Only apply dvar pointers that were captured by the already-proven
        // Dvar_RegisterBool hook. This keeps the stable 11-hook profile intact.
        if (g_autoLuiStage && uptimeMs >= 4000 && !LuaFrontendReadyForSelectors())
        {
            if (!g_autoLuaWaitLogged)
            {
                g_autoLuaWaitLogged = true;
                mw2019_diag::Log("[AUTO] stage 4/5 waiting for late Lua scan + live frontend VM; protected lookup/dispatcher hooks remain disabled\r\n");
            }
        }

        if (g_autoLuiStage && uptimeMs >= 4000 && LuaFrontendReadyForSelectors() && !g_autoRenderSelectorStarted)
        {
            g_autoRenderSelectorStarted = true;
            g_renderSelectorEnabled.store(false, std::memory_order_release);
            g_luiSelectorArmed.store(false, std::memory_order_release);

            const unsigned matched = ApplyCapturedFrontendSelectors(false);
            g_renderSelectorMatched.store(matched, std::memory_order_release);
            g_renderSelectorCompletedPass.store(1, std::memory_order_release);
            g_selectorPasses = 1;
            g_lastReportedRenderSelectorPass = 1;

            mw2019_diag::Log("[AUTO] stage 4/5 crash-safe cached selector pass matched=%u/%u; LuaShared_PCall/R_EndFrame/Dvar_FindVarByName dispatch disabled\r\n",
                matched, static_cast<unsigned>(kFrontendOverrideCount));
        }

        // The base 1.44 compatibility path has already installed its validated
        // patch/time fence set before this research profile starts.  Do not run a
        // second protected-image pattern scan automatically: a previous manual
        // patch144 test also stopped inside that scan.  Keep patch144 manual.
        if (g_autoLuiStage && g_autoRenderSelectorStarted && !g_autoPatchStage && uptimeMs >= 10000)
        {
            if (!g_autoPatchStarted)
            {
                g_autoPatchStarted = true;
                mw2019_diag::Log("[AUTO] stage 5/5: using validated base 1.44 patch/time hooks; duplicate protected scan deferred to patch144\r\n");
            }
            g_autoPatchStage = true;
            WriteReport();
            mw2019_diag::Log("[AUTO] stage 5/5 complete; hooks=%u\r\n", g_installedHooks);
        }

        if (!g_autoReadyLogged && g_autoSignInStage && g_autoContentStage && g_autoLuiStage &&
            g_autoPatchStage && g_autoRenderSelectorStarted)
        {
            g_autoReadyLogged = true;
            mw2019_diag::Log("[AUTO] 1.44 offline/frontend auto-stage sequence is active; manual commands remain available for testing\r\n");
        }
        } // !kFenceOnlyAutoProfile
    }

    void RequestFrontendSelectorPass() noexcept
    {
        if (kServerEmulationMode)
        {
            mw2019_diag::Log("[SERVER-EMU144] blocked: frontend dvar selector writes are disabled in PURE EMULATION mode\r\n");
            return;
        }
        if (!g_initialized.load() || !g_base)
        {
            mw2019_diag::Log("[DVAR] 1.44 profile is not initialized yet\r\n");
            return;
        }

        // Cached-only mode does not require the Lua VM.  It touches only pointers
        // captured by Dvar_RegisterBool and never calls back into a protected API.
        // Re-apply only dvars captured by Dvar_RegisterBool. This performs no
        // protected Dvar_FindVarByName call and installs no extra dispatcher hook.
        const unsigned matched = ApplyCapturedFrontendSelectors(true);
        g_renderSelectorMatched.store(matched, std::memory_order_release);
        g_renderSelectorCompletedPass.fetch_add(1, std::memory_order_acq_rel);
        ++g_selectorPasses;
        mw2019_diag::Log("[DVAR] crash-safe cached pass complete matched=%u/%u; no protected lookup or dispatcher hook used\r\n",
            matched, static_cast<unsigned>(kFrontendOverrideCount));
    }

    bool QueueFrontendMenu(const char* menuName) noexcept
    {
        if (kServerEmulationMode)
        {
            mw2019_diag::Log("[SERVER-EMU144] blocked: forced LUI menu routing is disabled in PURE EMULATION mode\r\n");
            return false;
        }
        if (!g_initialized.load() || !g_base || !menuName || !*menuName)
            return false;
        if (!LuaFrontendReadyForSelectors())
        {
            mw2019_diag::Log("[MENU144] '%s' not queued: frontend Lua VM is not live yet\r\n", menuName);
            return false;
        }
        // Queue only.  The request is consumed from LuaTrueDetour on the next
        // game-owned frontend LUI callback.  This avoids the old LuaShared_PCall
        // hook entirely while keeping LUI_OpenMenu off the helper/console thread.
        strncpy_s(g_luiMenuName, menuName, _TRUNCATE);
        g_luiMenuPending.store(true, std::memory_order_release);
        mw2019_diag::Log("[MENU144] pending for next validated LUI callback -> %s\r\n", menuName);
        return true;
    }

    void EnableSignInHooks() noexcept
    {
        if (kServerEmulationMode)
        {
            mw2019_diag::Log("[SERVER-EMU144] blocked: sign-in truth hooks are disabled in PURE EMULATION mode\r\n");
            return;
        }
        if (!g_initialized.load() || !g_base)
        {
            mw2019_diag::Log("[HOOK] 1.44 profile is not initialized yet\r\n");
            return;
        }
        mw2019_diag::Log("[HOOK] arming 1.44 sign-in group only\r\n");
        InstallSignInHooks();
        mw2019_diag::Log("[HOOK] sign-in group complete; hooks=%u\r\n", g_installedHooks);
    }

    void EnableContentHook() noexcept
    {
        if (kServerEmulationMode)
        {
            mw2019_diag::Log("[SERVER-EMU144] blocked: content ownership hooks are disabled in PURE EMULATION mode\r\n");
            return;
        }
        if (!g_initialized.load() || !g_base)
        {
            mw2019_diag::Log("[HOOK] 1.44 profile is not initialized yet\r\n");
            return;
        }
        mw2019_diag::Log("[HOOK] arming 1.44 content ownership hook only\r\n");
        InstallContentHook();
        mw2019_diag::Log("[HOOK] content group complete; hooks=%u\r\n", g_installedHooks);
    }

    void EnableLuiHooks() noexcept
    {
        if (kServerEmulationMode)
        {
            mw2019_diag::Log("[SERVER-EMU144] blocked: LUI truth hooks are disabled in PURE EMULATION mode\r\n");
            return;
        }
        if (!g_initialized.load() || !g_base)
        {
            mw2019_diag::Log("[HOOK] 1.44 profile is not initialized yet\r\n");
            return;
        }
        mw2019_diag::Log("[HOOK] arming 1.44 LUI frontend gate group only\r\n");
        InstallLuiHooks();
        mw2019_diag::Log("[HOOK] LUI group complete; hooks=%u\r\n", g_installedHooks);
    }

    void EnablePatchHooks() noexcept
    {
        if (kServerEmulationMode)
        {
            mw2019_diag::Log("[SERVER-EMU144] blocked: patch/time truth hooks are disabled in PURE EMULATION mode\r\n");
            return;
        }
        if (!g_initialized.load() || !g_base)
        {
            mw2019_diag::Log("[HOOK] 1.44 profile is not initialized yet\r\n");
            return;
        }
        mw2019_diag::Log("[HOOK] resolving/arming optional 1.44 patch/time group only\r\n");
        ResolveOptionalPatternTargets();
        mw2019_diag::Log("[HOOK] patch/time group complete; hooks=%u\r\n", g_installedHooks);
    }

    void EnableLateOfflineHooks() noexcept
    {
        if (kServerEmulationMode)
        {
            mw2019_diag::Log("[SERVER-EMU144] blocked: offline hook bundle is disabled in PURE EMULATION mode\r\n");
            return;
        }
        if (!g_initialized.load() || !g_base)
        {
            mw2019_diag::Log("[HOOK] 1.44 profile is not initialized yet\r\n");
            return;
        }

        mw2019_diag::Log("[HOOK] manually arming ALL late 1.44 groups\r\n");
        InstallLateExactHooks();
        ResolveOptionalPatternTargets();
        mw2019_diag::Log("[HOOK] manual 1.44 all-hook pass complete; hooks=%u\r\n", g_installedHooks);
    }

    void PrintOffsets() noexcept
    {
        if (!g_base) return;
        const auto& r = iw8_addresses::MW2019_1_44_Rvas;

        if (kServerEmulationMode)
        {
            const struct { const char* name; std::uintptr_t rva; } authRows[] = {
                {"CL_GetLocalClientSignInState", r.CL_GetLocalClientSignInState},
                {"dwGetLogOnStatus", r.dwGetLogOnStatus},
                {"Live_IsUserSignedInToDemonware", r.Live_IsUserSignedInToDemonware},
                {"unk_IsUserSignedInToBNet", r.unk_IsUserSignedInToBNet}
            };
            mw2019_diag::Log("[AUTH-OFFSET] stock login correlation points (read-only)\r\n");
            for (const auto& row : authRows)
                mw2019_diag::Log("[AUTH-OFFSET] %-34s = %p rva=0x%llX %s\r\n",
                    row.name,
                    reinterpret_cast<void*>(g_base + row.rva),
                    static_cast<unsigned long long>(row.rva),
                    CodeLooksReady(g_base + row.rva) ? "READY" : "WAIT");
            return;
        }

        const struct { const char* name; std::uintptr_t rva; } rows[] = {
            {"Dvar_RegisterBool", r.Dvar_RegisterBool}, {"Dvar_RegisterString", r.Dvar_RegisterString},
            {"Dvar_FindVarByName", r.Dvar_FindVarByName}, {"Cmd_Exec_Internal", r.Cmd_Exec_Internal},
            {"CL_GetLocalClientSignInState", r.CL_GetLocalClientSignInState}, {"dwGetLogOnStatus", r.dwGetLogOnStatus},
            {"Live_IsUserSignedInToDemonware", r.Live_IsUserSignedInToDemonware}, {"unk_IsUserSignedInToBNet", r.unk_IsUserSignedInToBNet},
            {"Content_DoWeHaveContentPack", r.Content_DoWeHaveContentPack}, {"Live_OnlineServicesFence_GetState", r.Live_OnlineServicesFence_GetState},
            {"Live_SyncOnlineDataFence_GetState", r.Live_SyncOnlineDataFence_GetState},
            {"LUI_CoD_LuaCall_IsBattleNetAuthReady", r.LUI_CoD_LuaCall_IsBattleNetAuthReady},
            {"LUI_CoD_LuaCall_IsConnectedToGameServer", r.LUI_CoD_LuaCall_IsConnectedToGameServer},
            {"LUI_CoD_LuaCall_ShouldBeInOnlineArea", r.LUI_CoD_LuaCall_ShouldBeInOnlineArea},
            {"LUI_CoD_LuaCall_OfflineDataFetched", r.LUI_CoD_LuaCall_OfflineDataFetched},
            {"OnlineErrorManager_GetFenceState", r.OnlineErrorManager_GetFenceState},
            {"OnlineErrorManager_IsMpNotAllowed", r.OnlineErrorManager_IsMpNotAllowed},
            {"s_OnlineServicesFenceData_state", r.s_OnlineServicesFenceData_state},
            {"lua_pushboolean", r.lua_pushboolean}, {"LUI_OpenMenu", r.LUI_OpenMenu}, {"R_EndFrame", r.R_EndFrame}
        };
        for (const auto& row : rows)
            mw2019_diag::Log("[OFFSET] %-42s = %p rva=0x%llX %s\r\n", row.name,
                reinterpret_cast<void*>(g_base + row.rva),
                static_cast<unsigned long long>(row.rva),
                (row.name[0] == 's' ? (IsWritableAddress(g_base + row.rva) ? "READY" : "WAIT") :
                    (CodeLooksReady(g_base + row.rva) ? "READY" : "WAIT")));

        if (g_detection.Live_PatchGetState)
            mw2019_diag::Log("[OFFSET] Live_PatchGetState(pattern)                 = %p rva=0x%llX\r\n",
                reinterpret_cast<void*>(g_detection.Live_PatchGetState),
                static_cast<unsigned long long>(g_detection.Live_PatchGetState - g_base));
        if (g_detection.GetBattleNetFenceState)
            mw2019_diag::Log("[OFFSET] GetBattleNetFenceState(pattern)             = %p rva=0x%llX\r\n",
                reinterpret_cast<void*>(g_detection.GetBattleNetFenceState),
                static_cast<unsigned long long>(g_detection.GetBattleNetFenceState - g_base));
        if (g_detection.LiveStorage_GetUTC)
            mw2019_diag::Log("[OFFSET] LiveStorage_GetUTC(pattern)                 = %p rva=0x%llX\r\n",
                reinterpret_cast<void*>(g_detection.LiveStorage_GetUTC),
                static_cast<unsigned long long>(g_detection.LiveStorage_GetUTC - g_base));
    }

    void PrintStatus() noexcept
    {
        if (kServerEmulationMode)
        {
            mw2019_diag::Log("[1.44] PURE EMULATION initialized=%s clientStateHooks=%u selectors=%u exactFingerprint=yes\r\n",
                g_initialized.load() ? "yes" : "no", g_installedHooks, g_selectorPasses);
            mw2019_diag::Log("[1.44] redirect/capture + login/auth scanners only; stock client login state is untouched\r\n");
            return;
        }

        mw2019_diag::Log("[1.44] profile initialized=%s hooks=%u selectors=%u exactFingerprint=yes\r\n",
            g_initialized.load() ? "yes" : "no", g_installedHooks, g_selectorPasses);
        mw2019_diag::Log("[1.44] crash-safe dispatch: PCallHook=%s REndFrameHook=%s selectorArmed=%s menuPending=%s cachedMatched=%u/%u\r\n",
            g_luaPCallHook ? "yes" : "no",
            g_rEndFrameHook ? "yes" : "no",
            g_luiSelectorArmed.load(std::memory_order_acquire) ? "yes" : "no",
            g_luiMenuPending.load(std::memory_order_acquire) ? "yes" : "no",
            g_renderSelectorMatched.load(std::memory_order_acquire),
            static_cast<unsigned>(kFrontendOverrideCount));
        mw2019_diag::Log(
            "[1.44] fence+signin auto profile: patch=%s online=%s sync=%s bnet=%s exchange=%s bundle=%s; "
            "signin=%s dw=%s demonware=%s bnetSignin=%s; content/LUI auto-stage after frontend Lua is live\r\n",
            g_patchHook ? "yes" : "no",
            g_onlineHook ? "yes" : "no",
            g_syncHook ? "yes" : "no",
            g_bnetFenceHook ? "yes" : "no",
            g_exchangeStateReady.load(std::memory_order_acquire) ? "GOOD" : "wait",
            MenuFenceBundleReady() ? "READY" : "retrying",
            g_signInHook ? "yes" : "no",
            g_dwHook ? "yes" : "no",
            g_demonwareHook ? "yes" : "no",
            g_bnetSignedHook ? "yes" : "no");
    }
}

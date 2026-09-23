#include "CamoPrototype1.h"

#include "../core/Main.hpp"

#include <Windows.h>
#include <array>
#include <atomic>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <mutex>
#include <sstream>
#include <unordered_set>
#include <unordered_map>
#include <string>
#include <vector>
#include <algorithm>

namespace camo_prototype1
{
    namespace
    {
        constexpr std::uintptr_t kDbRegisterRva = 0x0B2C90B0;
        constexpr unsigned int kWeaponCamoType = 0x2E;
        constexpr unsigned int kWeaponCamoBindingType = 0x2F;
        constexpr std::size_t kNativeRecordSize = 0x10;
        constexpr unsigned int kExpectedPoolEntrySize = 0x20;

        std::mutex g_mutex;
        std::array<unsigned char, kNativeRecordSize> g_template{};
        std::uintptr_t g_templateAddress = 0;
        std::uintptr_t g_captureRip = 0;
        std::atomic_bool g_haveTemplate{ false };
        std::atomic_bool g_attempted{ false };
        std::atomic_bool g_validatedNewEntry{ false };
        std::atomic_bool g_pending{ false };
        std::atomic_bool g_autoArmed{ false };
        std::atomic_bool g_havePreparedSource{ false };
        std::array<unsigned char, 0x80> g_preparedSource{};
        std::uintptr_t g_preparedSourceAddress = 0;
        std::atomic_bool g_deferredPostStock{ false };
        std::uintptr_t g_deferredStockResult = 0;
        std::uintptr_t g_deferredCallerRip = 0;
        std::unordered_set<std::uint64_t> g_reservedCustomIdentities;
        std::uint32_t g_nextCustomIdentitySequence = 1;
        std::atomic_uint g_batchDiscovered{ 0 };
        std::atomic_uint g_batchRegistered{ 0 };
        std::atomic_uint g_batchFailed{ 0 };

        struct RegisteredCustomCamo
        {
            std::string folder;
            std::uint64_t identity = 0;
            std::uintptr_t entry = 0;
            unsigned int poolIndex = 0;
            std::uintptr_t binding = 0;
            unsigned int bindingIndex = 0;
            std::uint64_t bindingIdentity = 0;
        };

        std::unordered_map<std::string, RegisteredCustomCamo> g_registeredCustomCamos;
        std::atomic_bool g_bindingsReady{ false };
        std::atomic_bool g_bindingWaitLogged{ false };
        std::atomic_uint g_bindingsRegistered{ 0 };
        std::atomic_uint g_bindingsFailed{ 0 };
        std::unordered_set<std::uint64_t> g_reservedBindingIdentities;

        std::uintptr_t g_lastResult = 0;
        int g_lastCountBefore = 0;
        int g_lastCountAfter = 0;

        void EnsureLogFolder()
        {
            CreateDirectoryA("logs", nullptr);
            CreateDirectoryA("logs\\camo", nullptr);
            CreateDirectoryA("logs\\camo\\prototype1", nullptr);
        }

        std::string Hex(std::uintptr_t value)
        {
            std::ostringstream out;
            out << "0x"
                << std::hex
                << std::uppercase
                << value;
            return out.str();
        }

        bool SafeRead(
            const void* address,
            void* output,
            std::size_t size)
        {
            if (!address || !output || !size)
                return false;

            SIZE_T got = 0;

            return
                ReadProcessMemory(
                    GetCurrentProcess(),
                    address,
                    output,
                    size,
                    &got) &&
                got == size;
        }

        bool IsExecutableAddress(
            std::uintptr_t address)
        {
            if (!address)
                return false;

            MEMORY_BASIC_INFORMATION mbi{};

            if (!VirtualQuery(
                    reinterpret_cast<const void*>(address),
                    &mbi,
                    sizeof(mbi)))
            {
                return false;
            }

            if (mbi.State != MEM_COMMIT ||
                (mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS)))
            {
                return false;
            }

            const DWORD p =
                mbi.Protect & 0xFFu;

            return
                p == PAGE_EXECUTE ||
                p == PAGE_EXECUTE_READ ||
                p == PAGE_EXECUTE_READWRITE ||
                p == PAGE_EXECUTE_WRITECOPY;
        }

        bool RecordIsWeaponCamo(
            const unsigned char* bytes)
        {
            if (!bytes)
                return false;

            // Runtime parent-loop capture proved the 16-byte record layout
            // uses the FIRST qword for the asset type. The second qword is
            // loader state/index and is commonly 0xFFFFFFFFFFFFFFFF before
            // the bridge processes the record.
            std::uint64_t typeValue = 0;

            std::memcpy(
                &typeValue,
                bytes,
                sizeof(typeValue));

            return
                typeValue ==
                static_cast<std::uint64_t>(
                    kWeaponCamoType);
        }

        bool PointerInsidePool(
            std::uintptr_t pointer,
            const XAssetPool& pool)
        {
            if (!pointer ||
                !pool.pool.unk ||
                pool.itemSize == 0 ||
                pool.itemCount <= 0)
            {
                return false;
            }

            const auto base =
                reinterpret_cast<std::uintptr_t>(
                    pool.pool.unk);

            const auto end =
                base +
                static_cast<std::uintptr_t>(
                    pool.itemSize) *
                static_cast<std::uintptr_t>(
                    pool.itemCount);

            return
                pointer >= base &&
                pointer < end &&
                ((pointer - base) % pool.itemSize) == 0;
        }

        // Keep SEH isolated from C++ objects that require unwinding.
        bool InvokeDbRegisterSafely(
            std::uintptr_t functionAddress,
            unsigned char assetType,
            void* preparedSource,
            std::uintptr_t* result,
            DWORD* exceptionCode)
        {
            if (result)
                *result = 0;

            if (exceptionCode)
                *exceptionCode = 0;

            using DbRegisterFn =
                void*(__fastcall*)(
                    unsigned char,
                    void*);

            __try
            {
                void* returned =
                    reinterpret_cast<DbRegisterFn>(
                        functionAddress)(
                            assetType,
                            preparedSource);

                if (result)
                {
                    *result =
                        reinterpret_cast<std::uintptr_t>(
                            returned);
                }

                return true;
            }
            __except (
                exceptionCode
                    ? (*exceptionCode =
                        GetExceptionCode(),
                       EXCEPTION_EXECUTE_HANDLER)
                    : EXCEPTION_EXECUTE_HANDLER)
            {
                return false;
            }
        }

        void AppendLog(
            const std::string& text)
        {
            EnsureLogFolder();

            std::ofstream log(
                "logs\\camo\\prototype1\\prototype1.log",
                std::ios::app);

            if (log)
                log << text << '\n';
        }

        std::string NormalizeName(std::string value)
        {
            std::transform(value.begin(), value.end(), value.begin(),
                [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
            return value;
        }

        bool FindBindingForCamo(std::uintptr_t camoEntry,
                                std::uintptr_t& bindingEntry,
                                unsigned int& bindingIndex,
                                unsigned int& ownerOffset);

        bool PoolContainsFirstQwordIdentity(
            const XAssetPool& pool,
            std::uint64_t identity)
        {
            if (!identity || !pool.pool.unk || pool.itemSize < 8 || pool.itemCount <= 0)
                return false;

            const auto base = reinterpret_cast<std::uintptr_t>(pool.pool.unk);
            for (int i = 0; i < pool.itemCount; ++i)
            {
                std::uint64_t v = 0;
                SIZE_T got = 0;
                const auto addr = base + static_cast<std::uintptr_t>(i) * pool.itemSize;
                if (ReadProcessMemory(GetCurrentProcess(), reinterpret_cast<const void*>(addr),
                                      &v, sizeof(v), &got) && got == sizeof(v) && v == identity)
                    return true;
            }
            return false;
        }

        std::uint64_t BindingIdentityForFolder(
            const std::string& folder,
            const XAssetPool& bindingPool)
        {
            // Caller serializes binding batch under g_mutex.
            // Deterministic base name with collision suffixes.
            for (unsigned int salt = 0; salt < 100000; ++salt)
            {
                std::ostringstream name;
                name << "t9_custom_camo_binding_" << NormalizeName(folder);
                if (salt) name << '_' << salt;
                const auto text = name.str();

                // Same FNV-1a style used by the custom WeaponCamo identities.
                std::uint64_t hash = 14695981039346656037ull;
                for (unsigned char c : text)
                {
                    hash ^= c;
                    hash *= 1099511628211ull;
                }

                if (!hash || hash == ~0ull)
                    continue;
                if (g_reservedBindingIdentities.count(hash))
                    continue;
                if (PoolContainsFirstQwordIdentity(bindingPool, hash))
                    continue;

                g_reservedBindingIdentities.insert(hash);
                return hash;
            }
            return 0;
        }

        bool RegisterBindingClone(
            RegisteredCustomCamo& custom,
            std::uintptr_t stockBinding,
            unsigned int stockOwnerOffset,
            std::string& reason)
        {
            if (!g_assetPool || !custom.entry || !stockBinding)
            {
                reason = "missing pool/custom/stock binding";
                return false;
            }

            XAssetPool& bindingPool = g_assetPool[ASSET_TYPE_WEAPONCAMOBINDING];
            if (!bindingPool.pool.unk || bindingPool.itemSize < 0x10 ||
                bindingPool.itemSize > 0x400 || bindingPool.itemAllocCount >= bindingPool.itemCount ||
                !bindingPool.freeHead)
            {
                reason = "binding pool not ready";
                return false;
            }

            if (stockOwnerOffset + sizeof(std::uintptr_t) > static_cast<unsigned int>(bindingPool.itemSize))
            {
                reason = "stock owner offset outside binding item";
                return false;
            }

            std::vector<unsigned char> clone(static_cast<std::size_t>(bindingPool.itemSize), 0);
            if (!SafeRead(reinterpret_cast<const void*>(stockBinding), clone.data(), clone.size()))
            {
                reason = "stock binding unreadable";
                return false;
            }

            const auto bindingIdentity = BindingIdentityForFolder(custom.folder, bindingPool);
            if (!bindingIdentity)
            {
                reason = "no unused binding identity";
                return false;
            }

            // Binding entries observed by the current client carry their DB identity
            // in the first qword, and one pointer-sized field references WeaponCamo.
            std::memcpy(clone.data(), &bindingIdentity, sizeof(bindingIdentity));
            std::memcpy(clone.data() + stockOwnerOffset, &custom.entry, sizeof(custom.entry));

            HMODULE module = GetModuleHandleW(nullptr);
            if (!module)
            {
                reason = "main module unavailable";
                return false;
            }

            const auto dbRegister = reinterpret_cast<std::uintptr_t>(module) + kDbRegisterRva;
            if (!IsExecutableAddress(dbRegister))
            {
                reason = "DB register unavailable";
                return false;
            }

            const int before = bindingPool.itemAllocCount;
            const auto freeBefore = reinterpret_cast<std::uintptr_t>(bindingPool.freeHead);
            std::uintptr_t result = 0;
            DWORD exceptionCode = 0;

            const bool invoked = InvokeDbRegisterSafely(
                dbRegister,
                static_cast<unsigned char>(kWeaponCamoBindingType),
                clone.data(),
                &result,
                &exceptionCode);

            const int after = bindingPool.itemAllocCount;
            const auto freeAfter = reinterpret_cast<std::uintptr_t>(bindingPool.freeHead);

            std::uintptr_t found = 0;
            unsigned int foundIndex = 0;
            unsigned int foundOffset = 0;
            const bool referencesCustom = FindBindingForCamo(custom.entry, found, foundIndex, foundOffset);

            std::ostringstream log;
            log << "[CUSTOM_BINDING] folder=\"" << custom.folder << "\""
                << " camo=" << Hex(custom.entry)
                << " stockBinding=" << Hex(stockBinding)
                << " ownerOffset=0x" << std::hex << stockOwnerOffset
                << " identity=0x" << bindingIdentity << std::dec
                << " invoked=" << (invoked?1:0)
                << " exception=0x" << std::hex << exceptionCode << std::dec
                << " count=" << before << "->" << after
                << " free=" << Hex(freeBefore) << "->" << Hex(freeAfter)
                << " result=" << Hex(result)
                << " referencesCustom=" << (referencesCustom?1:0)
                << " found=" << Hex(found)
                << " foundIndex=" << foundIndex;
            AppendLog(log.str());

            if (!invoked || exceptionCode || !referencesCustom)
            {
                reason = "native binding registration did not validate";
                return false;
            }

            custom.binding = found;
            custom.bindingIndex = foundIndex;
            custom.bindingIdentity = bindingIdentity;
            return true;
        }

        void EnsureBindingsForRegisteredCamos()
        {
            if (g_bindingsReady.load() || !g_assetPool || g_batchRegistered.load() == 0)
                return;

            // Use the original stock WeaponCamo result captured before the custom
            // batch as the source for a legitimate stock binding template.
            std::uintptr_t stockBinding = 0;
            unsigned int stockBindingIndex = 0;
            unsigned int ownerOffset = 0;
            if (!FindBindingForCamo(g_deferredStockResult, stockBinding, stockBindingIndex, ownerOffset))
            {
                if (!g_bindingWaitLogged.exchange(true))
                {
                    const auto& bindingPool = g_assetPool[ASSET_TYPE_WEAPONCAMOBINDING];
                    std::ostringstream wait;
                    wait << "[CUSTOM_BINDING_WAIT] stockCamo=" << Hex(g_deferredStockResult)
                         << " bindingAllocated=" << bindingPool.itemAllocCount
                         << " bindingCapacity=" << bindingPool.itemCount
                         << " itemSize=" << bindingPool.itemSize;
                    AppendLog(wait.str());
                }
                return; // stock binding pool can become ready slightly later
            }

            g_bindingWaitLogged.store(false);
            {
                std::ostringstream ready;
                ready << "[CUSTOM_BINDING_TEMPLATE] stockCamo=" << Hex(g_deferredStockResult)
                      << " stockBinding=" << Hex(stockBinding)
                      << " stockBindingIndex=" << stockBindingIndex
                      << " ownerOffset=0x" << std::hex << ownerOffset << std::dec;
                AppendLog(ready.str());
            }

            unsigned int ok = 0;
            unsigned int failed = 0;

            std::lock_guard<std::mutex> lock(g_mutex);
            for (auto& kv : g_registeredCustomCamos)
            {
                auto& custom = kv.second;
                if (custom.binding)
                {
                    ++ok;
                    continue;
                }

                std::string reason;
                if (RegisterBindingClone(custom, stockBinding, ownerOffset, reason))
                    ++ok;
                else
                {
                    ++failed;
                    AppendLog("[CUSTOM_BINDING_FAILED] folder=\"" + custom.folder + "\" reason=" + reason);
                }
            }

            g_bindingsRegistered.store(ok);
            g_bindingsFailed.store(failed);
            if (ok == g_registeredCustomCamos.size())
            {
                g_bindingsReady.store(true);
                std::ostringstream done;
                done << "[CUSTOM_BINDING_BATCH_END] registered=" << ok
                     << " failed=" << failed;
                AppendLog(done.str());
            }
        }

        bool FindBindingForCamo(std::uintptr_t camoEntry,
                                std::uintptr_t& bindingEntry,
                                unsigned int& bindingIndex,
                                unsigned int& ownerOffset)
        {
            bindingEntry = 0;
            bindingIndex = 0;
            ownerOffset = 0;
            if (!g_assetPool || !camoEntry)
                return false;

            const XAssetPool& pool = g_assetPool[ASSET_TYPE_WEAPONCAMOBINDING];
            if (!pool.pool.unk || pool.itemSize < sizeof(std::uintptr_t) || pool.itemAllocCount <= 0)
                return false;

            const auto base = reinterpret_cast<std::uintptr_t>(pool.pool.unk);
            const unsigned int count = static_cast<unsigned int>(pool.itemAllocCount);
            for (unsigned int i = 0; i < count; ++i)
            {
                const auto item = base + static_cast<std::uintptr_t>(i) * static_cast<std::uintptr_t>(pool.itemSize);
                for (unsigned int off = 0;
                     off + sizeof(std::uintptr_t) <= static_cast<unsigned int>(pool.itemSize);
                     off += static_cast<unsigned int>(sizeof(std::uintptr_t)))
                {
                    std::uintptr_t value = 0;
                    SIZE_T got = 0;
                    if (!ReadProcessMemory(GetCurrentProcess(),
                                           reinterpret_cast<const void*>(item + off),
                                           &value, sizeof(value), &got) || got != sizeof(value))
                        continue;
                    if (value == camoEntry)
                    {
                        bindingEntry = item;
                        bindingIndex = i;
                        ownerOffset = off;
                        return true;
                    }
                }
            }
            return false;
        }
    }

    void CaptureNativeTemplate(
        const void* recordAddress,
        std::uintptr_t callerRip)
    {
        if (!recordAddress ||
            g_haveTemplate.load())
        {
            return;
        }

        std::array<unsigned char, kNativeRecordSize> bytes{};

        if (!SafeRead(
                recordAddress,
                bytes.data(),
                bytes.size()))
        {
            return;
        }

        // The parent bridge is generic for asset types. Only keep a real
        // WeaponCamo record (type byte 0x2E).
        if (!RecordIsWeaponCamo(bytes.data()))
            return;

        std::lock_guard<std::mutex> lock(g_mutex);

        if (g_haveTemplate.load())
            return;

        g_template = bytes;
        g_templateAddress =
            reinterpret_cast<std::uintptr_t>(
                recordAddress);

        g_captureRip = callerRip;
        g_haveTemplate.store(true);

        std::uint64_t type = 0;
        std::uint64_t loaderState = 0;

        std::memcpy(
            &type,
            bytes.data(),
            sizeof(type));

        std::memcpy(
            &loaderState,
            bytes.data() + 8,
            sizeof(loaderState));

        std::ostringstream line;
        line
            << "[TEMPLATE_CAPTURED] record="
            << Hex(g_templateAddress)
            << " type=0x"
            << std::hex
            << std::uppercase
            << type
            << " loaderState="
            << Hex(static_cast<std::uintptr_t>(
                loaderState))
            << " callerRip="
            << Hex(callerRip);

        AppendLog(line.str());
    }

    void ArmAutomaticStartupAttempt()
    {
        if (g_autoArmed.exchange(true))
            return;

        g_pending.store(true);

        AppendLog(
            "[AUTO_ARMED] waiting for native WeaponCamo prepare + stock registration");
    }

    bool HasTemplate()
    {
        return g_haveTemplate.load();
    }

    bool Status(std::string& message)
    {
        XAssetPool* pool = nullptr;

        if (g_assetPool)
            pool = &g_assetPool[ASSET_TYPE_WEAPONCAMO];

        std::ostringstream out;
        out
            << "Prototype1"
            << " template="
            << (g_haveTemplate.load()
                    ? "captured"
                    : "pending")
            << " attempted="
            << (g_attempted.load()
                    ? "yes"
                    : "no")
            << " pending="
            << (g_pending.load()
                    ? "yes"
                    : "no")
            << " auto="
            << (g_autoArmed.load() ? "armed" : "off")
            << " preparedSource="
            << (g_havePreparedSource.load()
                    ? "captured"
                    : "pending")
            << " deferred="
            << (g_deferredPostStock.load()
                    ? "waiting_pool"
                    : "no")
            << " batch=" << g_batchRegistered.load()
            << "/" << g_batchDiscovered.load()
            << " failed=" << g_batchFailed.load()
            << " bindings=" << g_bindingsRegistered.load()
            << "/" << g_batchRegistered.load()
            << " bindingFailed=" << g_bindingsFailed.load()
            << " validatedNewEntry="
            << (g_validatedNewEntry.load()
                    ? "yes"
                    : "no")
            << " capturedRecord="
            << Hex(g_templateAddress)
            << " lastResult="
            << Hex(g_lastResult);

        if (pool)
        {
            out
                << " poolItemSize="
                << pool->itemSize
                << " poolAllocated="
                << pool->itemAllocCount
                << " poolCapacity="
                << pool->itemCount
                << " freeHead="
                << Hex(
                    reinterpret_cast<std::uintptr_t>(
                        pool->freeHead));
        }
        else
        {
            out << " pool=unavailable";
        }

        message = out.str();
        return true;
    }

    bool NativeApply(const std::string& name, std::string& message)
    {
        if (name.empty())
        {
            message = "usage: /camo apply <name>";
            return false;
        }

        EnsureBindingsForRegisteredCamos();

        RegisteredCustomCamo camo{};
        {
            std::lock_guard<std::mutex> lock(g_mutex);
            const auto it = g_registeredCustomCamos.find(NormalizeName(name));
            if (it == g_registeredCustomCamos.end())
            {
                std::ostringstream out;
                out << "custom camo not registered: \"" << name << "\"; batch="
                    << g_batchRegistered.load() << '/' << g_batchDiscovered.load();
                message = out.str();
                return false;
            }
            camo = it->second;
        }

        std::uintptr_t binding = camo.binding;
        unsigned int bindingIndex = camo.bindingIndex;
        unsigned int ownerOffset = 0;
        bool hasBinding = binding != 0;
        if (!hasBinding)
            hasBinding = FindBindingForCamo(camo.entry, binding, bindingIndex, ownerOffset);

        std::ostringstream log;
        log << "[NATIVE_APPLY] name=\"" << camo.folder << "\""
            << " identity=0x" << std::hex << std::uppercase << camo.identity
            << " entry=" << Hex(camo.entry) << std::dec
            << " poolIndex=" << camo.poolIndex
            << " binding=" << Hex(binding)
            << " bindingIndex=" << bindingIndex
            << " ownerOffset=0x" << std::hex << ownerOffset << std::dec
            << " status=" << (hasBinding ? "NATIVE_BINDING_FOUND" : "MISSING_NATIVE_BINDING");
        AppendLog(log.str());

        if (!hasBinding)
        {
            std::ostringstream out;
            out << "native WeaponCamo \"" << camo.folder << "\" resolved: id=0x"
                << std::hex << std::uppercase << camo.identity
                << " entry=" << Hex(camo.entry) << std::dec
                << " poolIndex=" << camo.poolIndex
                << "; no WeaponCamoBinding references this new entry yet. No stock camo was replaced.";
            message = out.str();
            return false;
        }

        std::ostringstream out;
        out << "NATIVE_APPLY_READY name=\"" << camo.folder << "\" id=0x"
            << std::hex << std::uppercase << camo.identity
            << " entry=" << Hex(camo.entry)
            << " binding=" << Hex(binding) << std::dec
            << " bindingIndex=" << bindingIndex
            << ". Native WeaponCamo + WeaponCamoBinding pair exists. The verified current-weapon/loadout camo setter is still unresolved, so this build stops before writing unknown weapon state. No donor-slot fallback was used.";
        message = out.str();
        return true;
    }

    bool Create(std::string& message)
    {
        message = "Prototype 1 is automatic in build 179; check /camo prototype status.";
        return false;
    }

    bool IsPending()
    {
        return g_pending.load();
    }

    void CapturePreparedSource(
        const void* preparedSource,
        std::uintptr_t callerRip)
    {
        if (!g_pending.load() ||
            !preparedSource ||
            g_havePreparedSource.load())
        {
            return;
        }

        std::array<unsigned char, 0x80> bytes{};

        if (!SafeRead(
                preparedSource,
                bytes.data(),
                bytes.size()))
        {
            AppendLog(
                "[PREPARED_SOURCE] unreadable");
            return;
        }

        {
            std::lock_guard<std::mutex> lock(g_mutex);
            g_preparedSource = bytes;
            g_preparedSourceAddress =
                reinterpret_cast<std::uintptr_t>(
                    preparedSource);
            g_havePreparedSource.store(true);
        }

        std::ostringstream log;
        log
            << "[PREPARED_SOURCE]"
            << " address=" << Hex(g_preparedSourceAddress)
            << " callerRip=" << Hex(callerRip);

        AppendLog(log.str());
    }


    namespace
    {
        std::string CamoRoot()
        {
            char exePath[MAX_PATH]{};
            if (!GetModuleFileNameA(nullptr, exePath, MAX_PATH))
                return std::string("Camos");

            std::string path = exePath;
            const auto slash = path.find_last_of("\\/");
            if (slash != std::string::npos)
                path.resize(slash);

            return path + "\\Camos";
        }

        bool FolderHasCamoPayload(const std::string& folder)
        {
            WIN32_FIND_DATAA data{};
            HANDLE find = FindFirstFileA((folder + "\\*").c_str(), &data);
            if (find == INVALID_HANDLE_VALUE)
                return false;

            bool found = false;
            do
            {
                if (data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
                    continue;

                std::string name = data.cFileName;
                std::transform(name.begin(), name.end(), name.begin(),
                    [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

                if ((name.size() >= 4 && name.compare(name.size()-4,4,".png") == 0) ||
                    (name.size() >= 4 && name.compare(name.size()-4,4,".gif") == 0))
                {
                    found = true;
                    break;
                }
            }
            while (FindNextFileA(find, &data));

            FindClose(find);
            return found;
        }

        std::vector<std::string> EnumerateCustomCamoFolders()
        {
            std::vector<std::string> result;
            const std::string root = CamoRoot();

            WIN32_FIND_DATAA data{};
            HANDLE find = FindFirstFileA((root + "\\*").c_str(), &data);
            if (find == INVALID_HANDLE_VALUE)
                return result;

            do
            {
                if (!(data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
                    continue;

                const std::string name = data.cFileName;
                if (name == "." || name == "..")
                    continue;

                const std::string folder = root + "\\" + name;
                if (FolderHasCamoPayload(folder))
                    result.push_back(name);
                else
                    AppendLog("[CUSTOM_CAMO_SKIP] folder=\"" + name + "\" reason=no_png_or_gif");
            }
            while (FindNextFileA(find, &data));

            FindClose(find);

            std::sort(result.begin(), result.end(),
                [](const std::string& a, const std::string& b)
                {
                    std::string aa=a, bb=b;
                    std::transform(aa.begin(),aa.end(),aa.begin(),[](unsigned char c){return static_cast<char>(std::tolower(c));});
                    std::transform(bb.begin(),bb.end(),bb.begin(),[](unsigned char c){return static_cast<char>(std::tolower(c));});
                    return aa < bb;
                });

            return result;
        }

        std::uint64_t Fnv1a64(const char* text)
        {
            constexpr std::uint64_t kOffset =
                14695981039346656037ull;

            constexpr std::uint64_t kPrime =
                1099511628211ull;

            std::uint64_t hash = kOffset;

            if (!text)
                return hash;

            while (*text)
            {
                hash ^=
                    static_cast<unsigned char>(
                        *text++);

                hash *= kPrime;
            }

            return hash;
        }

        bool PoolContainsIdentity(
            const XAssetPool& pool,
            std::uint64_t identity)
        {
            if (!identity ||
                !pool.pool.unk ||
                pool.itemSize < sizeof(identity) ||
                pool.itemCount <= 0)
            {
                return false;
            }

            const auto base =
                reinterpret_cast<std::uintptr_t>(
                    pool.pool.unk);

            // Scan the entire pool capacity, not only itemAllocCount. This is
            // deliberately conservative: a stale/free slot that still carries
            // an old identity is also treated as unavailable.
            for (int i = 0; i < pool.itemCount; ++i)
            {
                std::uint64_t existing = 0;
                SIZE_T got = 0;

                const auto entry =
                    base +
                    static_cast<std::uintptr_t>(i) *
                    static_cast<std::uintptr_t>(
                        pool.itemSize);

                if (!ReadProcessMemory(
                        GetCurrentProcess(),
                        reinterpret_cast<const void*>(
                            entry),
                        &existing,
                        sizeof(existing),
                        &got) ||
                    got != sizeof(existing))
                {
                    continue;
                }

                if (existing == identity)
                    return true;
            }

            return false;
        }

        bool AllocateUnusedCustomIdentityForFolder(
            const XAssetPool& pool,
            const std::string& folderName,
            std::uint64_t& identity,
            std::uint32_t& collisionIndex)
        {
            std::lock_guard<std::mutex> lock(g_mutex);

            for (std::uint32_t attempt = 0; attempt < 100000; ++attempt)
            {
                std::string key = "t9_custom_camo:" + folderName;
                if (attempt)
                    key += "#" + std::to_string(attempt);

                const std::uint64_t candidate = Fnv1a64(key.c_str());

                if (!candidate || candidate == ~0ull)
                    continue;

                if (g_reservedCustomIdentities.find(candidate) !=
                    g_reservedCustomIdentities.end())
                    continue;

                if (PoolContainsIdentity(pool, candidate))
                    continue;

                g_reservedCustomIdentities.insert(candidate);
                identity = candidate;
                collisionIndex = attempt;
                return true;
            }

            return false;
        }
    }

    bool PerformPostStockRegistration(
        std::uintptr_t stockResult,
        std::uintptr_t callerRip)
    {
        if (!g_pending.load() ||
            !g_havePreparedSource.load() ||
            g_attempted.exchange(true))
        {
            return false;
        }

        g_pending.store(false);

        if (!g_assetPool)
            return false;

        XAssetPool& pool = g_assetPool[ASSET_TYPE_WEAPONCAMO];

        if (!pool.pool.unk ||
            pool.itemSize != kExpectedPoolEntrySize ||
            pool.itemCount <= 0 ||
            pool.itemAllocCount < 0 ||
            !pool.freeHead)
        {
            AppendLog("[CUSTOM_CAMO_BATCH] refused: pool validation failed");
            return false;
        }

        HMODULE module = GetModuleHandleW(nullptr);
        if (!module)
            return false;

        const auto dbRegister =
            reinterpret_cast<std::uintptr_t>(module) + kDbRegisterRva;

        if (!IsExecutableAddress(dbRegister))
            return false;

        const auto folders = EnumerateCustomCamoFolders();
        g_batchDiscovered.store(static_cast<unsigned int>(folders.size()));
        g_batchRegistered.store(0);
        g_batchFailed.store(0);

        {
            std::ostringstream begin;
            begin << "[CUSTOM_CAMO_BATCH_BEGIN] root=\"" << CamoRoot()
                  << "\" discovered=" << folders.size()
                  << " poolAllocated=" << pool.itemAllocCount
                  << " poolCapacity=" << pool.itemCount;
            AppendLog(begin.str());
        }

        if (folders.empty())
        {
            AppendLog("[CUSTOM_CAMO_BATCH_END] registered=0 failed=0 reason=no_valid_folders");
            return false;
        }

        unsigned int registered = 0;
        unsigned int failed = 0;
        std::uintptr_t lastResult = 0;

        for (const auto& folderName : folders)
        {
            if (pool.itemAllocCount >= pool.itemCount || !pool.freeHead)
            {
                ++failed;
                AppendLog("[CUSTOM_CAMO] folder=\"" + folderName + "\" FAILED reason=pool_full");
                continue;
            }

            alignas(16) std::array<unsigned char, 0x80> sourceClone{};
            {
                std::lock_guard<std::mutex> lock(g_mutex);
                sourceClone = g_preparedSource;
            }

            std::uint64_t originalIdentity = 0;
            std::uint64_t customIdentity = 0;
            std::uint32_t collisionIndex = 0;
            std::memcpy(&originalIdentity, sourceClone.data(), sizeof(originalIdentity));

            if (!AllocateUnusedCustomIdentityForFolder(
                    pool, folderName, customIdentity, collisionIndex))
            {
                ++failed;
                AppendLog("[CUSTOM_CAMO] folder=\"" + folderName + "\" FAILED reason=no_unused_identity");
                continue;
            }

            std::memcpy(sourceClone.data(), &customIdentity, sizeof(customIdentity));

            const int countBefore = pool.itemAllocCount;
            const auto freeBefore = reinterpret_cast<std::uintptr_t>(pool.freeHead);
            DWORD exceptionCode = 0;
            std::uintptr_t extraResult = 0;

            const bool invoked = InvokeDbRegisterSafely(
                dbRegister,
                static_cast<unsigned char>(kWeaponCamoType),
                sourceClone.data(),
                &extraResult,
                &exceptionCode);

            const int countAfter = pool.itemAllocCount;
            const auto freeAfter = reinterpret_cast<std::uintptr_t>(pool.freeHead);

            const bool resultInPool = PointerInsidePool(extraResult, pool);
            const bool newStandalone =
                invoked && exceptionCode == 0 && resultInPool &&
                countAfter == countBefore + 1 &&
                freeAfter != freeBefore &&
                extraResult != stockResult;

            std::ostringstream line;
            line << "[CUSTOM_CAMO] folder=\"" << folderName << "\""
                 << " id=0x" << std::hex << std::uppercase << customIdentity << std::dec
                 << " collisionIndex=" << collisionIndex
                 << " result=" << Hex(extraResult)
                 << " count=" << countBefore << "->" << countAfter
                 << " status=" << (newStandalone ? "REGISTERED_NATIVE" : "FAILED")
                 << " exception=0x" << std::hex << std::uppercase << exceptionCode << std::dec;
            AppendLog(line.str());

            if (newStandalone)
            {
                ++registered;
                lastResult = extraResult;

                const auto poolBase = reinterpret_cast<std::uintptr_t>(pool.pool.unk);
                const unsigned int poolIndex =
                    (extraResult >= poolBase && pool.itemSize > 0)
                        ? static_cast<unsigned int>((extraResult - poolBase) / pool.itemSize)
                        : 0;

                RegisteredCustomCamo item{};
                item.folder = folderName;
                item.identity = customIdentity;
                item.entry = extraResult;
                item.poolIndex = poolIndex;

                std::lock_guard<std::mutex> lock(g_mutex);
                g_registeredCustomCamos[NormalizeName(folderName)] = item;
            }
            else
            {
                ++failed;
            }
        }

        g_batchRegistered.store(registered);
        g_batchFailed.store(failed);
        g_lastResult = lastResult;
        g_validatedNewEntry.store(registered > 0 && failed == 0);

        std::ostringstream done;
        done << "[CUSTOM_CAMO_BATCH_END] discovered=" << folders.size()
             << " registered=" << registered
             << " failed=" << failed
             << " finalPoolAllocated=" << pool.itemAllocCount;
        AppendLog(done.str());

        return registered > 0 && failed == 0;
    }

    bool ExecuteAfterStockRegistration(
        std::uintptr_t stockResult,
        std::uintptr_t callerRip)
    {
        if (!g_pending.load() ||
            !g_havePreparedSource.load())
        {
            return false;
        }

        // Build 185b: always preserve the legitimate stock WeaponCamo result.
        // Build 185 only stored this on the deferred-pool path, so runs where
        // g_assetPool was already ready had no stock camo pointer for the
        // WeaponCamoBinding template lookup.
        g_deferredStockResult = stockResult;
        g_deferredCallerRip = callerRip;

        if (!g_assetPool)
        {
            g_deferredStockResult = stockResult;
            g_deferredCallerRip = callerRip;
            g_deferredPostStock.store(true);

            AppendLog(
                "[POST_STOCK_DEFERRED] g_assetPool unavailable; waiting for pool readiness");

            return false;
        }

        g_deferredPostStock.store(false);

        return PerformPostStockRegistration(
            stockResult,
            callerRip);
    }

    void PumpDeferredAttempt()
    {
        // Build 185: once WeaponCamo batch exists, create matching native bindings.
        EnsureBindingsForRegisteredCamos();

        if (!g_deferredPostStock.load() ||
            !g_pending.load() ||
            !g_havePreparedSource.load() ||
            !g_assetPool)
        {
            return;
        }

        g_deferredPostStock.store(false);

        AppendLog(
            "[DEFERRED_POOL_READY] g_assetPool available; executing saved post-stock registration");

        PerformPostStockRegistration(
            g_deferredStockResult,
            g_deferredCallerRip);
    }

    bool ResetAttempt(std::string& message)
    {
        if (g_validatedNewEntry.load())
        {
            message =
                "Prototype 1 reset refused because a new native entry was "
                "validated. Restart the game before another attempt.";
            return false;
        }

        g_attempted.store(false);
        g_pending.store(false);
        g_havePreparedSource.store(false);
        g_preparedSourceAddress = 0;

        message =
            "Prototype 1 attempt flag reset. This does not undo any engine "
            "bookkeeping; restart the game if the previous call changed pool "
            "state unexpectedly.";

        return true;
    }
}

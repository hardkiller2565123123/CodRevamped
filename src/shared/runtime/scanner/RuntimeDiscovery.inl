namespace
{
    struct RuntimeDiscoveryRequest
    {
        std::string mode;
        std::string query;
    };

    struct RuntimeDiscoveryHit
    {
        uintptr_t address = 0;
        uintptr_t regionBase = 0;
        DWORD protect = 0;
        std::string category;
        std::string text;
        bool verified = false;
        uintptr_t dvarAddress = 0;
        unsigned int flags = 0;
        std::string type;
        std::string value;
        int score = 0;
        bool nativeQueryQueued = false;
        bool nativeRecognized = false;
        std::string nativeResponse;
        std::string scanState;
    };

    static std::atomic_bool g_runtimeDiscoveryRunning{ false };
    static std::atomic_bool g_runtimeDiscoveryCancel{ false };
    static std::atomic_ullong g_runtimeDiscoveryRegions{ 0 };
    static std::atomic_ullong g_runtimeDiscoveryBytes{ 0 };
    static std::atomic_ullong g_runtimeDiscoveryHits{ 0 };
    static std::mutex g_runtimeDiscoveryResultMutex;
    static std::vector<RuntimeDiscoveryHit> g_runtimeDiscoveryLatestHits;
    static std::string g_runtimeDiscoveryLatestMode;
    static std::string g_runtimeDiscoveryLatestDirectory;

    struct RuntimeDvarKnowledge
    {
        std::string name;
        std::string classification;
        std::string type;
        std::string value;
        unsigned int flags = 0;
        int bestScore = 0;
        bool nativeQuerySeen = false;
        unsigned int timesSeen = 0;
        unsigned int statesSeen = 0;
    };



    static std::string RuntimeDiscoveryLower(std::string value);

    enum class RuntimeNativeProbeResult
    {
        NoOutput,
        RecognizedDvar,
        RecognizedCommand,
        Unknown
    };

    // Keep SEH inside a POD-only helper. MSVC rejects __try in functions that
    // create C++ objects requiring stack unwinding (such as std::string).
    static bool RuntimeDiscoverySafeReadUInt32(uintptr_t address, unsigned int* value)
    {
        if (!address || !value) return false;
        __try
        {
            *value = *reinterpret_cast<volatile const unsigned int*>(address);
            return true;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            *value = 0;
            return false;
        }
    }

    static std::string RuntimeDiscoveryCurrentState()
    {
        unsigned int ui = 0;
        unsigned int session = 0;
        RuntimeDiscoverySafeReadUInt32(g_Addrs.s_uiScreen, &ui);
        RuntimeDiscoverySafeReadUInt32(g_Addrs.sSessionModeState, &session);

        char buffer[64]{};
        sprintf_s(buffer, "ui_%X_session_%X", ui, session);
        return std::string(buffer);
    }

    static unsigned int RuntimeDiscoveryStateBit(const std::string& state)
    {
        unsigned int hash = 2166136261u;
        for (unsigned char c : state) { hash ^= c; hash *= 16777619u; }
        return 1u << (hash & 31u);
    }

    static std::string RuntimeDiscoveryReadConsoleTail(SHORT startY)
    {
        HANDLE output = GetStdHandle(STD_OUTPUT_HANDLE);
        if (!output || output == INVALID_HANDLE_VALUE) return {};
        CONSOLE_SCREEN_BUFFER_INFO info{};
        if (!GetConsoleScreenBufferInfo(output, &info)) return {};
        const SHORT first = (std::max)(static_cast<SHORT>(0), startY);
        const SHORT last = info.dwCursorPosition.Y;
        if (last < first) return {};
        std::string result;
        result.reserve(static_cast<size_t>(last - first + 1) * 120);
        for (SHORT y = first; y <= last; ++y)
        {
            std::vector<char> line(static_cast<size_t>(info.dwSize.X) + 1, 0);
            DWORD read = 0;
            if (!ReadConsoleOutputCharacterA(output, line.data(), info.dwSize.X, COORD{0, y}, &read)) continue;
            while (read && (line[read - 1] == ' ' || line[read - 1] == '\0')) --read;
            if (read) { result.append(line.data(), read); result.push_back('\n'); }
        }
        return result;
    }

    static RuntimeNativeProbeResult RuntimeDiscoveryProbeNative(const std::string& name, std::string& response)
    {
        HANDLE output = GetStdHandle(STD_OUTPUT_HANDLE);
        CONSOLE_SCREEN_BUFFER_INFO before{};
        SHORT startY = 0;
        if (output && output != INVALID_HANDLE_VALUE && GetConsoleScreenBufferInfo(output, &before))
            startY = before.dwCursorPosition.Y;
        if (!ExecuteDeveloperCommand(name.c_str())) return RuntimeNativeProbeResult::NoOutput;
        for (int i = 0; i < 12 && !g_runtimeDiscoveryCancel.load(); ++i) Sleep(10);
        response = RuntimeDiscoveryReadConsoleTail(startY);
        // Remove our own runtime/scanner/logger lines so merely queuing a name cannot
        // falsely verify it as an engine command.
        {
            std::istringstream input(response);
            std::string line;
            std::string engineOnly;
            while (std::getline(input, line))
            {
                const std::string loweredLine = RuntimeDiscoveryLower(line);
                if (loweredLine.find("[devcon]") != std::string::npos ||
                    loweredLine.find("[memscan]") != std::string::npos ||
                    loweredLine.find("t9>") != std::string::npos)
                    continue;
                if (!line.empty()) { engineOnly += line; engineOnly.push_back('\n'); }
            }
            response.swap(engineOnly);
        }
        const std::string lower = RuntimeDiscoveryLower(response);
        if (lower.empty()) return RuntimeNativeProbeResult::NoOutput;
        if (lower.find("unknown command") != std::string::npos || lower.find("unknown dvar") != std::string::npos ||
            lower.find("couldn't find") != std::string::npos || lower.find("not found") != std::string::npos)
            return RuntimeNativeProbeResult::Unknown;
        const std::string lowerName = RuntimeDiscoveryLower(name);
        if (lower.find(lowerName + " =") != std::string::npos || lower.find(lowerName + ":") != std::string::npos ||
            lower.find("current value") != std::string::npos || lower.find("default") != std::string::npos)
            return RuntimeNativeProbeResult::RecognizedDvar;
        if (lower.find("usage") != std::string::npos || lower.find(lowerName) != std::string::npos)
            return RuntimeNativeProbeResult::RecognizedCommand;
        return RuntimeNativeProbeResult::NoOutput;
    }

    static bool RuntimeDiscoveryReadable(DWORD protect)
    {
        if (protect & (PAGE_GUARD | PAGE_NOACCESS)) return false;
        const DWORD base = protect & 0xFF;
        return base == PAGE_READONLY || base == PAGE_READWRITE || base == PAGE_WRITECOPY ||
            base == PAGE_EXECUTE_READ || base == PAGE_EXECUTE_READWRITE || base == PAGE_EXECUTE_WRITECOPY;
    }

    static std::string RuntimeDiscoveryLower(std::string value)
    {
        std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c)
        {
            return static_cast<char>(std::tolower(c));
        });
        return value;
    }

    static std::map<std::string, RuntimeDvarKnowledge> RuntimeDiscoveryLoadKnowledge()
    {
        std::map<std::string, RuntimeDvarKnowledge> result;
        std::ifstream file("logs\\dvar_knowledge.csv");
        if (!file) return result;
        std::string line;
        std::getline(file, line);
        while (std::getline(file, line))
        {
            std::vector<std::string> fields;
            std::string field;
            bool quoted = false;
            for (size_t i = 0; i < line.size(); ++i)
            {
                const char c = line[i];
                if (c == '"')
                {
                    if (quoted && i + 1 < line.size() && line[i + 1] == '"') { field.push_back('"'); ++i; }
                    else quoted = !quoted;
                }
                else if (c == ',' && !quoted) { fields.push_back(field); field.clear(); }
                else field.push_back(c);
            }
            fields.push_back(field);
            if (fields.size() < 7 || fields[0].empty()) continue;
            RuntimeDvarKnowledge item{};
            item.name = fields[0];
            item.classification = fields[1];
            item.bestScore = std::atoi(fields[2].c_str());
            item.timesSeen = static_cast<unsigned int>(std::strtoul(fields[3].c_str(), nullptr, 10));
            item.type = fields[4];
            item.flags = static_cast<unsigned int>(std::strtoul(fields[5].c_str(), nullptr, 0));
            item.value = fields[6];
            if (fields.size() >= 8) item.nativeQuerySeen = std::atoi(fields[7].c_str()) != 0;
            if (fields.size() >= 9) item.statesSeen = static_cast<unsigned int>(std::strtoul(fields[8].c_str(), nullptr, 0));
            result[RuntimeDiscoveryLower(item.name)] = std::move(item);
        }
        return result;
    }

    static void RuntimeDiscoverySaveKnowledge(const std::map<std::string, RuntimeDvarKnowledge>& knowledge)
    {
        CreateDirectoryA("logs", nullptr);
        std::ofstream file("logs\\dvar_knowledge.csv", std::ios::trunc);
        if (!file) return;
        file << "name,classification,best_score,times_seen,type,flags,last_value,native_query_seen,states_seen\n";
        for (const auto& pair : knowledge)
        {
            const RuntimeDvarKnowledge& item = pair.second;
            file << '"' << JsonEscape(item.name) << "\",\"" << JsonEscape(item.classification)
                 << "\"," << item.bestScore << ',' << item.timesSeen << ",\"" << JsonEscape(item.type)
                 << "\",0x" << std::hex << std::uppercase << item.flags << std::dec << ",\""
                 << JsonEscape(item.value) << "\"," << (item.nativeQuerySeen ? 1 : 0) << ",0x"
                 << std::hex << std::uppercase << item.statesSeen << std::dec << "\n";
        }
    }

    static bool RuntimeDiscoveryStartsWith(const std::string& value, const char* prefix)
    {
        const size_t length = strlen(prefix);
        return value.size() >= length && _strnicmp(value.c_str(), prefix, length) == 0;
    }

    static bool RuntimeDiscoveryIsIdentifier(const std::string& value)
    {
        if (value.size() < 2 || value.size() > 128)
            return false;
        if (!(std::isalpha(static_cast<unsigned char>(value[0])) || value[0] == '_'))
            return false;
        for (unsigned char c : value)
        {
            if (!(std::isalnum(c) || c == '_' || c == '.'))
                return false;
        }
        return true;
    }

    static bool RuntimeDiscoveryIsObviousNoise(const std::string& value)
    {
        const std::string lower = RuntimeDiscoveryLower(value);
        static const char* blockedPrefixes[] = {
            "__", "_zn", "_z", "dw_", "cuda", "cuipc", "opencl", "llvm", "rtx_",
            "bcrypt", "archive_", "cert", "chromium", "blink.", "accessibility.",
            "d3dkmt", "dxgi_", "cfgmgr32.", "cm_", "crypt", "evt", "fwpm", "fwps",
            "asn1", "openssl", "steam", "cmsg", "capi", "winhttp", "dns_", "bluetooth"
        };
        for (const char* prefix : blockedPrefixes)
            if (RuntimeDiscoveryStartsWith(lower, prefix))
                return true;
        static const char* blockedContains[] = {
            "syscall", "fullpath", "string_reference", "callback", "subscription", "threadpool",
            "closesthit", "dialogresult", "statusbar", "titlebar", "openfile", "closehandle",
            "certificate", "packagegraph", "filedownload", "javascript", "websocket"
        };
        for (const char* token : blockedContains)
            if (lower.find(token) != std::string::npos)
                return true;
        if (value.size() > 80) return true;
        return false;
    }

    static bool RuntimeDiscoveryLooksLikeSafeNativeDvarQuery(const std::string& value)
    {
        if (!RuntimeDiscoveryIsIdentifier(value) || RuntimeDiscoveryIsObviousNoise(value)) return false;
        if (value.size() < 5 || value.size() > 64) return false;
        if (value.find('_') == std::string::npos) return false;
        if (std::isupper(static_cast<unsigned char>(value[0]))) return false;

        const std::string lower = RuntimeDiscoveryLower(value);
        static const char* safePrefixes[] = {
            "ai_", "bg_", "cg_", "cl_", "com_", "g_", "input_", "lobby_", "m_",
            "party_", "player_", "r_", "scr_", "snd_", "sv_", "ui_"
        };
        bool prefixMatch = false;
        for (const char* prefix : safePrefixes)
        {
            if (RuntimeDiscoveryStartsWith(lower, prefix)) { prefixMatch = true; break; }
        }
        if (!prefixMatch) return false;

        // Bare execution of action-like commands can alter game state. Only queue
        // read-style probes for names that do not look like imperative commands.
        static const char* dangerousTokens[] = {
            "restart", "disconnect", "quit", "exit", "open", "close", "toggle", "reload",
            "reset", "delete", "remove", "kick", "ban", "map", "launch", "start", "stop"
        };
        for (const char* token : dangerousTokens)
            if (lower.find(token) != std::string::npos) return false;

        // Shader semantics and exported function labels are not dvars.
        if (RuntimeDiscoveryStartsWith(value, "SV_") || RuntimeDiscoveryStartsWith(value, "GScr_")) return false;
        for (size_t i = 1; i < value.size(); ++i)
        {
            if (std::isupper(static_cast<unsigned char>(value[i])) && value[i - 1] != '_')
                return false;
        }
        return true;
    }

    static bool RuntimeDiscoveryIsRelevantLabel(const std::string& value)
    {
        if (!RuntimeDiscoveryIsIdentifier(value) || RuntimeDiscoveryIsObviousNoise(value)) return false;
        const std::string lower = RuntimeDiscoveryLower(value);
        static const char* gamePrefixes[] = {
            "ui_", "lobby_", "menu_", "mpui_", "party_", "online_", "live_", "aar_",
            "cac_", "codcaster_", "classpicker_", "close_", "open_", "zombie_"
        };
        for (const char* prefix : gamePrefixes)
            if (RuntimeDiscoveryStartsWith(lower, prefix)) return true;
        return lower.find("lua_engine_function_") != std::string::npos;
    }

    static int RuntimeDiscoveryDvarScore(const std::string& value)
    {
        if (!RuntimeDiscoveryIsIdentifier(value) || RuntimeDiscoveryIsObviousNoise(value))
            return -100;

        int score = 0;
        const std::string lower = RuntimeDiscoveryLower(value);
        if (value.size() <= 4) return -100;
        if (RuntimeDiscoveryStartsWith(value, "SV_") || RuntimeDiscoveryStartsWith(value, "GScr_") ||
            RuntimeDiscoveryStartsWith(value, "CL_") || RuntimeDiscoveryStartsWith(value, "Com_") ||
            RuntimeDiscoveryStartsWith(value, "R_") || RuntimeDiscoveryStartsWith(value, "Scr_")) return -100;
        static const char* strongPrefixes[] = {
            "cg_", "com_", "cl_", "sv_", "scr_", "r_", "g_", "bg_", "ai_",
            "snd_", "sys_", "net_", "party_", "lobby_", "input_", "player_"
        };
        static const char* weakPrefixes[] = {
            "ui_", "fx_", "weapon_", "perk_", "profile_", "zombie_", "dw_", "xblive_"
        };
        for (const char* prefix : strongPrefixes)
            if (RuntimeDiscoveryStartsWith(value, prefix)) { score += 45; break; }
        for (const char* prefix : weakPrefixes)
            if (RuntimeDiscoveryStartsWith(value, prefix)) { score += 18; break; }

        if (lower == "developer" || lower == "developer_script" || lower == "timescale" ||
            lower == "noclip" || lower == "god" || lower == "notarget" || lower == "ufo")
            score += 80;
        if (value.size() >= 4 && value.size() <= 64) score += 15;
        if (value.find('.') == std::string::npos) score += 5;
        if (lower.find("icon_") != std::string::npos || lower.find("_jnt") != std::string::npos ||
            lower.find("battle_pass_render") != std::string::npos || lower.find("string_reference") != std::string::npos)
            score -= 40;
        if (lower.find("open") != std::string::npos || lower.find("close") != std::string::npos ||
            lower.find("dialog") != std::string::npos || lower.find("title") != std::string::npos ||
            lower.find("label") != std::string::npos || lower.find("status") != std::string::npos)
            score -= 15;
        return score;
    }

    static bool RuntimeDiscoveryLooksLikeLabel(const std::string& value)
    {
        return RuntimeDiscoveryIsRelevantLabel(value);
    }

    static bool RuntimeDiscoveryLooksLikeDvar(const std::string& value)
    {
        static const char* prefixes[] = {
            "cg_", "r_", "com_", "cl_", "sv_", "scr_", "ui_", "g_", "ai_", "bg_",
            "fx_", "snd_", "sys_", "net_", "party_", "lobby_", "dw_", "xblive_", "input_",
            "vid_", "win_", "loc_", "profile_", "perk_", "weapon_", "player_", "zombie_"
        };
        if (!RuntimeDiscoveryIsIdentifier(value) || value.size() < 4 || value.size() > 96 ||
            RuntimeDiscoveryIsObviousNoise(value)) return false;
        for (const char* prefix : prefixes)
            if (RuntimeDiscoveryStartsWith(value, prefix)) return RuntimeDiscoveryDvarScore(value) >= 10;
        const std::string lower = RuntimeDiscoveryLower(value);
        return lower == "developer" || lower == "developer_script" || lower == "timescale" ||
            lower == "noclip" || lower == "god" || lower == "notarget" || lower == "ufo";
    }

    static bool RuntimeDiscoveryLooksLikeGsc(const std::string& value)
    {
        if (value.size() < 4 || value.size() > 260) return false;
        const std::string lower = RuntimeDiscoveryLower(value);
        return lower.find(".gsc") != std::string::npos || lower.find(".csc") != std::string::npos ||
            lower.find("scripts/") != std::string::npos || lower.find("scripts\\") != std::string::npos ||
            lower.find("maps/mp/") != std::string::npos || lower.find("maps/zm/") != std::string::npos ||
            RuntimeDiscoveryStartsWith(value, "GScr_") || RuntimeDiscoveryStartsWith(value, "ScrCmd_") ||
            RuntimeDiscoveryStartsWith(value, "PlayerCmd_") || RuntimeDiscoveryStartsWith(value, "GSCFunc_") ||
            value.find("::") != std::string::npos;
    }

    static bool RuntimeDiscoveryMatches(const std::string& value, const RuntimeDiscoveryRequest& request, std::string& category)
    {
        const std::string mode = RuntimeDiscoveryLower(request.mode);
        const std::string lower = RuntimeDiscoveryLower(value);
        if (!request.query.empty() && lower.find(RuntimeDiscoveryLower(request.query)) == std::string::npos)
            return false;

        const bool dvar = RuntimeDiscoveryLooksLikeDvar(value);
        const bool gsc = RuntimeDiscoveryLooksLikeGsc(value);
        if (mode == "dvar" || mode == "dvars")
        {
            if (!dvar && !RuntimeDiscoveryLooksLikeLabel(value)) return false;
            category = dvar ? "candidate" : "label";
            return true;
        }
        if (mode == "gsc" || mode == "script" || mode == "scripts")
        {
            if (!gsc) return false;
            category = "gsc";
            return true;
        }
        if (mode == "prefix")
        {
            if (request.query.empty()) return false;
            category = dvar ? "dvar" : (gsc ? "gsc" : "string");
            return RuntimeDiscoveryStartsWith(lower, RuntimeDiscoveryLower(request.query).c_str());
        }
        if (dvar) category = "dvar";
        else if (gsc) category = "gsc";
        else return false;
        return true;
    }

    static std::string RuntimeDiscoveryDirectory()
    {
        CreateDirectoryA("logs", nullptr);
        CreateDirectoryA("logs\\runtime_scan", nullptr);
        SYSTEMTIME time{};
        GetLocalTime(&time);
        char path[MAX_PATH]{};
        sprintf_s(path, "logs\\runtime_scan\\scan_%04u-%02u-%02u_%02u-%02u-%02u",
            time.wYear, time.wMonth, time.wDay, time.wHour, time.wMinute, time.wSecond);
        CreateDirectoryA(path, nullptr);
        return path;
    }

    static void RuntimeDiscoveryWriteCsv(const std::string& path, const std::vector<RuntimeDiscoveryHit>& hits)
    {
        std::ofstream file(path, std::ios::trunc);
        if (!file) return;
        file << "category,score,string_address,region_base,protection,verified,dvar_address,type,flags,value,text\n";
        for (const auto& hit : hits)
        {
            file << hit.category << "," << hit.score << ",0x" << std::hex << std::uppercase << hit.address
                 << ",0x" << hit.regionBase << ",0x" << hit.protect << std::dec
                 << "," << (hit.verified ? "true" : "false")
                 << ",0x" << std::hex << std::uppercase << hit.dvarAddress << std::dec
                 << ",\"" << JsonEscape(hit.type) << "\""
                 << ",0x" << std::hex << std::uppercase << hit.flags << std::dec
                 << ",\"" << JsonEscape(hit.value) << "\""
                 << ",\"" << JsonEscape(hit.text) << "\"\n";
        }
    }

    static DWORD WINAPI RuntimeDiscoveryThread(LPVOID parameter)
    {
        std::unique_ptr<RuntimeDiscoveryRequest> request(static_cast<RuntimeDiscoveryRequest*>(parameter));
        if (!request)
        {
            g_runtimeDiscoveryRunning.store(false);
            return 0;
        }

        SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_BELOW_NORMAL);
        const std::string directory = RuntimeDiscoveryDirectory();
        StatusPrintf("[MEMSCAN] Runtime %s scan started%s%s.\n", request->mode.c_str(),
            request->query.empty() ? "" : " query=\"", request->query.empty() ? "" : request->query.c_str());
        if (!request->query.empty()) StatusPrintf("[MEMSCAN] Query filter: %s\n", request->query.c_str());
        StatusPrintf("[MEMSCAN] Scanning committed readable process memory after runtime initialization.\n");
        auto knowledge = RuntimeDiscoveryLoadKnowledge();
        StatusPrintf("[MEMSCAN] Loaded %zu persistent dvar knowledge record(s); previously rejected low-confidence names will be skipped.\n", knowledge.size());

        std::vector<RuntimeDiscoveryHit> hits;
        std::set<std::string> unique;
        SYSTEM_INFO systemInfo{};
        GetSystemInfo(&systemInfo);
        uintptr_t cursor = reinterpret_cast<uintptr_t>(systemInfo.lpMinimumApplicationAddress);
        const uintptr_t maximum = reinterpret_cast<uintptr_t>(systemInfo.lpMaximumApplicationAddress);
        HANDLE process = GetCurrentProcess();
        unsigned long long regions = 0;
        unsigned long long bytesRead = 0;
        g_runtimeDiscoveryCancel.store(false);
        g_runtimeDiscoveryRegions.store(0);
        g_runtimeDiscoveryBytes.store(0);
        g_runtimeDiscoveryHits.store(0);
        unsigned int livePrinted = 0;
        const size_t chunkSize = 1024 * 1024;
        std::vector<unsigned char> buffer(chunkSize + 1);

        while (cursor < maximum && !g_runtimeDiscoveryCancel.load())
        {
            MEMORY_BASIC_INFORMATION mbi{};
            if (!VirtualQuery(reinterpret_cast<const void*>(cursor), &mbi, sizeof(mbi)) || !mbi.RegionSize)
                break;
            const uintptr_t regionBase = reinterpret_cast<uintptr_t>(mbi.BaseAddress);
            const uintptr_t regionEnd = regionBase + mbi.RegionSize;
            if (mbi.State == MEM_COMMIT && RuntimeDiscoveryReadable(mbi.Protect))
            {
                ++regions;
                g_runtimeDiscoveryRegions.store(regions);
                const size_t overlap = 512;
                const size_t blockStep = chunkSize - overlap;
                for (uintptr_t block = regionBase; block < regionEnd && !g_runtimeDiscoveryCancel.load(); block += blockStep)
                {
                    const SIZE_T wanted = static_cast<SIZE_T>((std::min)(regionEnd - block, static_cast<uintptr_t>(chunkSize)));
                    SIZE_T got = 0;
                    if (!ReadProcessMemory(process, reinterpret_cast<const void*>(block), buffer.data(), wanted, &got) || got < 4)
                        continue;
                    bytesRead += got;
                    g_runtimeDiscoveryBytes.store(bytesRead);
                    buffer[got] = 0;
                    for (size_t i = 0; i + 4 < got; )
                    {
                        const unsigned char c = buffer[i];
                        if (c < 0x20 || c > 0x7E)
                        {
                            ++i;
                            continue;
                        }
                        size_t length = 1;
                        while (i + length < got && length < 512 && buffer[i + length] >= 0x20 && buffer[i + length] <= 0x7E)
                            ++length;
                        const bool terminated = i + length < got && buffer[i + length] == 0;
                        if (terminated && length >= 4)
                        {
                            std::string value(reinterpret_cast<const char*>(buffer.data() + i), length);
                            std::string category;
                            if (RuntimeDiscoveryMatches(value, *request, category))
                            {
                                const std::string key = category + "\n" + RuntimeDiscoveryLower(value);
                                if (unique.insert(key).second)
                                {
                                    RuntimeDiscoveryHit hit{};
                                    hit.address = block + i;
                                    hit.regionBase = regionBase;
                                    hit.protect = mbi.Protect;
                                    hit.category = category;
                                    hit.text = value;
                                    hit.score = category == "candidate" ? RuntimeDiscoveryDvarScore(value) : 0;
                                    hits.push_back(std::move(hit));
                                    g_runtimeDiscoveryHits.store(static_cast<unsigned long long>(hits.size()));
                                    const bool dvarMode = RuntimeDiscoveryLower(request->mode) == "dvar" ||
                                        RuntimeDiscoveryLower(request->mode) == "dvars";
                                    if (!dvarMode && livePrinted < 300)
                                    {
                                        const auto& shown = hits.back();
                                        StatusPrintf("[MEMSCAN] %-18s 0x%p %s\n", shown.category.c_str(),
                                            reinterpret_cast<void*>(shown.address), shown.text.c_str());
                                        ++livePrinted;
                                    }
                                }
                            }
                            i += length + 1;
                        }
                        else
                        {
                            i += length ? length : 1;
                        }
                    }
                }
            }
            cursor = regionEnd > cursor ? regionEnd : cursor + 0x1000;
        }

        if (RuntimeDiscoveryLower(request->mode) == "dvar" || RuntimeDiscoveryLower(request->mode) == "dvars")
        {
            StatusPrintf("[MEMSCAN] Candidate collection complete; refreshing the live dvar registry view.\n");
            t9_dvars::Refresh();
            StatusPrintf("[MEMSCAN] Validating pointer metadata first, then conservatively probing dvar-shaped names through the native command path.\n");
            std::vector<std::string> candidateNames;
            candidateNames.reserve(hits.size());
            for (const auto& hit : hits)
                if (hit.category == "candidate") candidateNames.push_back(hit.text);
            size_t cachedCandidateCount = 0;
            for (const auto& pair : knowledge)
            {
                const RuntimeDvarKnowledge& item = pair.second;
                if (item.classification == "verified" || item.classification == "possible")
                {
                    candidateNames.push_back(item.name);
                    ++cachedCandidateCount;
                }
            }
            StatusPrintf("[MEMSCAN] Reusing %zu cached verified/possible name(s); only unknown or changed candidates require new classification.\n",
                cachedCandidateCount);
            t9_dvars::MergeCandidates(candidateNames, t9_dvars::Source::RuntimeDump);

            // Include verified database entries even when their name string was
            // outside the readable ranges captured in this pass.
            for (const auto& known : t9_dvars::Entries({}, true))
            {
                const std::string key = std::string("candidate\n") + RuntimeDiscoveryLower(known.name);
                if (!unique.insert(key).second)
                    continue;
                RuntimeDiscoveryHit hit{};
                hit.category = "verified_dvar";
                hit.text = known.name;
                hit.verified = true;
                hit.dvarAddress = known.address;
                hit.flags = known.flags;
                hit.type = known.type;
                hit.value = known.value;
                hits.push_back(std::move(hit));
            }

            const std::string scanState = RuntimeDiscoveryCurrentState();
            const unsigned int scanStateBit = RuntimeDiscoveryStateBit(scanState);
            StatusPrintf("[MEMSCAN] Scan state: %s (knowledge is merged across menu/match/mode scans).\n", scanState.c_str());
            for (auto& hit : hits) hit.scanState = scanState;
            size_t nativeQueriesQueued = 0;
            constexpr size_t kMaxNativeQueriesPerScan = 128;
            for (auto& hit : hits)
            {
                if (g_runtimeDiscoveryCancel.load())
                    break;
                if (hit.category != "candidate")
                    continue;

                const std::string knowledgeKey = RuntimeDiscoveryLower(hit.text);
                const auto previous = knowledge.find(knowledgeKey);
                if (previous != knowledge.end() && previous->second.classification == "rejected" &&
                    previous->second.bestScore < 35 && hit.score < 35)
                {
                    hit.category = "rejected_candidate";
                    continue;
                }

                t9_dvars::Entry verified{};
                if (t9_dvars::ProbeConsoleDvar(hit.text, verified, nullptr))
                {
                    hit.category = "verified_dvar";
                    hit.verified = true;
                    hit.dvarAddress = verified.address;
                    hit.flags = verified.flags;
                    hit.type = verified.type;
                    hit.value = verified.value;
                }
                else
                {
                    if (RuntimeDiscoveryLooksLikeLabel(hit.text))
                    {
                        hit.category = "label";
                    }
                    else if (hit.score >= 35)
                    {
                        hit.category = "possible_dvar";
                        // Dvar_FindVar is unresolved on this retail build, while the
                        // native command buffer is known to accept real dvars such as
                        // com_maxfps. Queue a conservative read-only query only for
                        // dvar-shaped names. This is tracked separately and is never
                        // misreported as pointer-verified metadata.
                        if (hit.score >= 65 && nativeQueriesQueued < kMaxNativeQueriesPerScan &&
                            RuntimeDiscoveryLooksLikeSafeNativeDvarQuery(hit.text))
                        {
                            hit.nativeQueryQueued = true;
                            const RuntimeNativeProbeResult probe = RuntimeDiscoveryProbeNative(hit.text, hit.nativeResponse);
                            if (probe == RuntimeNativeProbeResult::RecognizedDvar)
                            {
                                hit.category = "verified_native_dvar";
                                hit.nativeRecognized = true;
                            }
                            else if (probe == RuntimeNativeProbeResult::RecognizedCommand)
                            {
                                hit.category = "verified_command";
                                hit.nativeRecognized = true;
                            }
                            else if (probe == RuntimeNativeProbeResult::Unknown)
                            {
                                hit.category = "rejected_candidate";
                            }
                            ++nativeQueriesQueued;
                        }
                    }
                    else
                    {
                        hit.category = "rejected_candidate";
                    }
                }
            }

            for (const auto& hit : hits)
            {
                if (hit.category != "verified_dvar" && hit.category != "verified_native_dvar" &&
                    hit.category != "verified_command" && hit.category != "possible_dvar" &&
                    hit.category != "rejected_candidate") continue;
                const std::string key = RuntimeDiscoveryLower(hit.text);
                RuntimeDvarKnowledge& item = knowledge[key];
                if (item.name.empty()) item.name = hit.text;
                item.bestScore = (std::max)(item.bestScore, hit.score);
                ++item.timesSeen;
                item.statesSeen |= scanStateBit;
                item.nativeQuerySeen = item.nativeQuerySeen || hit.nativeQueryQueued;
                if (hit.category == "verified_dvar" || hit.category == "verified_native_dvar" || hit.category == "verified_command")
                {
                    item.classification = hit.category == "verified_command" ? "command" : "verified";
                    item.type = hit.type;
                    item.flags = hit.flags;
                    item.value = hit.value;
                }
                else if (item.classification != "verified")
                {
                    item.classification = hit.category == "possible_dvar" ? "possible" : "rejected";
                }
            }
            RuntimeDiscoverySaveKnowledge(knowledge);
            t9_dvars::WriteReport();
            StatusPrintf("[MEMSCAN] Native read-query probes queued: %zu (cap=%zu). Results are promoted only when engine console output recognizes the name; silent probes remain candidates.\n",
                nativeQueriesQueued, kMaxNativeQueriesPerScan);

            unsigned int verifiedPrinted = 0;
            unsigned int possiblePrinted = 0;
            unsigned int labelPrinted = 0;
            for (const auto& hit : hits)
            {
                if (hit.category == "verified_dvar" && verifiedPrinted < 300)
                {
                    StatusPrintf("[MEMSCAN] DVAR  %-38s type=%-8s value=%s flags=0x%X dvar=0x%p\n",
                        hit.text.c_str(), hit.type.c_str(), hit.value.c_str(), hit.flags,
                        reinterpret_cast<void*>(hit.dvarAddress));
                    ++verifiedPrinted;
                }
                else if ((hit.category == "verified_native_dvar" || hit.category == "verified_command") && verifiedPrinted < 300)
                {
                    StatusPrintf(hit.category == "verified_native_dvar"
                        ? "[MEMSCAN] NATIVE-DVAR %-38s state=%s\n"
                        : "[MEMSCAN] COMMAND     %-38s state=%s\n", hit.text.c_str(), hit.scanState.c_str());
                    ++verifiedPrinted;
                }
                else if (hit.category == "possible_dvar" && possiblePrinted < 80)
                {
                    StatusPrintf(hit.nativeQueryQueued
                        ? "[MEMSCAN] NATIVE-QUERY score=%d 0x%p %s\n"
                        : "[MEMSCAN] POSSIBLE score=%d 0x%p %s\n", hit.score,
                        reinterpret_cast<void*>(hit.address), hit.text.c_str());
                    ++possiblePrinted;
                }
                else if (hit.category == "label" && labelPrinted < 40)
                {
                    StatusPrintf("[MEMSCAN] LABEL 0x%p %s\n", reinterpret_cast<void*>(hit.address), hit.text.c_str());
                    ++labelPrinted;
                }
            }
            livePrinted = verifiedPrinted + possiblePrinted + labelPrinted;
        }

        std::sort(hits.begin(), hits.end(), [](const RuntimeDiscoveryHit& left, const RuntimeDiscoveryHit& right)
        {
            if (left.category != right.category) return left.category < right.category;
            return _stricmp(left.text.c_str(), right.text.c_str()) < 0;
        });
        RuntimeDiscoveryWriteCsv(directory + "\\runtime_strings.csv", hits);

        {
            std::lock_guard<std::mutex> lock(g_runtimeDiscoveryResultMutex);
            g_runtimeDiscoveryLatestHits = hits;
            g_runtimeDiscoveryLatestMode = request->mode;
            g_runtimeDiscoveryLatestDirectory = directory;
        }

        std::ofstream dvars(directory + "\\verified_dvars.csv", std::ios::trunc);
        std::ofstream labels(directory + "\\labels.txt", std::ios::trunc);
        std::ofstream nativeDvars(directory + "\\verified_native_dvars.csv", std::ios::trunc);
        std::ofstream commands(directory + "\\verified_commands.csv", std::ios::trunc);
        std::ofstream possible(directory + "\\possible_dvars.csv", std::ios::trunc);
        std::ofstream rejected(directory + "\\rejected_candidates.txt", std::ios::trunc);
        std::ofstream gsc(directory + "\\gsc_scripts.txt", std::ios::trunc);
        if (dvars) dvars << "name,dvar_address,type,flags,value,string_address\n";
        if (possible) possible << "name,score,string_address,native_query_queued,scan_state\n";
        if (nativeDvars) nativeDvars << "name,string_address,scan_state,response\n";
        if (commands) commands << "name,string_address,scan_state,response\n";
        size_t dvarCount = 0, possibleCount = 0, labelCount = 0, rejectedCount = 0, gscCount = 0;
        for (const auto& hit : hits)
        {
            if (hit.category == "verified_dvar")
            {
                if (dvars) dvars << "\"" << JsonEscape(hit.text) << "\",0x" << std::hex << std::uppercase
                    << hit.dvarAddress << std::dec << ",\"" << JsonEscape(hit.type) << "\",0x" << std::hex
                    << std::uppercase << hit.flags << std::dec << ",\"" << JsonEscape(hit.value)
                    << "\",0x" << std::hex << std::uppercase << hit.address << std::dec << "\n";
                ++dvarCount;
            }
            else if (hit.category == "verified_native_dvar")
            {
                if (nativeDvars) nativeDvars << "\"" << JsonEscape(hit.text) << "\",0x" << std::hex << std::uppercase
                    << hit.address << std::dec << ",\"" << JsonEscape(hit.scanState) << "\",\""
                    << JsonEscape(hit.nativeResponse) << "\"\n";
                ++dvarCount;
            }
            else if (hit.category == "verified_command")
            {
                if (commands) commands << "\"" << JsonEscape(hit.text) << "\",0x" << std::hex << std::uppercase
                    << hit.address << std::dec << ",\"" << JsonEscape(hit.scanState) << "\",\""
                    << JsonEscape(hit.nativeResponse) << "\"\n";
            }
            else if (hit.category == "possible_dvar")
            {
                if (possible) possible << "\"" << JsonEscape(hit.text) << "\"," << hit.score
                    << ",0x" << std::hex << std::uppercase << hit.address << std::dec << ','
                    << (hit.nativeQueryQueued ? 1 : 0) << ",\"" << JsonEscape(hit.scanState) << "\"\n";
                ++possibleCount;
            }
            else if (hit.category == "label") { if (labels) labels << hit.text << "\n"; ++labelCount; }
            else if (hit.category == "rejected_candidate") { if (rejected) rejected << hit.text << "\n"; ++rejectedCount; }
            else if (hit.category == "gsc") { if (gsc) gsc << hit.text << "\n"; ++gscCount; }
        }

        if (g_runtimeDiscoveryCancel.load())
            StatusPrintf("[MEMSCAN] Runtime scan cancelled: regions=%llu bytes=0x%llX unique=%zu verified_dvars=%zu possible_dvars=%zu labels=%zu rejected=%zu gsc=%zu.\n",
                regions, bytesRead, hits.size(), dvarCount, possibleCount, labelCount, rejectedCount, gscCount);
        else
            StatusPrintf("[MEMSCAN] Runtime scan complete: regions=%llu bytes=0x%llX unique=%zu verified_dvars=%zu possible_dvars=%zu labels=%zu rejected=%zu gsc=%zu.\n",
                regions, bytesRead, hits.size(), dvarCount, possibleCount, labelCount, rejectedCount, gscCount);
        if (hits.size() > livePrinted)
            StatusPrintf("[MEMSCAN] CMD output limited to %u rows; all %zu results were dumped.\n", livePrinted, hits.size());
        StatusPrintf("[MEMSCAN] Output: %s\\runtime_strings.csv\n", directory.c_str());
        StatusPrintf("[MEMSCAN] Pointer-verified dvars: %s\\verified_dvars.csv\n", directory.c_str());
        StatusPrintf("[MEMSCAN] Native-output dvars:   %s\\verified_native_dvars.csv\n", directory.c_str());
        StatusPrintf("[MEMSCAN] Verified commands:     %s\\verified_commands.csv\n", directory.c_str());
        StatusPrintf("[MEMSCAN] Possible dvars: %s\\possible_dvars.csv\n", directory.c_str());
        StatusPrintf("[MEMSCAN] Labels:         %s\\labels.txt\n", directory.c_str());
        StatusPrintf("[MEMSCAN] Rejected:       %s\\rejected_candidates.txt\n", directory.c_str());
        StatusPrintf("[MEMSCAN] GSC:            %s\\gsc_scripts.txt\n", directory.c_str());
        if (RuntimeDiscoveryLower(request->mode) == "dvar" || RuntimeDiscoveryLower(request->mode) == "dvars")
            StatusPrintf("[MEMSCAN] Persistent knowledge: logs\\dvar_knowledge.csv (%zu records).\n", knowledge.size());
        g_runtimeDiscoveryRunning.store(false);
        return 0;
    }

    static void PrintRuntimeDiscoveryStatus()
    {
        StatusPrintf("[MEMSCAN] status=%s regions=%llu bytes=0x%llX hits=%llu cancel=%s\n",
            g_runtimeDiscoveryRunning.load() ? "running" : "idle",
            g_runtimeDiscoveryRegions.load(),
            g_runtimeDiscoveryBytes.load(),
            g_runtimeDiscoveryHits.load(),
            g_runtimeDiscoveryCancel.load() ? "requested" : "no");

        std::lock_guard<std::mutex> lock(g_runtimeDiscoveryResultMutex);
        if (!g_runtimeDiscoveryLatestDirectory.empty())
            StatusPrintf("[MEMSCAN] latest mode=%s results=%zu output=%s\n",
                g_runtimeDiscoveryLatestMode.c_str(), g_runtimeDiscoveryLatestHits.size(),
                g_runtimeDiscoveryLatestDirectory.c_str());
    }

    static void StopRuntimeDiscovery()
    {
        if (!g_runtimeDiscoveryRunning.load())
        {
            StatusPrintf("[MEMSCAN] No runtime scan is currently running.\n");
            return;
        }
        g_runtimeDiscoveryCancel.store(true);
        StatusPrintf("[MEMSCAN] Cancellation requested. The current memory block will finish first.\n");
    }

    static void SaveLatestRuntimeDiscovery()
    {
        std::vector<RuntimeDiscoveryHit> hits;
        std::string mode;
        {
            std::lock_guard<std::mutex> lock(g_runtimeDiscoveryResultMutex);
            hits = g_runtimeDiscoveryLatestHits;
            mode = g_runtimeDiscoveryLatestMode;
        }

        if (hits.empty())
        {
            StatusPrintf("[MEMSCAN] No completed or cancelled runtime scan results are available to save.\n");
            return;
        }

        const std::string directory = RuntimeDiscoveryDirectory();
        RuntimeDiscoveryWriteCsv(directory + "\\runtime_strings.csv", hits);
        std::ofstream dvars(directory + "\\verified_dvars.csv", std::ios::trunc);
        std::ofstream labels(directory + "\\labels.txt", std::ios::trunc);
        std::ofstream nativeDvars(directory + "\\verified_native_dvars.csv", std::ios::trunc);
        std::ofstream commands(directory + "\\verified_commands.csv", std::ios::trunc);
        std::ofstream possible(directory + "\\possible_dvars.csv", std::ios::trunc);
        std::ofstream rejected(directory + "\\rejected_candidates.txt", std::ios::trunc);
        std::ofstream gsc(directory + "\\gsc_scripts.txt", std::ios::trunc);
        if (dvars) dvars << "name,dvar_address,type,flags,value,string_address\n";
        if (possible) possible << "name,score,string_address,native_query_queued,scan_state\n";
        if (nativeDvars) nativeDvars << "name,string_address,scan_state,response\n";
        if (commands) commands << "name,string_address,scan_state,response\n";
        for (const auto& hit : hits)
        {
            if (hit.category == "verified_dvar" && dvars)
                dvars << "\"" << JsonEscape(hit.text) << "\",0x" << std::hex << std::uppercase
                    << hit.dvarAddress << std::dec << ",\"" << JsonEscape(hit.type) << "\",0x"
                    << std::hex << std::uppercase << hit.flags << std::dec << ",\""
                    << JsonEscape(hit.value) << "\",0x" << std::hex << std::uppercase << hit.address
                    << std::dec << "\n";
            else if (hit.category == "verified_native_dvar" && nativeDvars)
                nativeDvars << "\"" << JsonEscape(hit.text) << "\",0x" << std::hex << std::uppercase
                    << hit.address << std::dec << ",\"" << JsonEscape(hit.scanState) << "\",\""
                    << JsonEscape(hit.nativeResponse) << "\"\n";
            else if (hit.category == "verified_command" && commands)
                commands << "\"" << JsonEscape(hit.text) << "\",0x" << std::hex << std::uppercase
                    << hit.address << std::dec << ",\"" << JsonEscape(hit.scanState) << "\",\""
                    << JsonEscape(hit.nativeResponse) << "\"\n";
            else if (hit.category == "possible_dvar" && possible)
                possible << "\"" << JsonEscape(hit.text) << "\"," << hit.score << ",0x"
                    << std::hex << std::uppercase << hit.address << std::dec << ','
                    << (hit.nativeQueryQueued ? 1 : 0) << ",\"" << JsonEscape(hit.scanState) << "\"\n";
            else if (hit.category == "label" && labels) labels << hit.text << "\n";
            else if (hit.category == "rejected_candidate" && rejected) rejected << hit.text << "\n";
            else if (hit.category == "gsc" && gsc) gsc << hit.text << "\n";
        }
        StatusPrintf("[MEMSCAN] Saved %zu latest %s result(s) to %s.\n",
            hits.size(), mode.empty() ? "runtime" : mode.c_str(), directory.c_str());
    }

    static bool StartRuntimeDiscovery(const std::string& mode, const std::string& query)
    {
        if (g_runtimeDiscoveryRunning.exchange(true))
        {
            StatusPrintf("[MEMSCAN] A runtime discovery scan is already running.\n");
            return false;
        }
        auto* request = new (std::nothrow) RuntimeDiscoveryRequest{};
        if (!request)
        {
            g_runtimeDiscoveryRunning.store(false);
            StatusPrintf("[MEMSCAN] Could not allocate scan request.\n");
            return false;
        }
        g_runtimeDiscoveryCancel.store(false);
        request->mode = mode;
        request->query = query;
        HANDLE thread = CreateThread(nullptr, 0, RuntimeDiscoveryThread, request, 0, nullptr);
        if (!thread)
        {
            delete request;
            g_runtimeDiscoveryRunning.store(false);
            StatusPrintf("[MEMSCAN] Could not create scan thread (error %lu).\n", GetLastError());
            return false;
        }
        CloseHandle(thread);
        return true;
    }
}

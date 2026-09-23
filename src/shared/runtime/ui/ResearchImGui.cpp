#include "../console/T9ConsoleCommandSuggestions.h"
#ifndef WIN32_LEAN_AND_MEAN
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#endif
#ifndef NOMINMAX
#ifndef NOMINMAX
#define NOMINMAX
#endif
#endif

#include "ResearchImGui.h"
#include "ClientServices.h"
#include "../../diagnostics/ResearchCatalog.h"
#include "../../diagnostics/CommandDiscovery.h"
#include "../../features/OfflineFeatures.h"
#include "../PointerRegistry.h"
#include "../RuntimeStageManager.h"
#include "../../features/content/ContentManager.h"

#include <Windows.h>
#include <algorithm>
#include <array>
#include <atomic>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iterator>
#include <mutex>
#include <sstream>
#include <string>
#include <vector>

#if __has_include(<imgui.h>)
#include "../../../../third_party/imgui/imgui.h"
#define T9_HAS_IMGUI 1
#else
#define T9_HAS_IMGUI 0
#endif

namespace research_imgui
{
    namespace
    {
        std::atomic_bool g_visible{ false };
        std::atomic_bool g_consoleVisible{ false };
        std::atomic_bool g_serverBrowserVisible{ false };
        std::atomic_bool g_chatInputVisible{ false };
        std::atomic_bool g_backendReady{ false };
        std::atomic_bool g_consoleNeedsFocus{ false };
        std::atomic_bool g_chatNeedsFocus{ false };
        CommandExecutor g_commandExecutor = nullptr;
        std::mutex g_commandMutex;
        std::vector<std::string> g_commandHistory;
        std::vector<std::string> g_consoleLines{ "T9 Client console initialized." };
        std::string g_commandStatus = "Command backend not configured.";

#if T9_HAS_IMGUI
        float g_windowAlpha = 0.94f;
        float g_uiScale = 1.0f;
        bool g_captureInput = true;
        bool g_autoScrollLogs = true;
        char g_commandInput[512]{};
        char g_consoleInput[1024]{};
        char g_chatInput[256]{};
        char g_chatNickname[64] = "Revampedplayer";
        char g_serverFilter[128]{};
        char g_serverName[96] = "T9 Local Match";
        int g_selectedServer = -1;
        int g_consoleHistoryIndex = -1;
        bool g_consoleAutoScroll = true;
        char g_catalogFilter[160]{};
        char g_watchAddress[32]{};
        int g_watchBytes = 8;
        ULONGLONG g_lastLogRefresh = 0;
        std::string g_logTail;
        std::string g_lastCatalogFilter;
        std::vector<research_catalog::Entry> g_catalogResults;

        struct WatchEntry
        {
            uintptr_t address{};
            int bytes{ 8 };
            std::string label;
        };
        std::vector<WatchEntry> g_watches;

        bool SafeRead(uintptr_t address, void* output, size_t size)
        {
            if (!address || !output || size == 0)
                return false;
            SIZE_T read = 0;
            return ReadProcessMemory(GetCurrentProcess(), reinterpret_cast<const void*>(address), output, size, &read) != FALSE && read == size;
        }

        std::string HexValue(uintptr_t address, int bytes)
        {
            std::array<unsigned char, 16> data{};
            bytes = std::clamp(bytes, 1, static_cast<int>(data.size()));
            if (!SafeRead(address, data.data(), static_cast<size_t>(bytes)))
                return "<unreadable>";
            char buffer[128]{};
            std::string out;
            for (int i = 0; i < bytes; ++i)
            {
                std::snprintf(buffer, sizeof(buffer), "%02X", data[static_cast<size_t>(i)]);
                if (!out.empty()) out.push_back(' ');
                out += buffer;
            }
            return out;
        }

        std::string ExecutableDirectory()
        {
            char path[MAX_PATH]{};
            GetModuleFileNameA(nullptr, path, MAX_PATH);
            char* slash = std::strrchr(path, '\\');
            if (slash) *slash = '\0';
            return path;
        }

        void RefreshLogTail()
        {
            const ULONGLONG now = GetTickCount64();
            if (now - g_lastLogRefresh < 500)
                return;
            g_lastLogRefresh = now;

            const std::string logDir = ExecutableDirectory() + "\\logs";
            WIN32_FIND_DATAA findData{};
            HANDLE find = FindFirstFileA((logDir + "\\memory_scanner_*.log").c_str(), &findData);
            if (find == INVALID_HANDLE_VALUE)
            {
                g_logTail = "No memory_scanner log found yet.";
                return;
            }

            std::string newest;
            FILETIME newestTime{};
            do
            {
                if (!(findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) &&
                    CompareFileTime(&findData.ftLastWriteTime, &newestTime) > 0)
                {
                    newestTime = findData.ftLastWriteTime;
                    newest = logDir + "\\" + findData.cFileName;
                }
            } while (FindNextFileA(find, &findData));
            FindClose(find);

            if (newest.empty())
                return;

            std::ifstream stream(newest, std::ios::binary);
            if (!stream)
                return;
            stream.seekg(0, std::ios::end);
            const std::streamoff length = stream.tellg();
            const std::streamoff tail = std::min<std::streamoff>(length, 96 * 1024);
            stream.seekg(length - tail, std::ios::beg);
            g_logTail.assign(std::istreambuf_iterator<char>(stream), std::istreambuf_iterator<char>());
        }

        void AppendConsoleLine(const std::string& text)
        {
            g_consoleLines.push_back(text);
            if (g_consoleLines.size() > 800)
                g_consoleLines.erase(g_consoleLines.begin(), g_consoleLines.begin() + 200);
        }

        bool ExecuteCommandText(const char* text)
        {
            if (!text || !*text)
                return false;

            std::string visibleCommand = text;
            while (!visibleCommand.empty() &&
                (visibleCommand.back() == '\r' || visibleCommand.back() == '\n' || visibleCommand.back() == ' '))
                visibleCommand.pop_back();

            if (visibleCommand.empty() || visibleCommand.front() != '/')
            {
                g_commandStatus = "Commands must begin with /. Example: /map_restart";
                AppendConsoleLine("Error: " + g_commandStatus);
                return false;
            }

            if (visibleCommand.size() == 1)
            {
                g_commandStatus = "Missing command after /.";
                AppendConsoleLine("Error: " + g_commandStatus);
                return false;
            }

            std::lock_guard<std::mutex> lock(g_commandMutex);
            if (!g_commandExecutor)
            {
                g_commandStatus = "Command backend is unresolved.";
                return false;
            }

            AppendConsoleLine(std::string("] ") + visibleCommand);
            const bool ok = g_commandExecutor(visibleCommand.c_str());
            g_commandStatus = ok ? std::string("Queued: ") + visibleCommand : std::string("Failed: ") + visibleCommand;
            AppendConsoleLine(g_commandStatus);
            if (ok)
            {
                g_commandHistory.emplace_back(visibleCommand);
                if (g_commandHistory.size() > 100)
                    g_commandHistory.erase(g_commandHistory.begin());
            }
            return ok;
        }

        void RenderOverview()
        {
            const auto pointers = pointer_registry::Get();
            ImGui::Text("Build: %s", research_catalog::BuildFingerprint().c_str());
            ImGui::Text("Catalog: %zu entries | Resolver: %zu validated", research_catalog::EntryCount(), research_catalog::ResolvedCount());
            ImGui::Separator();

            if (ImGui::BeginTable("runtime_state", 3, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_Resizable))
            {
                ImGui::TableSetupColumn("Runtime item");
                ImGui::TableSetupColumn("Address");
                ImGui::TableSetupColumn("Live value");
                ImGui::TableHeadersRow();

                struct Item { const char* name; uintptr_t address; int bytes; };
                const Item items[] = {
                    {"s_uiScreen", pointers.uiScreen, 4},
                    {"s_networkMode", pointers.networkMode, 4},
                    {"sSessionModeState", pointers.sessionMode, 4},
                    {"s_inited", pointers.initialized, 1},
                    {"Command buffer", pointers.commandBuffer, 8},
                    {"Dvar_FindVar", pointers.dvarFind, 8},
                    {"Console font", pointers.font, 8}
                };
                for (const auto& item : items)
                {
                    ImGui::TableNextRow();
                    ImGui::TableSetColumnIndex(0); ImGui::TextUnformatted(item.name);
                    ImGui::TableSetColumnIndex(1); ImGui::Text("0x%llX", static_cast<unsigned long long>(item.address));
                    ImGui::TableSetColumnIndex(2);
                    if (item.name == std::string("Command buffer") || item.name == std::string("Dvar_FindVar") || item.name == std::string("Console font"))
                        ImGui::TextUnformatted(item.address ? "resolved" : "missing");
                    else
                        ImGui::TextUnformatted(HexValue(item.address, item.bytes).c_str());
                }
                ImGui::EndTable();
            }

            ImGui::SeparatorText("Offline local-match features");
            for (const auto& feature : offline_features::Snapshot())
            {
                bool value = feature.enabled;
                ImGui::BeginDisabled(!feature.available);
                if (ImGui::Checkbox(feature.name, &value))
                    offline_features::Set(feature.id, value);
                ImGui::EndDisabled();
                ImGui::SameLine(260.0f);
                ImGui::TextDisabled("%s", feature.reason.c_str());
            }
            ImGui::TextDisabled("These buttons queue native developer commands. They do not patch player memory.");
        }

        void RenderResolver()
        {
            if (ImGui::Button("Resolve all")) research_catalog::ResolveAll();
            ImGui::SameLine();
            if (ImGui::Button("Revalidate")) research_catalog::Revalidate();
            ImGui::SameLine();
            if (ImGui::Button("Write reports")) research_catalog::WriteReports();

            if (ImGui::BeginTable("resolver_table", 5,
                ImGuiTableFlags_RowBg | ImGuiTableFlags_Borders | ImGuiTableFlags_ScrollY |
                ImGuiTableFlags_Resizable | ImGuiTableFlags_SizingStretchProp, ImVec2(0, 0)))
            {
                ImGui::TableSetupColumn("Name");
                ImGui::TableSetupColumn("Value");
                ImGui::TableSetupColumn("Kind");
                ImGui::TableSetupColumn("Valid");
                ImGui::TableSetupColumn("Status");
                ImGui::TableHeadersRow();
                for (const auto& pattern : research_catalog::PatternSnapshot())
                {
                    ImGui::TableNextRow();
                    ImGui::TableSetColumnIndex(0); ImGui::TextUnformatted(pattern.name);
                    ImGui::TableSetColumnIndex(1); ImGui::Text("0x%llX", static_cast<unsigned long long>(pattern.resolvedAddress));
                    ImGui::TableSetColumnIndex(2); ImGui::TextUnformatted(pattern.scalarValue ? "scalar offset" : "code address");
                    ImGui::TableSetColumnIndex(3); ImGui::TextColored(pattern.unique ? ImVec4(0.25f, 0.9f, 0.35f, 1.0f) : ImVec4(0.95f, 0.35f, 0.25f, 1.0f), pattern.unique ? "yes" : "no");
                    ImGui::TableSetColumnIndex(4); ImGui::TextUnformatted(pattern.status.c_str());
                }
                ImGui::EndTable();
            }
        }

        void RenderCatalog()
        {
            ImGui::SetNextItemWidth(420.0f);
            ImGui::InputTextWithHint("##catalog_filter", "Search PlayerCmd, GScr, map, lobby...", g_catalogFilter, sizeof(g_catalogFilter));
            if (ImGui::BeginTable("catalog_table", 6,
                ImGuiTableFlags_RowBg | ImGuiTableFlags_Borders | ImGuiTableFlags_ScrollY |
                ImGuiTableFlags_Resizable | ImGuiTableFlags_SizingStretchProp, ImVec2(0, 0)))
            {
                ImGui::TableSetupColumn("Name");
                ImGui::TableSetupColumn("Reference RVA");
                ImGui::TableSetupColumn("Current VA");
                ImGui::TableSetupColumn("Subsystem");
                ImGui::TableSetupColumn("Current build");
                ImGui::TableSetupColumn("Source");
                ImGui::TableHeadersRow();
                const std::string currentFilter = g_catalogFilter;
                if (currentFilter != g_lastCatalogFilter || g_catalogResults.empty())
                {
                    g_lastCatalogFilter = currentFilter;
                    g_catalogResults = research_catalog::Search(currentFilter, 10000);
                }

                ImGuiListClipper clipper;
                clipper.Begin(static_cast<int>(g_catalogResults.size()));
                while (clipper.Step())
                {
                    for (int row = clipper.DisplayStart; row < clipper.DisplayEnd; ++row)
                    {
                        const auto& item = g_catalogResults[static_cast<size_t>(row)];
                        ImGui::TableNextRow();
                        ImGui::TableSetColumnIndex(0); ImGui::TextUnformatted(item.name);
                        ImGui::TableSetColumnIndex(1); ImGui::Text("0x%llX", static_cast<unsigned long long>(item.referenceRva));
                        ImGui::TableSetColumnIndex(2); ImGui::Text("0x%llX", static_cast<unsigned long long>(item.runtimeAddress));
                        ImGui::TableSetColumnIndex(3); ImGui::TextUnformatted(item.subsystem);
                        ImGui::TableSetColumnIndex(4); ImGui::TextUnformatted(item.currentBuildCandidate ? "candidate" : "reference only");
                        ImGui::TableSetColumnIndex(5); ImGui::TextUnformatted(item.source);
                    }
                }
                ImGui::EndTable();
            }
        }

        void RenderCommands()
        {
            ImGui::TextWrapped("Commands are queued through the currently resolved native command-buffer path. A newline is appended automatically.");
            ImGui::SetNextItemWidth(-90.0f);
            const bool enter = ImGui::InputTextWithHint("##command", "/map_restart, /disconnect, /noclip...", g_commandInput, sizeof(g_commandInput), ImGuiInputTextFlags_EnterReturnsTrue);
            ImGui::SameLine();
            if ((ImGui::Button("Execute") || enter) && g_commandInput[0])
            {
                ExecuteCommandText(g_commandInput);
                g_commandInput[0] = '\0';
                ImGui::SetKeyboardFocusHere(-1);
            }
            ImGui::TextWrapped("%s", g_commandStatus.c_str());

            static const char* quick[] = { "/map_restart", "/disconnect", "/noclip", "/god", "/ufo", "/notarget" };
            for (const char* command : quick)
            {
                if (ImGui::SmallButton(command)) ExecuteCommandText(command);
                ImGui::SameLine();
            }
            ImGui::NewLine();
            ImGui::SeparatorText("History");
            ImGui::BeginChild("command_history", ImVec2(0, 0), true);
            for (const auto& command : g_commandHistory)
            {
                if (ImGui::Selectable(command.c_str()))
                    std::snprintf(g_commandInput, sizeof(g_commandInput), "%s", command.c_str());
            }
            ImGui::EndChild();
        }

        void RenderMemory()
        {
            const auto pointers = pointer_registry::Get();
            if (g_watches.empty())
            {
                if (pointers.uiScreen) g_watches.push_back({ pointers.uiScreen, 4, "s_uiScreen" });
                if (pointers.networkMode) g_watches.push_back({ pointers.networkMode, 4, "s_networkMode" });
                if (pointers.sessionMode) g_watches.push_back({ pointers.sessionMode, 4, "sSessionModeState" });
                if (pointers.initialized) g_watches.push_back({ pointers.initialized, 1, "s_inited" });
            }

            ImGui::SetNextItemWidth(210.0f);
            ImGui::InputTextWithHint("##watch_addr", "Address, e.g. 7FF6...", g_watchAddress, sizeof(g_watchAddress), ImGuiInputTextFlags_CharsHexadecimal);
            ImGui::SameLine();
            ImGui::SetNextItemWidth(90.0f);
            ImGui::SliderInt("Bytes", &g_watchBytes, 1, 16);
            ImGui::SameLine();
            if (ImGui::Button("Add watch") && g_watchAddress[0])
            {
                const uintptr_t address = static_cast<uintptr_t>(std::strtoull(g_watchAddress, nullptr, 16));
                if (address) g_watches.push_back({ address, g_watchBytes, "custom" });
                g_watchAddress[0] = '\0';
            }

            if (ImGui::BeginTable("watch_table", 4, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_Resizable))
            {
                ImGui::TableSetupColumn("Label");
                ImGui::TableSetupColumn("Address");
                ImGui::TableSetupColumn("Bytes");
                ImGui::TableSetupColumn("Live value");
                ImGui::TableHeadersRow();
                for (size_t i = 0; i < g_watches.size(); ++i)
                {
                    auto& watch = g_watches[i];
                    ImGui::TableNextRow();
                    ImGui::TableSetColumnIndex(0); ImGui::TextUnformatted(watch.label.c_str());
                    ImGui::TableSetColumnIndex(1); ImGui::Text("0x%llX", static_cast<unsigned long long>(watch.address));
                    ImGui::TableSetColumnIndex(2); ImGui::Text("%d", watch.bytes);
                    ImGui::TableSetColumnIndex(3); ImGui::TextUnformatted(HexValue(watch.address, watch.bytes).c_str());
                }
                ImGui::EndTable();
            }
            if (ImGui::Button("Clear custom watches"))
                g_watches.clear();
        }

        void RenderModules()
        {
            if (ImGui::Button("Refresh modules")) content_manager::Refresh();
            const auto modules = content_manager::Modules();
            if (ImGui::BeginTable("modules", 3, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY | ImGuiTableFlags_Resizable, ImVec2(0, 0)))
            {
                ImGui::TableSetupColumn("Module");
                ImGui::TableSetupColumn("Base");
                ImGui::TableSetupColumn("Size");
                ImGui::TableHeadersRow();
                for (const auto& module : modules)
                {
                    ImGui::TableNextRow();
                    ImGui::TableSetColumnIndex(0); ImGui::Text("%ls", module.name.c_str());
                    ImGui::TableSetColumnIndex(1); ImGui::Text("0x%llX", static_cast<unsigned long long>(module.base));
                    ImGui::TableSetColumnIndex(2); ImGui::Text("0x%lX", module.size);
                }
                ImGui::EndTable();
            }
        }

        void RenderLogs()
        {
            RefreshLogTail();
            ImGui::Checkbox("Auto-scroll", &g_autoScrollLogs);
            ImGui::SameLine();
            if (ImGui::Button("Refresh now")) g_lastLogRefresh = 0;
            ImGui::BeginChild("log_tail", ImVec2(0, 0), true, ImGuiWindowFlags_HorizontalScrollbar);
            ImGui::TextUnformatted(g_logTail.c_str());
            if (g_autoScrollLogs && ImGui::GetScrollY() >= ImGui::GetScrollMaxY() - 10.0f)
                ImGui::SetScrollHereY(1.0f);
            ImGui::EndChild();
        }

        std::vector<std::string> CommandSuggestions(const char* input)
        {
            if (!input || !*input) return {};
            return command_discovery::Suggestions(input, 8);
        }

        void RenderCommandDiscovery()
        {
            static char filter[128]{};
            if (ImGui::Button("Refresh live dvars")) { command_discovery::Refresh(); command_discovery::WriteReports(); }
            ImGui::SameLine(); ImGui::InputTextWithHint("##discovery_filter", "cg_fov, sv_, map...", filter, sizeof(filter));
            const auto dvars = command_discovery::Dvars(filter);
            ImGui::Text("Live candidates: %zu", dvars.size());
            if (ImGui::BeginTable("dvar_discovery", 6, ImGuiTableFlags_Borders|ImGuiTableFlags_RowBg|ImGuiTableFlags_ScrollY, ImVec2(0,260)))
            {
                ImGui::TableSetupColumn("Name"); ImGui::TableSetupColumn("Live"); ImGui::TableSetupColumn("Type"); ImGui::TableSetupColumn("Value"); ImGui::TableSetupColumn("Flags"); ImGui::TableSetupColumn("Address"); ImGui::TableHeadersRow();
                for (const auto& e : dvars) { ImGui::TableNextRow(); ImGui::TableSetColumnIndex(0); ImGui::TextUnformatted(e.name.c_str()); ImGui::TableSetColumnIndex(1); ImGui::TextColored(e.live?ImVec4(0.2f,1,0.2f,1):ImVec4(.7f,.7f,.7f,1), e.live?"yes":"no"); ImGui::TableSetColumnIndex(2); ImGui::TextUnformatted(e.type.c_str()); ImGui::TableSetColumnIndex(3); ImGui::TextUnformatted(e.value.c_str()); ImGui::TableSetColumnIndex(4); ImGui::Text("0x%X",e.flags); ImGui::TableSetColumnIndex(5); ImGui::Text("0x%llX",(unsigned long long)e.address); }
                ImGui::EndTable();
            }
            ImGui::SeparatorText("Known command candidates");
            for (const auto& c : command_discovery::Commands(filter)) ImGui::BulletText("%s", c.c_str());
        }

        int ConsoleInputCallback(ImGuiInputTextCallbackData* data)
        {
            if (!data)
                return 0;

            if (data->EventFlag == ImGuiInputTextFlags_CallbackCompletion)
            {
                const std::string current(data->Buf, static_cast<size_t>(data->BufTextLen));
                const auto matches = command_discovery::Suggestions(current, 1);
                if (!matches.empty())
                {
                    data->DeleteChars(0, data->BufTextLen);
                    data->InsertChars(0, matches.front().c_str());
                    data->SelectionStart = data->SelectionEnd = data->CursorPos = data->BufTextLen;
                }
                return 0;
            }

            if (data->EventFlag == ImGuiInputTextFlags_CallbackHistory && !g_commandHistory.empty())
            {
                if (data->EventKey == ImGuiKey_UpArrow)
                {
                    if (g_consoleHistoryIndex < 0)
                        g_consoleHistoryIndex = static_cast<int>(g_commandHistory.size()) - 1;
                    else if (g_consoleHistoryIndex > 0)
                        --g_consoleHistoryIndex;
                }
                else if (data->EventKey == ImGuiKey_DownArrow)
                {
                    if (g_consoleHistoryIndex >= 0 && g_consoleHistoryIndex + 1 < static_cast<int>(g_commandHistory.size()))
                        ++g_consoleHistoryIndex;
                    else
                        g_consoleHistoryIndex = -1;
                }

                data->DeleteChars(0, data->BufTextLen);
                if (g_consoleHistoryIndex >= 0)
                    data->InsertChars(0, g_commandHistory[static_cast<size_t>(g_consoleHistoryIndex)].c_str());
            }
            return 0;
        }

        void RenderWatermark()
        {
            const ImGuiViewport* viewport = ImGui::GetMainViewport();
            if (!viewport)
                return;

            const char* label = "T9 CLIENT";
            const ImVec2 textSize = ImGui::CalcTextSize(label);
            const ImVec2 pos(viewport->WorkPos.x + viewport->WorkSize.x - textSize.x - 12.0f,
                viewport->WorkPos.y + 6.0f);
            ImGui::SetNextWindowPos(pos, ImGuiCond_Always);
            ImGui::SetNextWindowBgAlpha(0.0f);
            ImGui::SetNextWindowSize(ImVec2(textSize.x + 8.0f, textSize.y + 6.0f), ImGuiCond_Always);
            const ImGuiWindowFlags flags = ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoInputs |
                ImGuiWindowFlags_NoNav | ImGuiWindowFlags_NoSavedSettings | ImGuiWindowFlags_NoBackground;
            ImGui::Begin("##t9_client_watermark", nullptr, flags);
            ImGui::TextColored(ImVec4(0.72f, 0.72f, 0.72f, 0.70f), "%s", label);
            ImGui::End();
        }

        void RenderTraditionalConsole()
        {
            if (!g_consoleVisible.load())
                return;

            const ImGuiViewport* viewport = ImGui::GetMainViewport();
            if (!viewport)
                return;

            const auto suggestions = CommandSuggestions(g_consoleInput);
            const float barHeight = 30.0f;
            const float suggestionHeight = suggestions.empty() ? 0.0f : (8.0f + suggestions.size() * 21.0f);
            const ImVec2 pos(viewport->WorkPos.x + 7.0f, viewport->WorkPos.y + 7.0f);
            const ImVec2 size(viewport->WorkSize.x - 14.0f, barHeight + suggestionHeight);

            ImGui::SetNextWindowPos(pos, ImGuiCond_Always);
            ImGui::SetNextWindowSize(size, ImGuiCond_Always);
            ImGui::SetNextWindowBgAlpha(0.0f);

            ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 0.0f);
            ImGui::PushStyleVar(ImGuiStyleVar_WindowBorderSize, 0.0f);
            ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(0.0f, 0.0f));
            const ImGuiWindowFlags flags = ImGuiWindowFlags_NoTitleBar |
                ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoResize |
                ImGuiWindowFlags_NoSavedSettings | ImGuiWindowFlags_NoCollapse |
                ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse |
                ImGuiWindowFlags_NoBackground;

            if (ImGui::Begin("##t9_client_command_bar", nullptr, flags))
            {
                ImDrawList* draw = ImGui::GetWindowDrawList();
                const ImVec2 barMin = ImGui::GetWindowPos();
                const ImVec2 barMax(barMin.x + viewport->WorkSize.x - 14.0f, barMin.y + barHeight);
                draw->AddRectFilled(barMin, barMax, IM_COL32(25, 26, 28, 245));
                draw->AddRect(barMin, barMax, IM_COL32(65, 65, 65, 230));

                const char* prompt = "T9 Client r001 >";
                const float promptWidth = ImGui::CalcTextSize(prompt).x;
                const float rightLabelWidth = ImGui::CalcTextSize("T9 CLIENT").x;
                draw->AddText(ImVec2(barMin.x + 8.0f, barMin.y + 7.0f),
                    IM_COL32(235, 145, 42, 255), prompt);

                ImGui::SetCursorPos(ImVec2(promptWidth + 16.0f, 4.0f));
                const float inputWidth = size.x - promptWidth - rightLabelWidth - 38.0f;
                ImGui::SetNextItemWidth(inputWidth > 100.0f ? inputWidth : 100.0f);

                if (g_consoleNeedsFocus.exchange(false))
                    ImGui::SetKeyboardFocusHere();

                ImGui::PushStyleColor(ImGuiCol_Text, IM_COL32(235, 145, 42, 255));
                ImGui::PushStyleColor(ImGuiCol_FrameBg, IM_COL32(0, 0, 0, 0));
                ImGui::PushStyleColor(ImGuiCol_FrameBgHovered, IM_COL32(0, 0, 0, 0));
                ImGui::PushStyleColor(ImGuiCol_FrameBgActive, IM_COL32(0, 0, 0, 0));
                const ImGuiInputTextFlags inputFlags = ImGuiInputTextFlags_EnterReturnsTrue |
                    ImGuiInputTextFlags_CallbackHistory |
                    ImGuiInputTextFlags_CallbackCompletion;
                if (ImGui::InputText("##t9_command_bar_input", g_consoleInput,
                    sizeof(g_consoleInput), inputFlags, &ConsoleInputCallback))
                {
                    if (g_consoleInput[0])
                        ExecuteCommandText(g_consoleInput);
                    g_consoleInput[0] = '\0';
                    g_consoleHistoryIndex = -1;
                    g_consoleNeedsFocus.store(true);
                }
                ImGui::PopStyleColor(4);

                if (!suggestions.empty())
                {
                    ImGui::SetCursorPos(ImVec2(7.0f, barHeight + 3.0f));
                    ImGui::PushStyleColor(ImGuiCol_ChildBg, IM_COL32(20, 21, 23, 238));
                    ImGui::BeginChild("##command_suggestions", ImVec2(inputWidth, suggestionHeight - 3.0f), true,
                        ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse);
                    for (const auto& suggestion : suggestions)
                    {
                        if (ImGui::Selectable(suggestion.c_str(), false))
                        {
                            strncpy_s(g_consoleInput, sizeof(g_consoleInput), suggestion.c_str(), _TRUNCATE);
                            g_consoleNeedsFocus.store(true);
                        }
                    }
                    ImGui::EndChild();
                    ImGui::PopStyleColor();
                }
            }
            ImGui::End();
            ImGui::PopStyleVar(3);
        }

        void RenderChatOverlay()
        {
            const auto messages = client_services::ChatMessages();
            const ImGuiViewport* viewport = ImGui::GetMainViewport();
            if (!viewport)
                return;

            // Minimal side chat: transparent, fixed in the left-center, with only
            // the text box becoming interactive when T is pressed. While typing,
            // the backend captures all game input so clicks and movement cannot
            // leak into the game.
            const float width = std::clamp(viewport->WorkSize.x * 0.34f, 430.0f, 680.0f);
            const float height = 255.0f;
            const ImVec2 pos(viewport->WorkPos.x + 22.0f,
                viewport->WorkPos.y + viewport->WorkSize.y * 0.50f - height * 0.5f);

            ImGui::SetNextWindowPos(pos, ImGuiCond_Always);
            ImGui::SetNextWindowSize(ImVec2(width, height), ImGuiCond_Always);
            ImGui::SetNextWindowBgAlpha(0.0f);

            ImGuiWindowFlags flags = ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoMove |
                ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoSavedSettings |
                ImGuiWindowFlags_NoNav | ImGuiWindowFlags_NoBackground;
            if (!g_chatInputVisible.load())
                flags |= ImGuiWindowFlags_NoInputs;

            ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(0.0f, 0.0f));
            if (ImGui::Begin("##t9_text_chat", nullptr, flags))
            {
                const bool typing = g_chatInputVisible.load();
                ImGui::BeginChild("##chat_messages", ImVec2(0, typing ? -30.0f : 0.0f),
                    false, ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse |
                    ImGuiWindowFlags_NoBackground);
                const std::uint64_t now = static_cast<std::uint64_t>(GetTickCount64());
                const std::size_t start = messages.size() > 10 ? messages.size() - 10 : 0;
                ImGui::SetWindowFontScale(1.18f);
                for (std::size_t i = start; i < messages.size(); ++i)
                {
                    const auto& message = messages[i];
                    if (!typing && now - message.receivedMs > 9000)
                        continue;

                    const std::uint64_t age = now > message.receivedMs ? now - message.receivedMs : 0;
                    float fade = 1.0f;
                    if (!typing && age > 5500)
                        fade = std::clamp(1.0f - static_cast<float>(age - 5500) / 3500.0f, 0.0f, 1.0f);
                    const int alpha = static_cast<int>(255.0f * fade);
                    const ImVec2 textPos = ImGui::GetCursorScreenPos();
                    const std::string full = message.sender + ": " + message.text;
                    ImDrawList* draw = ImGui::GetWindowDrawList();
                    draw->AddText(ImVec2(textPos.x - 1.0f, textPos.y), IM_COL32(255, 255, 255, alpha), full.c_str());
                    draw->AddText(ImVec2(textPos.x + 1.0f, textPos.y), IM_COL32(255, 255, 255, alpha), full.c_str());
                    draw->AddText(ImVec2(textPos.x, textPos.y - 1.0f), IM_COL32(255, 255, 255, alpha), full.c_str());
                    draw->AddText(ImVec2(textPos.x, textPos.y + 1.0f), IM_COL32(255, 255, 255, alpha), full.c_str());
                    draw->AddText(textPos, IM_COL32(0, 0, 0, alpha), full.c_str());
                    ImGui::Dummy(ImVec2(0.0f, ImGui::GetTextLineHeightWithSpacing()));
                }
                ImGui::EndChild();

                if (typing)
                {
                    ImGui::PushStyleColor(ImGuiCol_Text, IM_COL32(0, 0, 0, 255));
                    ImGui::PushStyleColor(ImGuiCol_FrameBg, IM_COL32(255, 255, 255, 225));
                    ImGui::PushStyleColor(ImGuiCol_FrameBgHovered, IM_COL32(255, 255, 255, 240));
                    ImGui::PushStyleColor(ImGuiCol_FrameBgActive, IM_COL32(255, 255, 255, 255));
                    ImGui::SetNextItemWidth(-1.0f);
                    if (g_chatNeedsFocus.exchange(false))
                        ImGui::SetKeyboardFocusHere();
                    if (ImGui::InputTextWithHint("##chat_input", "Say...", g_chatInput,
                        sizeof(g_chatInput), ImGuiInputTextFlags_EnterReturnsTrue))
                    {
                        if (g_chatInput[0])
                            client_services::SendChat(g_chatInput);
                        g_chatInput[0] = '\0';
                        g_chatInputVisible.store(false);
                    }
                    ImGui::PopStyleColor(4);
                }
            }
            ImGui::End();
            ImGui::PopStyleVar();
        }

        void RenderServerBrowser()
        {
            if (!g_serverBrowserVisible.load())
                return;

            const ImGuiViewport* viewport = ImGui::GetMainViewport();
            if (!viewport)
                return;

            const float browserWidth = std::clamp(viewport->WorkSize.x * 0.58f, 720.0f, 980.0f);
            const float browserHeight = std::clamp(viewport->WorkSize.y * 0.62f, 470.0f, 680.0f);
            const ImVec2 browserPos(
                viewport->WorkPos.x + (viewport->WorkSize.x - browserWidth) * 0.5f,
                viewport->WorkPos.y + (viewport->WorkSize.y - browserHeight) * 0.5f);
            ImGui::SetNextWindowPos(browserPos, ImGuiCond_Always);
            ImGui::SetNextWindowSize(ImVec2(browserWidth, browserHeight), ImGuiCond_Always);
            ImGui::SetNextWindowBgAlpha(0.96f);

            const ImGuiWindowFlags flags = ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoMove |
                ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoSavedSettings;
            if (!ImGui::Begin("##t9_server_browser", nullptr, flags))
            {
                ImGui::End();
                return;
            }

            ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.02f, 0.42f, 0.95f, 1.0f));
            ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.08f, 0.52f, 1.0f, 1.0f));
            ImGui::SetWindowFontScale(1.0f);
            if (ImGui::Button("< SERVERS"))
                g_serverBrowserVisible.store(false);
            ImGui::SetWindowFontScale(1.0f);
            ImGui::SameLine();
            ImGui::SetNextItemWidth(-98.0f);
            ImGui::InputTextWithHint("##server_filter", "Search servers...", g_serverFilter, sizeof(g_serverFilter));
            ImGui::SameLine();
            if (ImGui::Button("REFRESH", ImVec2(84.0f, 0.0f)))
                client_services::RefreshServers();

            bool advertising = client_services::IsAdvertising();
            if (ImGui::Checkbox("Advertise this local match on LAN", &advertising))
                client_services::SetAdvertising(advertising);
            ImGui::SameLine();
            ImGui::SetNextItemWidth(190.0f);
            if (ImGui::InputText("Server name", g_serverName, sizeof(g_serverName)))
                client_services::SetAdvertisedServerName(g_serverName);

            const auto servers = client_services::Servers();
            const float rightWidth = 300.0f;
            ImGui::BeginChild("##server_list", ImVec2(-rightWidth - 12.0f, 0.0f), true);
            if (ImGui::BeginTable("##servers", 3, ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersInnerH |
                ImGuiTableFlags_SizingStretchProp | ImGuiTableFlags_ScrollY, ImVec2(0, 0)))
            {
                ImGui::TableSetupColumn("Hostname", ImGuiTableColumnFlags_WidthStretch);
                ImGui::TableSetupColumn("Players", ImGuiTableColumnFlags_WidthFixed, 80.0f);
                ImGui::TableSetupColumn("Ping", ImGuiTableColumnFlags_WidthFixed, 60.0f);
                ImGui::TableHeadersRow();
                for (int i = 0; i < static_cast<int>(servers.size()); ++i)
                {
                    const auto& server = servers[static_cast<std::size_t>(i)];
                    std::string lowerName = server.name;
                    std::string lowerFilter = g_serverFilter;
                    std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(), ::tolower);
                    std::transform(lowerFilter.begin(), lowerFilter.end(), lowerFilter.begin(), ::tolower);
                    if (!lowerFilter.empty() && lowerName.find(lowerFilter) == std::string::npos)
                        continue;

                    ImGui::TableNextRow();
                    ImGui::TableSetColumnIndex(0);
                    const bool selected = g_selectedServer == i;
                    std::string label = server.name + "##server_" + std::to_string(i);
                    if (ImGui::Selectable(label.c_str(), selected, ImGuiSelectableFlags_SpanAllColumns))
                        g_selectedServer = i;
                    ImGui::TextDisabled("%s - %s", server.map.c_str(), server.mode.c_str());
                    ImGui::TableSetColumnIndex(1);
                    ImGui::Text("%d / %d", server.players, server.maxPlayers);
                    ImGui::TableSetColumnIndex(2);
                    ImGui::Text("%d", server.pingMs);
                }
                ImGui::EndTable();
            }
            ImGui::EndChild();

            ImGui::SameLine();
            ImGui::BeginChild("##server_info", ImVec2(0, 0), true);
            ImGui::TextUnformatted("SERVER INFORMATION");
            ImGui::Separator();
            if (g_selectedServer >= 0 && g_selectedServer < static_cast<int>(servers.size()))
            {
                const auto& server = servers[static_cast<std::size_t>(g_selectedServer)];
                ImGui::Dummy(ImVec2(0, 25.0f));
                ImGui::SetWindowFontScale(1.12f);
                ImGui::TextWrapped("%s", server.name.c_str());
                ImGui::SetWindowFontScale(1.0f);
                ImGui::Text("%s", server.map.c_str());
                ImGui::Text("%s", server.mode.c_str());
                ImGui::Text("Players: %d/%d", server.players, server.maxPlayers);
                ImGui::Text("Address: %s", server.address.c_str());
                ImGui::Dummy(ImVec2(0, 20.0f));
                if (ImGui::Button("CONNECT", ImVec2(-1.0f, 34.0f)))
                {
                    const std::string command = "/connect " + server.address;
                    ExecuteCommandText(command.c_str());
                    g_serverBrowserVisible.store(false);
                }
                if (ImGui::Button("COPY IP", ImVec2(-1.0f, 30.0f)))
                    ImGui::SetClipboardText(server.address.c_str());
            }
            else
            {
                ImGui::TextWrapped("No LAN server selected. Press Refresh. Servers appear when another T9 Client instance advertises a local match.");
            }
            ImGui::EndChild();
            ImGui::PopStyleColor(2);
            ImGui::End();
        }


        void RenderRuntimeStages()
        {
            ImGui::TextUnformatted("Independent startup stages");
            ImGui::Separator();
            const auto stages = runtime_stages::Snapshot();
            if (ImGui::BeginTable("runtime_stages", 4,
                ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY,
                ImVec2(0.0f, -1.0f)))
            {
                ImGui::TableSetupColumn("Stage");
                ImGui::TableSetupColumn("State");
                ImGui::TableSetupColumn("Elapsed");
                ImGui::TableSetupColumn("Detail");
                ImGui::TableHeadersRow();
                for (const auto& stage : stages)
                {
                    ImGui::TableNextRow();
                    ImGui::TableSetColumnIndex(0); ImGui::TextUnformatted(stage.name.c_str());
                    ImGui::TableSetColumnIndex(1); ImGui::TextUnformatted(runtime_stages::ToString(stage.state));
                    ImGui::TableSetColumnIndex(2);
                    const unsigned long long elapsed = stage.finishedAtMs >= stage.startedAtMs
                        ? static_cast<unsigned long long>(stage.finishedAtMs - stage.startedAtMs) : 0ULL;
                    ImGui::Text("%llu ms", elapsed);
                    ImGui::TableSetColumnIndex(3); ImGui::TextUnformatted(stage.detail.c_str());
                }
                ImGui::EndTable();
            }
        }

        void RenderSettings()
        {
            ImGui::TextUnformatted("Menu hotkey: INSERT");
            ImGui::Checkbox("Capture all game mouse/keyboard input while open", &g_captureInput);
            ImGui::SliderFloat("Window transparency", &g_windowAlpha, 0.55f, 1.0f, "%.2f");
            if (ImGui::SliderFloat("UI scale", &g_uiScale, 0.75f, 1.75f, "%.2f"))
                ImGui::GetIO().FontGlobalScale = g_uiScale;
            ImGui::TextWrapped("Closing the menu restores the cursor state and returns input to the game. Heavy signature and module rescans are manual so gameplay is not interrupted by periodic background work.");
            if (ImGui::Button("Close menu")) g_visible.store(false);
        }
#endif
    }

    void SetVisible(bool visible) { g_visible.store(visible); if (visible) { g_consoleVisible.store(false); g_serverBrowserVisible.store(false); g_chatInputVisible.store(false); } }
    bool IsVisible() { return g_visible.load(); }
    void SetConsoleVisible(bool visible) { g_consoleVisible.store(visible); if (visible) { g_consoleInput[0] = '\0'; g_consoleNeedsFocus.store(true); g_visible.store(false); g_serverBrowserVisible.store(false); g_chatInputVisible.store(false); } }
    bool IsConsoleVisible() { return g_consoleVisible.load(); }
    void SetServerBrowserVisible(bool visible) { g_serverBrowserVisible.store(visible); if (visible) { g_visible.store(false); g_consoleVisible.store(false); g_chatInputVisible.store(false); client_services::RefreshServers(); } }
    bool IsServerBrowserVisible() { return g_serverBrowserVisible.load(); }
    void SetChatInputVisible(bool visible) { g_chatInputVisible.store(visible); if (visible) { g_chatInput[0] = '\0'; g_chatNeedsFocus.store(true); g_visible.store(false); g_consoleVisible.store(false); g_serverBrowserVisible.store(false); } }
    bool IsChatInputVisible() { return g_chatInputVisible.load(); }
    bool IsInteractiveVisible() { return g_visible.load() || g_consoleVisible.load() || g_serverBrowserVisible.load() || g_chatInputVisible.load(); }
    bool WantsMouseCursor() { return g_visible.load() || g_serverBrowserVisible.load(); }
    bool WantsBackend() { return true; }
    void SetBackendReady(bool ready) { g_backendReady.store(ready); }
    bool ExclusiveInputEnabled()
    {
#if T9_HAS_IMGUI
        return g_captureInput;
#else
        return true;
#endif
    }

    void ConfigureCommandExecutor(CommandExecutor executor)
    {
        std::lock_guard<std::mutex> lock(g_commandMutex);
        g_commandExecutor = executor;
        g_commandStatus = executor ? "Native command backend ready." : "Command backend not configured.";
    }

#if T9_HAS_IMGUI
    bool BackendAvailable() { return g_backendReady.load() && ImGui::GetCurrentContext() != nullptr; }

    void Render()
    {
        if (!BackendAvailable())
            return;

        RenderWatermark();
        RenderChatOverlay();
        RenderServerBrowser();
        RenderTraditionalConsole();
        if (!g_visible.load())
            return;

        ImGui::GetIO().MouseDrawCursor = WantsMouseCursor();
        const ImGuiViewport* viewport = ImGui::GetMainViewport();
        const ImVec2 workPos = viewport ? viewport->WorkPos : ImVec2(0.0f, 0.0f);
        const ImVec2 workSize = viewport ? viewport->WorkSize : ImGui::GetIO().DisplaySize;
        const float width = std::clamp(workSize.x * 0.58f, 760.0f, 1180.0f);
        const float height = std::clamp(workSize.y * 0.70f, 520.0f, 820.0f);
        ImGui::SetNextWindowPos(ImVec2(workPos.x + (workSize.x - width) * 0.5f,
            workPos.y + (workSize.y - height) * 0.5f), ImGuiCond_Always);
        ImGui::SetNextWindowSize(ImVec2(width, height), ImGuiCond_Always);
        ImGui::SetNextWindowBgAlpha(g_windowAlpha);
        bool open = true;
        const ImGuiWindowFlags flags = ImGuiWindowFlags_NoCollapse |
            ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoSavedSettings;
        if (!ImGui::Begin("Black Ops Cold War Research Client", &open, flags))
        {
            ImGui::End();
            if (!open) g_visible.store(false);
            return;
        }
        if (!open) g_visible.store(false);

        if (ImGui::BeginTabBar("main_tabs"))
        {
            if (ImGui::BeginTabItem("Overview")) { RenderOverview(); ImGui::EndTabItem(); }
            if (ImGui::BeginTabItem("Resolver")) { RenderResolver(); ImGui::EndTabItem(); }
            if (ImGui::BeginTabItem("Function Catalog")) { RenderCatalog(); ImGui::EndTabItem(); }
            if (ImGui::BeginTabItem("Commands")) { RenderCommands(); ImGui::EndTabItem(); }
            if (ImGui::BeginTabItem("Dvars & Commands")) { RenderCommandDiscovery(); ImGui::EndTabItem(); }
            if (ImGui::BeginTabItem("Memory")) { RenderMemory(); ImGui::EndTabItem(); }
            if (ImGui::BeginTabItem("Modules")) { RenderModules(); ImGui::EndTabItem(); }
            if (ImGui::BeginTabItem("Logs")) { RenderLogs(); ImGui::EndTabItem(); }
            if (ImGui::BeginTabItem("Runtime Stages")) { RenderRuntimeStages(); ImGui::EndTabItem(); }
            if (ImGui::BeginTabItem("Settings")) { RenderSettings(); ImGui::EndTabItem(); }
            ImGui::EndTabBar();
        }
        ImGui::End();
    }
#else
    bool BackendAvailable() { return false; }
    void Render() {}
#endif
}

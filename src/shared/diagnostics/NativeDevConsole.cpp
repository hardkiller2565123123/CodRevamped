#include "NativeDevConsole.h"
#include "../core/CoreRuntime.h"
#include "../core/Main.hpp"
#include "../runtime/LogPaths.h"
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>
#include <winnt.h>
#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <map>
#include <set>
#include <sstream>
#include <string>
#include <vector>
#include <algorithm>

namespace native_dev_console
{
    namespace
    {
        std::atomic_bool g_started{ false };
        std::atomic_bool g_ready{ false };

        struct Image
        {
            std::uintptr_t base{};
            std::uintptr_t end{};
            std::uintptr_t textBegin{};
            std::uintptr_t textEnd{};
            std::uintptr_t rdataBegin{};
            std::uintptr_t rdataEnd{};
        };

        struct Primitive
        {
            const char* name{};
            std::uintptr_t address{};
            const char* role{};
            bool executable{};
        };

        bool GetImage(Image& out)
        {
            const auto base = reinterpret_cast<std::uintptr_t>(GetModuleHandleW(L"BlackOpsColdWar.exe"));
            if (!base) return false;
            __try
            {
                const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
                if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
                const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(base + dos->e_lfanew);
                if (nt->Signature != IMAGE_NT_SIGNATURE) return false;
                out.base = base;
                out.end = base + nt->OptionalHeader.SizeOfImage;
                const auto* sec = IMAGE_FIRST_SECTION(nt);
                for (unsigned int i = 0; i < nt->FileHeader.NumberOfSections; ++i)
                {
                    char name[9]{};
                    memcpy(name, sec[i].Name, 8);
                    const auto b = base + sec[i].VirtualAddress;
                    const auto e = b + (std::max)(sec[i].Misc.VirtualSize, sec[i].SizeOfRawData);
                    if (!strcmp(name, ".text")) { out.textBegin = b; out.textEnd = e; }
                    else if (!strcmp(name, ".rdata")) { out.rdataBegin = b; out.rdataEnd = e; }
                }
                return out.textBegin && out.rdataBegin;
            }
            __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
        }

        bool IsReadable(std::uintptr_t p)
        {
            if (!p) return false;
            MEMORY_BASIC_INFORMATION mbi{};
            if (!VirtualQuery(reinterpret_cast<const void*>(p), &mbi, sizeof(mbi))) return false;
            return mbi.State == MEM_COMMIT && !(mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS));
        }

        bool IsExecutable(std::uintptr_t p)
        {
            if (!p) return false;
            MEMORY_BASIC_INFORMATION mbi{};
            if (!VirtualQuery(reinterpret_cast<const void*>(p), &mbi, sizeof(mbi))) return false;
            if (mbi.State != MEM_COMMIT || (mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS))) return false;
            const DWORD x = mbi.Protect & 0xFF;
            return x == PAGE_EXECUTE || x == PAGE_EXECUTE_READ || x == PAGE_EXECUTE_READWRITE || x == PAGE_EXECUTE_WRITECOPY;
        }

        std::string Hex(std::uintptr_t v)
        {
            std::ostringstream s;
            s << "0x" << std::hex << std::uppercase << v;
            return s.str();
        }

        bool SafeMemEqual(std::uintptr_t p, const void* expected, std::size_t len)
        {
            if (!p || !expected || !len) return false;
            __try
            {
                return memcmp(reinterpret_cast<const void*>(p), expected, len) == 0;
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                return false;
            }
        }

        bool SafeReadU8(std::uintptr_t p, unsigned char& out)
        {
            __try
            {
                out = *reinterpret_cast<const unsigned char*>(p);
                return true;
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                return false;
            }
        }

        bool SafeReadI32(std::uintptr_t p, std::int32_t& out)
        {
            __try
            {
                out = *reinterpret_cast<const std::int32_t*>(p);
                return true;
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                return false;
            }
        }

        std::vector<std::uintptr_t> FindAsciiContains(const Image& im, const char* text, std::size_t maxHits = 64)
        {
            std::vector<std::uintptr_t> out;
            const auto len = strlen(text);
            if (!len) return out;
            for (auto p = im.rdataBegin; p + len < im.rdataEnd && out.size() < maxHits; ++p)
            {
                if (SafeMemEqual(p, text, len)) out.push_back(p);
            }
            return out;
        }

        std::vector<std::uintptr_t> FindRipXrefs(const Image& im, std::uintptr_t target, std::size_t maxHits = 256)
        {
            std::vector<std::uintptr_t> out;
            for (auto p = im.textBegin; p + 7 < im.textEnd && out.size() < maxHits; ++p)
            {
                unsigned char b0 = 0, b1 = 0, b2 = 0;
                std::int32_t disp = 0;
                if (!SafeReadU8(p, b0) || !SafeReadU8(p + 1, b1) || !SafeReadU8(p + 2, b2) || !SafeReadI32(p + 3, disp)) continue;
                if (!((b0 == 0x48 || b0 == 0x4C) && (b1 == 0x8D || b1 == 0x8B))) continue;
                if ((b2 & 0xC7) != 0x05) continue;
                if (p + 7 + disp == target) out.push_back(p);
            }
            return out;
        }

        std::vector<std::uintptr_t> FindCallXrefs(const Image& im, std::uintptr_t target, std::size_t maxHits = 512)
        {
            std::vector<std::uintptr_t> out;
            if (!target) return out;
            for (auto p = im.textBegin; p + 5 < im.textEnd && out.size() < maxHits; ++p)
            {
                unsigned char opcode = 0;
                std::int32_t rel = 0;
                if (!SafeReadU8(p, opcode) || opcode != 0xE8) continue;
                if (!SafeReadI32(p + 1, rel)) continue;
                if (p + 5 + rel == target) out.push_back(p);
            }
            return out;
        }

        std::uintptr_t ContainingFunction(std::uintptr_t address)
        {
            DWORD64 imageBase = 0;
            const auto* rf = RtlLookupFunctionEntry(address, &imageBase, nullptr);
            return rf ? static_cast<std::uintptr_t>(imageBase + rf->BeginAddress) : 0;
        }

        std::vector<Primitive> CurrentPrimitives()
        {
            return {
                {"CL_DrawTextPhysical", g_Addrs.CL_DrawTextPhysical, "draw text", true},
                {"R_AddCmdDrawStretchPic", g_Addrs.R_AddCmdDrawStretchPic, "draw translucent/background quads", true},
                {"R_TextWidth", g_Addrs.R_TextWidth, "cursor/autocomplete text measurement", true},
                {"UI_GetFontHandle", g_Addrs.UI_GetFontHandle, "font acquisition", true},
                {"ScrPlace_GetViewUIContext", g_Addrs.ScrPlace_GetViewUIContext, "UI placement/context", true},
                {"Material_RegisterHandle", g_Addrs.Material_RegisterHandle, "material acquisition", true},
                {"KeyboardInput", g_Addrs.KeyboardInput, "game keyboard/input path", true},
                {"Cbuf_AddText", g_Addrs.Cbuf_AddText, "engine command submission", true},
                {"Dvar_FindVar", g_Addrs.Dvar_FindVar, "dvar lookup/autocomplete", true},
                {"watermark_font", g_Addrs.watermark_font, "known live font pointer slot", false},
                {"shader_white", g_Addrs.shader_white, "known white material pointer slot", false},
            };
        }

        unsigned int PrimitiveScore(const std::vector<Primitive>& p)
        {
            unsigned int score = 0;
            for (const auto& x : p)
            {
                const bool ok = x.executable ? IsExecutable(x.address) : IsReadable(x.address);
                if (ok) ++score;
            }
            return score;
        }

        bool MinimumConsoleReady(const std::vector<Primitive>& p)
        {
            auto good = [&](const char* name)
            {
                for (const auto& x : p)
                    if (!strcmp(x.name, name))
                        return x.executable ? IsExecutable(x.address) : IsReadable(x.address);
                return false;
            };

            const bool font = good("UI_GetFontHandle") || good("watermark_font");
            const bool material = good("shader_white") || good("Material_RegisterHandle");
            return good("CL_DrawTextPhysical") &&
                good("R_AddCmdDrawStretchPic") &&
                good("R_TextWidth") &&
                font && material &&
                good("KeyboardInput") &&
                good("Cbuf_AddText");
        }

        void WritePrimitiveReport(const Image& im, const std::vector<Primitive>& primitives, unsigned int pass)
        {
            log_paths::EnsureAll();
            CreateDirectoryA("logs\\console", nullptr);

            std::ofstream report("logs\\console\\ingame_console_scan.txt", std::ios::trunc);
            std::ofstream candidates("logs\\console\\ingame_console_candidates.csv", std::ios::trunc);
            std::ofstream xrefs("logs\\console\\ingame_console_xrefs.csv", std::ios::trunc);
            if (candidates) candidates << "name,role,address,rva,kind,valid,call_xrefs\n";
            if (xrefs) xrefs << "source_kind,source_name,string_or_target_rva,xref_rva,function_rva\n";

            if (report)
            {
                report << "CodRevamped T9 in-game console automatic discovery\n";
                report << "pass=" << pass << "\n";
                report << "module_base=" << Hex(im.base) << "\n";
                report << "goal=game-rendered console; no ImGui/external console dependency\n\n";
            }

            for (const auto& p : primitives)
            {
                const bool valid = p.executable ? IsExecutable(p.address) : IsReadable(p.address);
                const auto calls = p.executable && valid ? FindCallXrefs(im, p.address) : std::vector<std::uintptr_t>{};
                if (report)
                    report << p.name << " role=\"" << p.role << "\" address=" << Hex(p.address)
                        << " rva=" << (p.address >= im.base && p.address < im.end ? Hex(p.address - im.base) : "outside-image")
                        << " valid=" << (valid ? "yes" : "no") << " call_xrefs=" << calls.size() << "\n";
                if (candidates)
                    candidates << p.name << ",\"" << p.role << "\"," << Hex(p.address) << ','
                        << (p.address >= im.base && p.address < im.end ? Hex(p.address - im.base) : "") << ','
                        << (p.executable ? "code" : "data") << ',' << (valid ? 1 : 0) << ',' << calls.size() << "\n";
                for (auto c : calls)
                {
                    const auto f = ContainingFunction(c);
                    if (xrefs)
                        xrefs << "call," << p.name << ','
                            << (p.address >= im.base ? Hex(p.address - im.base) : Hex(p.address)) << ','
                            << Hex(c - im.base) << ',' << (f ? Hex(f - im.base) : "") << "\n";
                }
            }

            struct Anchor { const char* group; const char* text; };
            const Anchor anchors[] = {
                {"font", "fonts/"}, {"font", "font"}, {"material", "white"},
                {"input", "bind"}, {"input", "key"}, {"input", "keyboard"},
                {"command", "cmd"}, {"command", "command"}, {"dvar", "dvar"},
                {"ui", "console"}, {"ui", "chat"}, {"ui", "say"},
                {"ui", "autocomplete"}, {"ui", "scroll"}
            };

            if (report) report << "\nSTRING/XREF DISCOVERY\n";
            for (const auto& a : anchors)
            {
                const auto strings = FindAsciiContains(im, a.text, 24);
                std::size_t totalXrefs = 0;
                for (auto s : strings)
                {
                    const auto refs = FindRipXrefs(im, s, 64);
                    totalXrefs += refs.size();
                    for (auto r : refs)
                    {
                        const auto f = ContainingFunction(r);
                        if (xrefs)
                            xrefs << "string:" << a.group << ',' << a.text << ',' << Hex(s - im.base) << ','
                                << Hex(r - im.base) << ',' << (f ? Hex(f - im.base) : "") << "\n";
                    }
                }
                if (report)
                    report << a.group << ":\"" << a.text << "\" strings=" << strings.size() << " xrefs=" << totalXrefs << "\n";
            }

            const auto score = PrimitiveScore(primitives);
            const bool minimum = MinimumConsoleReady(primitives);
            if (report)
            {
                report << "\nSUMMARY\n";
                report << "resolved_valid_primitives=" << score << '/' << primitives.size() << "\n";
                report << "minimum_console_primitive_set=" << (minimum ? "READY" : "INCOMPLETE") << "\n";
                report << "developer_command_path=" << (core_runtime::DeveloperCommandReady() ? "READY" : "NOT_READY") << "\n";
                report << "next_action=automatic scanner continues; no manual scan/hotkey required\n";
            }
        }

        void ScanPass(unsigned int pass)
        {
            Image im{};
            if (!GetImage(im)) return;
            const auto primitives = CurrentPrimitives();
            WritePrimitiveReport(im, primitives, pass);
            const bool ready = MinimumConsoleReady(primitives) && core_runtime::DeveloperCommandReady();
            g_ready.store(ready);
            std::printf("[INGAME-CONSOLE-SCAN] pass=%u primitives=%u/%llu minimum=%s commandPath=%s\n",
                pass, PrimitiveScore(primitives), static_cast<unsigned long long>(primitives.size()),
                MinimumConsoleReady(primitives) ? "READY" : "INCOMPLETE",
                core_runtime::DeveloperCommandReady() ? "READY" : "NOT_READY");
        }

        DWORD WINAPI Worker(LPVOID)
        {
            // Auto-only worker. Early passes catch known RVA table results; later passes
            // catch addresses promoted by the runtime/universal scanners and late renderer/input init.
            const DWORD delaysMs[] = { 3500, 2500, 4000, 6000, 8000, 12000, 15000, 20000, 30000 };
            for (unsigned int pass = 0; pass < _countof(delaysMs); ++pass)
            {
                Sleep(delaysMs[pass]);
                __try { ScanPass(pass + 1); }
                __except (EXCEPTION_EXECUTE_HANDLER)
                {
                    std::printf("[INGAME-CONSOLE-SCAN] guarded pass %u faulted; continuing automatically.\n", pass + 1);
                }
            }
            return 0;
        }
    }

    void StartAsync()
    {
        if (g_started.exchange(true)) return;
        HANDLE t = CreateThread(nullptr, 0, Worker, nullptr, 0, nullptr);
        if (t) CloseHandle(t);
    }

    bool Ready() { return g_ready.load(); }
}

#include "../../../clients/coldwar/game/T9Addresses.h"
#include "../../features/camo/CamoManager.h"
#include "../../features/camo/CamoTextureUpload.h"
#include "../../core/Main.hpp"

#include <Windows.h>
#include <algorithm>
#include <array>
#include <atomic>
#include <cctype>
#include <cstdint>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <mutex>
#include <sstream>
#include <string>
#include <unordered_map>
#include <vector>

namespace
{
    std::string CamoRoot()
    {
        static const std::string root = []()
        {
            char exePath[MAX_PATH]{};
            if (!GetModuleFileNameA(nullptr, exePath, MAX_PATH))
                return std::string("Camos");

            std::string path = exePath;
            const auto slash = path.find_last_of("\\/");
            if (slash != std::string::npos)
                path.resize(slash);

            return path + "\\Camos";
        }();

        return root;
    }

    std::mutex g_camoMutex;
    std::unordered_map<unsigned int, std::uint64_t> g_backups;

    struct CustomImagePatch
    {
        std::uintptr_t address = 0;
        std::uint64_t originalValue = 0;
        std::uint64_t replacementValue = 0;
    };

    std::unordered_map<unsigned int, std::vector<CustomImagePatch>> g_customImageBackups;

    struct CamoImageCandidate
    {
        std::uintptr_t pointerAddress = 0;
        std::uint64_t imagePtr = 0;
        unsigned int imageIndex = 0;
        std::string source;
        unsigned int ownerIndex = 0;
        std::uint64_t parentPtr = 0;
        std::size_t parentOffset = 0;
    };

    std::unordered_map<unsigned int, std::vector<CamoImageCandidate>> g_imageCandidates;
    std::unordered_map<unsigned int, CustomImagePatch> g_singleImageTestBackup;

    struct ImageGroupCandidate
    {
        unsigned int imageIndex = 0;
        std::uint64_t imagePtr = 0;
        unsigned int refCount = 0;
        unsigned int ownerCount = 0;
        unsigned int tier = 0;
        std::vector<std::size_t> candidateRows;
    };

    struct CamoImageCycleState
    {
        std::vector<ImageGroupCandidate> queue;
        int position = -1;
        std::vector<CustomImagePatch> activePatches;
        bool analyzed = false;
        bool kept = false;
        std::string keptRole;
    };

    std::unordered_map<unsigned int, CamoImageCycleState> g_imageCycleStates;
    std::atomic_bool g_autoApplyStarted{false};
    std::atomic_bool g_defaultCamoAutoStarted{false};

    // Placeholder feature for the future multi-camo mapping system.
    // Keep the parser/code compiled, but GIF-only folders are valid for now.
    constexpr bool kEnableCamoInfoFiles = false;

    struct CustomCamoPackage
    {
        std::string folder;
        std::string name;
        std::string infoPath;
        bool autoApply = false;
        unsigned int targetCamo = 1;
        std::string propertiesPath;
        std::string animationPath;
        std::string iconPath;
        std::string colorPath;
        std::string greyPath;

        int blendMapChannels = 0;
        float uvScaleX = 1.0f;
        float uvScaleY = 1.0f;
        float scrollX = 0.0f;
        float scrollY = 0.0f;
        float colorCycleMin = 0.0f;
        float colorCycleMax = 0.0f;
        std::string colorTint;
        std::string colorFormat;
        std::string greyFormat;
        std::uint64_t colorBytes = 0;
        std::uint64_t greyBytes = 0;
    };

    bool FileExists(const std::string& path)
    {
        const DWORD a = GetFileAttributesA(path.c_str());
        return a != INVALID_FILE_ATTRIBUTES && !(a & FILE_ATTRIBUTE_DIRECTORY);
    }

    bool DirectoryExists(const std::string& path)
    {
        const DWORD a = GetFileAttributesA(path.c_str());
        return a != INVALID_FILE_ATTRIBUTES && (a & FILE_ATTRIBUTE_DIRECTORY);
    }

    std::string Join(const std::string& a, const std::string& b)
    {
        if (a.empty()) return b;
        if (a.back() == '\\' || a.back() == '/') return a + b;
        return a + "\\" + b;
    }

    std::string ExtensionLower(const std::string& path)
    {
        const auto dot = path.find_last_of('.');
        if (dot == std::string::npos)
            return {};

        std::string ext = path.substr(dot);
        std::transform(ext.begin(), ext.end(), ext.begin(),
            [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        return ext;
    }

    std::string Trim(std::string value)
    {
        auto notSpace = [](unsigned char c)
        {
            return !std::isspace(c);
        };

        value.erase(
            value.begin(),
            std::find_if(value.begin(), value.end(), notSpace));

        value.erase(
            std::find_if(value.rbegin(), value.rend(), notSpace).base(),
            value.end());

        return value;
    }

    bool ParseBoolValue(const std::string& value)
    {
        std::string lower = Trim(value);
        std::transform(lower.begin(), lower.end(), lower.begin(),
            [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

        return lower == "1" ||
               lower == "true" ||
               lower == "yes" ||
               lower == "on" ||
               lower == "enabled";
    }

    std::string FindAnyCamoImage(const std::string& folder)
    {
        WIN32_FIND_DATAA fd{};
        const std::string pattern =
            Join(folder, "*");

        HANDLE h =
            FindFirstFileA(
                pattern.c_str(),
                &fd);

        if (h == INVALID_HANDLE_VALUE)
            return {};

        std::vector<std::string> gifs;
        std::vector<std::string> preferredPngs;
        std::vector<std::string> colorPngs;
        std::vector<std::string> fallbackPngs;

        do
        {
            if (fd.dwFileAttributes &
                FILE_ATTRIBUTE_DIRECTORY)
            {
                continue;
            }

            std::string name =
                fd.cFileName;

            std::string lower =
                name;

            std::transform(
                lower.begin(),
                lower.end(),
                lower.begin(),
                [](unsigned char c)
                {
                    return static_cast<char>(
                        std::tolower(c));
                });

            const std::string ext =
                ExtensionLower(name);

            if (ext == ".gif")
            {
                gifs.emplace_back(
                    std::move(name));
                continue;
            }

            if (ext != ".png")
                continue;

            // Never accidentally use menu/normal/gray support images as
            // the visible albedo when a package follows the MW camo format.
            if (lower == "icon.png" ||
                lower.find("normal") !=
                    std::string::npos ||
                lower.find("gray") !=
                    std::string::npos ||
                lower.find("grey") !=
                    std::string::npos)
            {
                continue;
            }

            if (lower == "layer0_color.png")
            {
                preferredPngs.emplace_back(
                    std::move(name));
            }
            else if (lower.find("color") !=
                     std::string::npos)
            {
                colorPngs.emplace_back(
                    std::move(name));
            }
            else
            {
                fallbackPngs.emplace_back(
                    std::move(name));
            }

        } while (FindNextFileA(h, &fd));

        FindClose(h);

        auto sortCaseInsensitive =
            [](std::vector<std::string>& names)
            {
                std::sort(
                    names.begin(),
                    names.end(),
                    [](const std::string& a,
                       const std::string& b)
                    {
                        std::string al = a;
                        std::string bl = b;

                        std::transform(
                            al.begin(),
                            al.end(),
                            al.begin(),
                            [](unsigned char c)
                            {
                                return static_cast<char>(
                                    std::tolower(c));
                            });

                        std::transform(
                            bl.begin(),
                            bl.end(),
                            bl.begin(),
                            [](unsigned char c)
                            {
                                return static_cast<char>(
                                    std::tolower(c));
                            });

                        return al < bl;
                    });
            };

        sortCaseInsensitive(gifs);
        sortCaseInsensitive(preferredPngs);
        sortCaseInsensitive(colorPngs);
        sortCaseInsensitive(fallbackPngs);

        // STRICT GLOBAL PRIORITY:
        // ANY GIF in the folder beats EVERY PNG.
        if (!gifs.empty())
            return Join(folder, gifs.front());

        // PNG package priority:
        // layer0_color.png -> other *color*.png -> other usable PNG.
        if (!preferredPngs.empty())
            return Join(folder, preferredPngs.front());

        if (!colorPngs.empty())
            return Join(folder, colorPngs.front());

        if (!fallbackPngs.empty())
            return Join(folder, fallbackPngs.front());

        return {};
    }


    std::string FindInfoFile(const std::string& folder)
    {
        WIN32_FIND_DATAA fd{};
        const std::string pattern = Join(folder, "*");
        HANDLE h = FindFirstFileA(pattern.c_str(), &fd);
        if (h == INVALID_HANDLE_VALUE)
            return {};

        std::string result;

        do
        {
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
                continue;

            std::string name = fd.cFileName;
            std::string lower = name;

            std::transform(
                lower.begin(), lower.end(), lower.begin(),
                [](unsigned char c)
                {
                    return static_cast<char>(std::tolower(c));
                });

            if (lower == "info.txt")
            {
                result = Join(folder, name);
                break;
            }

        } while (FindNextFileA(h, &fd));

        FindClose(h);
        return result;
    }


    bool ParseInfoFile(const std::string& path,
                       std::string& name,
                       bool& autoApply,
                       unsigned int& targetCamo)
    {
        std::ifstream file(path);
        if (!file)
            return false;

        std::string line;

        while (std::getline(file, line))
        {
            line = Trim(line);

            if (line.empty() ||
                line[0] == '#' ||
                line[0] == ';')
                continue;

            const auto equals = line.find('=');
            if (equals == std::string::npos)
                continue;

            std::string key = Trim(line.substr(0, equals));
            std::string value = Trim(line.substr(equals + 1));

            std::transform(key.begin(), key.end(), key.begin(),
                [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

            if (key == "name")
            {
                name = value;
            }
            else if (key == "autoapply" ||
                     key == "auto_apply" ||
                     key == "enabled")
            {
                autoApply = ParseBoolValue(value);
            }
            else if (key == "camo" ||
                     key == "camoslot" ||
                     key == "targetcamo" ||
                     key == "target")
            {
                char* end = nullptr;
                const unsigned long parsed =
                    std::strtoul(value.c_str(), &end, 10);

                if (end != value.c_str())
                    targetCamo = static_cast<unsigned int>(parsed);
            }
        }

        return true;
    }

    void AutoLog(const std::string& message)
    {
        CreateDirectoryA("logs", nullptr);

        std::ofstream file(
            "logs\\camo\\custom_camo_auto.log",
            std::ios::app);

        if (file)
            file << message << "\n";

        std::printf("[CAMO-AUTO] %s\n", message.c_str());
        std::fflush(stdout);
    }


    bool ReadWholeFile(const std::string& path, std::vector<unsigned char>& bytes)
    {
        std::ifstream f(path, std::ios::binary | std::ios::ate);
        if (!f) return false;
        const auto n = f.tellg();
        if (n < 0) return false;
        bytes.resize(static_cast<std::size_t>(n));
        f.seekg(0, std::ios::beg);
        if (!bytes.empty())
            f.read(reinterpret_cast<char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
        return f.good() || f.eof();
    }

    bool ReadTextFile(const std::string& path, std::string& text)
    {
        std::ifstream f(path, std::ios::binary);
        if (!f) return false;
        std::ostringstream out;
        out << f.rdbuf();
        text = out.str();
        return true;
    }

    std::string DetectImageFormat(const std::vector<unsigned char>& bytes)
    {
        if (bytes.size() >= 8 &&
            bytes[0] == 0x89 && bytes[1] == 'P' && bytes[2] == 'N' && bytes[3] == 'G' &&
            bytes[4] == 0x0D && bytes[5] == 0x0A && bytes[6] == 0x1A && bytes[7] == 0x0A)
            return "PNG";
        if (bytes.size() >= 6 &&
            bytes[0] == 'G' && bytes[1] == 'I' && bytes[2] == 'F')
            return "GIF";
        if (bytes.size() >= 2 && bytes[0] == 0xFF && bytes[1] == 0xD8)
            return "JPEG";
        return "UNKNOWN";
    }

    bool ExtractJsonString(const std::string& json, const char* key, std::string& out)
    {
        const std::string needle = std::string("\"") + key + "\"";
        auto p = json.find(needle);
        if (p == std::string::npos) return false;
        p = json.find(':', p + needle.size());
        if (p == std::string::npos) return false;
        p = json.find('"', p + 1);
        if (p == std::string::npos) return false;
        const auto q = json.find('"', p + 1);
        if (q == std::string::npos) return false;
        out = json.substr(p + 1, q - p - 1);
        return true;
    }

    bool ExtractJsonInt(const std::string& json, const char* key, int& out)
    {
        const std::string needle = std::string("\"") + key + "\"";
        auto p = json.find(needle);
        if (p == std::string::npos) return false;
        p = json.find(':', p + needle.size());
        if (p == std::string::npos) return false;
        ++p;
        while (p < json.size() && std::isspace(static_cast<unsigned char>(json[p]))) ++p;
        char* end = nullptr;
        const long v = std::strtol(json.c_str() + p, &end, 10);
        if (end == json.c_str() + p) return false;
        out = static_cast<int>(v);
        return true;
    }

    bool ExtractJsonPair(const std::string& json, const char* key, float& a, float& b)
    {
        const std::string needle = std::string("\"") + key + "\"";
        auto p = json.find(needle);
        if (p == std::string::npos) return false;
        p = json.find('[', p + needle.size());
        if (p == std::string::npos) return false;
        char* end = nullptr;
        a = std::strtof(json.c_str() + p + 1, &end);
        if (end == json.c_str() + p + 1) return false;
        const auto comma = json.find(',', static_cast<std::size_t>(end - json.c_str()));
        if (comma == std::string::npos) return false;
        b = std::strtof(json.c_str() + comma + 1, &end);
        return true;
    }

    bool PoolReady(XAssetPool*& pool, std::string& error)
    {
        if (!g_assetPool)
        {
            error = "asset pool table is unavailable";
            return false;
        }

        pool = &g_assetPool[ASSET_TYPE_WEAPONCAMO];
        if (!pool->pool.unk || pool->itemSize == 0 || pool->itemAllocCount <= 0)
        {
            std::ostringstream out;
            out << "weapon-camo pool is not ready (base=" << pool->pool.unk
                << " itemSize=" << pool->itemSize
                << " itemAllocCount=" << pool->itemAllocCount << ")";
            error = out.str();
            return false;
        }
        return true;
    }

    bool CopyFromProcess(const void* address, void* out, std::size_t size)
    {
        SIZE_T got = 0;
        return address && out && size &&
            ReadProcessMemory(GetCurrentProcess(), address, out, size, &got) &&
            got == size;
    }

    bool CopyToProcess(void* address, const void* data, std::size_t size)
    {
        if (!address || !data || !size) return false;
        DWORD oldProtect = 0;
        if (!VirtualProtect(address, size, PAGE_READWRITE, &oldProtect))
            return false;
        SIZE_T wrote = 0;
        const BOOL ok = WriteProcessMemory(GetCurrentProcess(), address, data, size, &wrote);
        FlushInstructionCache(GetCurrentProcess(), address, size);
        DWORD ignored = 0;
        VirtualProtect(address, size, oldProtect, &ignored);
        return ok && wrote == size;
    }

    bool InPool(std::uint64_t value, const XAssetPool& pool, unsigned int& index)
    {
        if (!value || !pool.pool.unk || pool.itemSize == 0 || pool.itemAllocCount <= 0)
            return false;
        const auto base = reinterpret_cast<std::uint64_t>(pool.pool.unk);
        const auto end = base + static_cast<std::uint64_t>(pool.itemSize) *
                                static_cast<std::uint64_t>(pool.itemAllocCount);
        if (value < base || value >= end) return false;
        const auto delta = value - base;
        if ((delta % pool.itemSize) != 0) return false;
        index = static_cast<unsigned int>(delta / pool.itemSize);
        return true;
    }

    std::vector<std::string> EnumeratePackageFolders()
    {
        std::vector<std::string> folders;
        const std::string root = CamoRoot();

        CreateDirectoryA("logs", nullptr);

        std::ofstream scan(
            "logs\\camo\\custom_camo_folder_scan.log",
            std::ios::trunc);

        if (scan)
        {
            scan << "root=" << root << "\n";
            scan << "info_txt_required="
                 << (kEnableCamoInfoFiles ? 1 : 0)
                 << "\n";
        }

        if (!DirectoryExists(root))
        {
            if (scan)
                scan << "ERROR: Camos root does not exist\n";
            return folders;
        }

        // Root-package compatibility:
        // Camos\<any gif> is valid while Info.txt support is disabled.
        const std::string rootInfo =
            FindInfoFile(root);

        const std::string rootGif =
            FindAnyCamoImage(root);

        const bool rootInfoValid =
            !kEnableCamoInfoFiles ||
            !rootInfo.empty();

        if (!rootGif.empty() && rootInfoValid)
        {
            folders.push_back(root);

            if (scan)
            {
                scan
                    << "OK root-package folder=\""
                    << root
                    << "\" image=\""
                    << rootGif
                    << "\" info=\""
                    << (rootInfo.empty() ? "<disabled/not-present>" : rootInfo)
                    << "\"\n";
            }
        }

        WIN32_FIND_DATAA fd{};
        const std::string pattern =
            Join(root, "*");

        HANDLE h =
            FindFirstFileA(
                pattern.c_str(),
                &fd);

        if (h == INVALID_HANDLE_VALUE)
        {
            if (scan)
                scan << "ERROR: could not enumerate Camos root\n";
            return folders;
        }

        do
        {
            if (!(fd.dwFileAttributes &
                  FILE_ATTRIBUTE_DIRECTORY))
            {
                continue;
            }

            if (!std::strcmp(fd.cFileName, ".") ||
                !std::strcmp(fd.cFileName, ".."))
            {
                continue;
            }

            const std::string folder =
                Join(root, fd.cFileName);

            const std::string info =
                FindInfoFile(folder);

            const std::string gif =
                FindAnyCamoImage(folder);

            if (gif.empty())
            {
                if (scan)
                {
                    scan
                        << "SKIP folder=\""
                        << folder
                        << "\" reason=no GIF/PNG\n";
                }

                continue;
            }

            if (kEnableCamoInfoFiles &&
                info.empty())
            {
                if (scan)
                {
                    scan
                        << "SKIP folder=\""
                        << folder
                        << "\" reason=no Info.txt\n";
                }

                continue;
            }

            if (std::find(
                    folders.begin(),
                    folders.end(),
                    folder) ==
                folders.end())
            {
                folders.push_back(folder);
            }

            if (scan)
            {
                scan
                    << "OK folder=\""
                    << folder
                    << "\" image=\""
                    << gif
                    << "\" info=\""
                    << (info.empty()
                        ? "<disabled/not-present>"
                        : info)
                    << "\"\n";
            }

        } while (FindNextFileA(h, &fd));

        FindClose(h);

        std::sort(
            folders.begin(),
            folders.end(),
            [](const std::string& a,
               const std::string& b)
            {
                std::string al = a;
                std::string bl = b;

                std::transform(
                    al.begin(),
                    al.end(),
                    al.begin(),
                    [](unsigned char c)
                    {
                        return static_cast<char>(
                            std::tolower(c));
                    });

                std::transform(
                    bl.begin(),
                    bl.end(),
                    bl.begin(),
                    [](unsigned char c)
                    {
                        return static_cast<char>(
                            std::tolower(c));
                    });

                return al < bl;
            });

        if (scan)
        {
            scan
                << "valid_packages="
                << folders.size()
                << "\n";
        }

        return folders;
    }

    bool LoadPackageFolder(
        const std::string& folder,
        CustomCamoPackage& pkg,
        std::string& error)
    {
        pkg = {};
        pkg.folder = folder;
        pkg.infoPath =
            FindInfoFile(folder);

        pkg.propertiesPath =
            Join(folder, "properties.json");

        pkg.animationPath =
            Join(folder, "animation.json");

        pkg.iconPath =
            Join(folder, "icon.png");

        // Current confirmed custom-camo target.
        // Future Info.txt mapping will replace this default.
        pkg.targetCamo = 1;
        pkg.autoApply = false;

        // GIF/PNG filename is intentionally irrelevant. GIF wins if both exist.
        pkg.colorPath =
            FindAnyCamoImage(folder);

        if (pkg.colorPath.empty())
        {
            error =
                "folder contains no .gif or .png file";
            return false;
        }

        const auto slash =
            folder.find_last_of("\\/");

        const std::string folderName =
            slash == std::string::npos
            ? folder
            : folder.substr(slash + 1);

        pkg.name =
            folderName;

        // Keep the entire Info.txt implementation compiled for later,
        // but ignore it completely while the feature flag is disabled.
        if (kEnableCamoInfoFiles)
        {
            if (pkg.infoPath.empty() ||
                !FileExists(pkg.infoPath))
            {
                error =
                    "Info.txt is required while Info support is enabled";
                return false;
            }

            if (!ParseInfoFile(
                    pkg.infoPath,
                    pkg.name,
                    pkg.autoApply,
                    pkg.targetCamo))
            {
                error =
                    "could not read Info.txt";
                return false;
            }

            if (pkg.name.empty())
                pkg.name = folderName;
        }

        // Older optional metadata remains available for compatibility.
        std::string properties;

        if (ReadTextFile(
                pkg.propertiesPath,
                properties))
        {
            ExtractJsonString(
                properties,
                "color_tint",
                pkg.colorTint);

            ExtractJsonInt(
                properties,
                "blend_map_channels",
                pkg.blendMapChannels);

            ExtractJsonPair(
                properties,
                "uv_scale",
                pkg.uvScaleX,
                pkg.uvScaleY);
        }

        std::string animation;

        if (ReadTextFile(
                pkg.animationPath,
                animation))
        {
            ExtractJsonPair(
                animation,
                "scroll",
                pkg.scrollX,
                pkg.scrollY);

            ExtractJsonPair(
                animation,
                "color_cycle",
                pkg.colorCycleMin,
                pkg.colorCycleMax);
        }

        std::vector<unsigned char> color;

        if (ReadWholeFile(
                pkg.colorPath,
                color))
        {
            pkg.colorBytes =
                static_cast<std::uint64_t>(
                    color.size());

            pkg.colorFormat =
                DetectImageFormat(color);
        }

        return true;
    }

    bool FindPackage(const std::string& requested, CustomCamoPackage& pkg, std::string& error)
    {
        std::string wanted = requested;
        std::transform(wanted.begin(), wanted.end(), wanted.begin(),
            [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

        for (const auto& folder : EnumeratePackageFolders())
        {
            CustomCamoPackage candidate;
            std::string ignored;
            if (!LoadPackageFolder(folder, candidate, ignored))
                continue;

            std::string name = candidate.name;
            std::transform(name.begin(), name.end(), name.begin(),
                [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

            const auto slash = folder.find_last_of("\\/");
            std::string folderName = slash == std::string::npos ? folder : folder.substr(slash + 1);
            std::transform(folderName.begin(), folderName.end(), folderName.begin(),
                [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

            if (name == wanted || folderName == wanted)
            {
                pkg = candidate;
                return true;
            }
        }

        error = "custom camo folder not found under \"" + CamoRoot() + "\"";
        return false;
    }
    DWORD WINAPI DefaultBo4DiamondWorker(LPVOID)
    {
        SetThreadPriority(
            GetCurrentThread(),
            THREAD_PRIORITY_BELOW_NORMAL);

        // Let renderer/pools settle. Prewarm starts at the same guarded stage.
        Sleep(1500);

        CustomCamoPackage pkg;
        std::string error;

        if (!FindPackage(
                "Bo4Diamond",
                pkg,
                error))
        {
            AutoLog(
                "default Bo4Diamond auto-apply skipped: " +
                error);
            return 0;
        }

        AutoLog(
            "default Bo4Diamond found: image=\"" +
            pkg.colorPath + "\"");

        // Ensure max-quality cache is prepared first. The background prewarm
        // also prioritizes this folder, so this is normally just a wait/HIT.
        // If missing, build in this below-normal thread.
        if (!camo_texture_upload::IsGifPrecached(
                pkg.colorPath,
                2048))
        {
            AutoLog(
                "Bo4Diamond 2048 cache missing; preparing in background");

            std::string cacheMessage;

            if (!camo_texture_upload::PrecacheGif(
                    pkg.colorPath,
                    cacheMessage))
            {
                AutoLog(
                    "Bo4Diamond precache failed: " +
                    cacheMessage);
                return 0;
            }

            AutoLog(
                "Bo4Diamond precache ready: " +
                cacheMessage);
        }
        else
        {
            AutoLog(
                "Bo4Diamond max-quality cache already exists");
        }

        // Wait for the live renderer resource. Cache work is already finished,
        // so successful apply should now be the fast path.
        for (unsigned int attempt = 1;
             attempt <= 120;
             ++attempt)
        {
            std::string applyMessage;

            if (camo_manager::CustomApplyConfigured(
                    "Bo4Diamond",
                    applyMessage))
            {
                AutoLog(
                    "Bo4Diamond auto-applied: " +
                    applyMessage);
                return 0;
            }

            if (attempt == 1 ||
                attempt % 10 == 0)
            {
                AutoLog(
                    "Bo4Diamond waiting for live camo resource attempt " +
                    std::to_string(attempt) +
                    "/120: " +
                    applyMessage);
            }

            Sleep(500);
        }

        AutoLog(
            "Bo4Diamond auto-apply timed out; manual /apply camo Bo4Diamond remains available");

        return 0;
    }

    DWORD WINAPI AutoApplyWorker(LPVOID)
    {

        if (!kEnableCamoInfoFiles)
        {
            AutoLog(
                "Info.txt auto-apply is disabled; GIF-only folders are enabled for manual /apply camo <folder>");
            return 0;
        }


        // Overlay hooks are installed before this thread is started, but the
        // actual game D3D12 device/queue may not be captured until later frames.
        Sleep(2000);

        const auto folders =
            EnumeratePackageFolders();

        std::vector<CustomCamoPackage> automatic;

        for (const auto& folder : folders)
        {
            CustomCamoPackage pkg;
            std::string error;

            if (LoadPackageFolder(folder, pkg, error) &&
                pkg.autoApply)
            {
                automatic.push_back(std::move(pkg));
            }
        }

        if (automatic.empty())
        {
            AutoLog(
                "no Info.txt package has AutoApply=1; manual /apply camo <folder> remains available");
            return 0;
        }

        // EnumeratePackageFolders is sorted, so first folder wins consistently.
        if (automatic.size() > 1)
        {
            std::ostringstream warning;
            warning
                << automatic.size()
                << " folders have AutoApply=1; using first alphabetically: "
                << automatic.front().folder;
            AutoLog(warning.str());
        }

        const auto& selected =
            automatic.front();

        if (selected.targetCamo != 1)
        {
            std::ostringstream unsupported;
            unsupported
                << "Info.txt requested Camo="
                << selected.targetCamo
                << ", but only confirmed custom GPU target Camo=1 is supported right now";
            AutoLog(unsupported.str());
            return 0;
        }

        const auto slash =
            selected.folder.find_last_of("\\/");

        const std::string folderName =
            slash == std::string::npos
            ? selected.folder
            : selected.folder.substr(slash + 1);

        AutoLog(
            "selected \"" + folderName +
            "\" -> GIF \"" + selected.colorPath +
            "\" target camo " +
            std::to_string(selected.targetCamo));

        // Retry while the renderer finishes creating the confirmed resident
        // GfxImage resource. This keeps auto apply out of fragile early startup.
        for (unsigned int attempt = 1;
             attempt <= 120;
             ++attempt)
        {
            std::string message;

            if (camo_manager::CustomApplyConfigured(
                    folderName,
                    message))
            {
                AutoLog(
                    "applied \"" + folderName +
                    "\" automatically: " +
                    message);
                return 0;
            }

            if (attempt == 1 ||
                attempt % 10 == 0)
            {
                AutoLog(
                    "waiting for camo resource (attempt " +
                    std::to_string(attempt) +
                    "/120): " +
                    message);
            }

            Sleep(1000);
        }

        AutoLog(
            "auto apply timed out after 120 seconds; use /apply camo " +
            folderName +
            " to retry manually");

        return 0;
    }

}

    std::string SnapshotStamp()
    {
        SYSTEMTIME st{};
        GetLocalTime(&st);
        char buf[64]{};
        std::snprintf(buf, sizeof(buf), "%04u%02u%02u_%02u%02u%02u",
            st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
        return buf;
    }

    bool ReadQword(std::uintptr_t address, std::uint64_t& value)
    {
        return CopyFromProcess(reinterpret_cast<const void*>(address), &value, sizeof(value));
    }

    const char* ClassifyPoolPointer(std::uint64_t value,
                                    const XAssetPool& camoPool,
                                    const XAssetPool& bindingPool,
                                    const XAssetPool& materialPool,
                                    const XAssetPool& imagePool,
                                    unsigned int& index)
    {
        if (InPool(value, camoPool, index)) return "WEAPONCAMO";
        if (InPool(value, bindingPool, index)) return "WEAPONCAMOBINDING";
        if (InPool(value, materialPool, index)) return "MATERIAL";
        if (InPool(value, imagePool, index)) return "IMAGE";
        return nullptr;
    }


    bool QueryReadableRegion(std::uint64_t address, MEMORY_BASIC_INFORMATION& mbi)
    {
        if (!address) return false;
        if (!VirtualQuery(reinterpret_cast<LPCVOID>(address), &mbi, sizeof(mbi)))
            return false;
        if (mbi.State != MEM_COMMIT) return false;
        if (mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)) return false;
        return true;
    }

    std::size_t SafeReadableSpan(std::uint64_t address, std::size_t requested)
    {
        MEMORY_BASIC_INFORMATION mbi{};
        if (!QueryReadableRegion(address, mbi)) return 0;
        const auto regionStart = reinterpret_cast<std::uint64_t>(mbi.BaseAddress);
        const auto regionEnd = regionStart + static_cast<std::uint64_t>(mbi.RegionSize);
        if (address < regionStart || address >= regionEnd) return 0;
        const auto available = regionEnd - address;
        return static_cast<std::size_t>(std::min<std::uint64_t>(available, requested));
    }

    const char* RegionTypeName(std::uint64_t address)
    {
        MEMORY_BASIC_INFORMATION mbi{};
        if (!QueryReadableRegion(address, mbi)) return "UNREADABLE";
        if (mbi.Type == MEM_PRIVATE) return "PRIVATE";
        if (mbi.Type == MEM_MAPPED) return "MAPPED";
        if (mbi.Type == MEM_IMAGE) return "IMAGE";
        return "OTHER";
    }

    bool ReadBlock(std::uint64_t address, std::vector<unsigned char>& out, std::size_t requested)
    {
        const auto span = SafeReadableSpan(address, requested);
        if (span < 8) return false;
        out.resize(span);
        return CopyFromProcess(reinterpret_cast<const void*>(address), out.data(), out.size());
    }

    struct PoolHit
    {
        const char* type = nullptr;
        unsigned int index = 0;
        std::uint64_t itemBase = 0;
        std::uint64_t interiorOffset = 0;
    };

    bool ClassifyPoolPointerDeep(std::uint64_t value,
                                 const XAssetPool& camoPool,
                                 const XAssetPool& bindingPool,
                                 const XAssetPool& materialPool,
                                 const XAssetPool& imagePool,
                                 PoolHit& hit)
    {
        auto classify = [&](const XAssetPool& pool, const char* name) -> bool
        {
            if (!value || !pool.pool.unk || pool.itemSize == 0 || pool.itemAllocCount <= 0)
                return false;
            const auto base = reinterpret_cast<std::uint64_t>(pool.pool.unk);
            const auto end = base + static_cast<std::uint64_t>(pool.itemSize) *
                                    static_cast<std::uint64_t>(pool.itemAllocCount);
            if (value < base || value >= end) return false;
            const auto delta = value - base;
            hit.type = name;
            hit.index = static_cast<unsigned int>(delta / pool.itemSize);
            hit.itemBase = base + static_cast<std::uint64_t>(hit.index) * pool.itemSize;
            hit.interiorOffset = value - hit.itemBase;
            return true;
        };

        if (classify(camoPool, "WEAPONCAMO")) return true;
        if (classify(bindingPool, "WEAPONCAMOBINDING")) return true;
        if (classify(materialPool, "MATERIAL")) return true;
        if (classify(imagePool, "IMAGE")) return true;
        return false;
    }

    bool ReadCamoEntry(unsigned int camoIndex, XAssetPool*& pool, std::uint64_t& definition,
                       std::uint64_t& nameHash, std::string& error)
    {
        if (!PoolReady(pool, error)) return false;
        const unsigned int count = static_cast<unsigned int>(std::max(0, pool->itemAllocCount));
        if (camoIndex >= count)
        {
            std::ostringstream out;
            out << "target camo index out of range; valid range 0-" << (count ? count - 1 : 0);
            error = out.str();
            return false;
        }

        const auto base = reinterpret_cast<std::uintptr_t>(pool->pool.unk);
        const auto address = base + static_cast<std::uintptr_t>(camoIndex) * pool->itemSize;
        unsigned char bytes[32]{};
        if (!CopyFromProcess(reinterpret_cast<const void*>(address), bytes, sizeof(bytes)))
        {
            error = "could not read target camo entry";
            return false;
        }

        std::memcpy(&nameHash, bytes + 0x00, 8);
        std::memcpy(&definition, bytes + 0x10, 8);
        return true;
    }

    std::vector<unsigned int> CollectCamoMaterials(unsigned int camoIndex,
                                                   const XAssetPool& camoPool,
                                                   const XAssetPool& materialPool)
    {
        std::vector<unsigned int> result;
        const auto camoBase = reinterpret_cast<std::uintptr_t>(camoPool.pool.unk);
        const auto address = camoBase + static_cast<std::uintptr_t>(camoIndex) * camoPool.itemSize;

        std::uint64_t definition = 0;
        if (!CopyFromProcess(reinterpret_cast<const void*>(address + 0x10), &definition, 8) || !definition)
            return result;

        std::vector<unsigned char> def;
        if (!ReadBlock(definition, def, 0x2000))
            return result;

        for (std::size_t off = 0; off + 8 <= def.size(); off += 8)
        {
            std::uint64_t value = 0;
            std::memcpy(&value, def.data() + off, 8);
            unsigned int index = 0;
            if (InPool(value, materialPool, index) &&
                std::find(result.begin(), result.end(), index) == result.end())
                result.push_back(index);
        }
        return result;
    }

    std::vector<std::pair<unsigned int, std::uint64_t>> CollectCamoBindingObjects(
        unsigned int camoIndex,
        const XAssetPool& camoPool,
        const XAssetPool& bindingPool)
    {
        std::vector<std::pair<unsigned int, std::uint64_t>> result;
        const auto bindingBase = reinterpret_cast<std::uintptr_t>(bindingPool.pool.unk);
        const auto camoBase = reinterpret_cast<std::uintptr_t>(camoPool.pool.unk);
        const auto expectedOwner = camoBase + static_cast<std::uintptr_t>(camoIndex) * camoPool.itemSize;
        const unsigned int count = static_cast<unsigned int>(std::max(0, bindingPool.itemAllocCount));

        for (unsigned int i = 0; i < count; ++i)
        {
            const auto address = bindingBase + static_cast<std::uintptr_t>(i) * bindingPool.itemSize;
            unsigned char bytes[32]{};
            if (!CopyFromProcess(reinterpret_cast<const void*>(address), bytes, sizeof(bytes)))
                continue;

            std::uint64_t q2 = 0, owner = 0;
            std::memcpy(&q2, bytes + 0x10, 8);
            std::memcpy(&owner, bytes + 0x18, 8);
            if (owner == expectedOwner && q2)
                result.emplace_back(i, q2);
        }
        return result;
    }

    bool BackupAndPatchPointer(unsigned int targetIndex,
                               std::uintptr_t address,
                               std::uint64_t replacement,
                               std::size_t maxPatches,
                               std::size_t& patchCount)
    {
        if (patchCount >= maxPatches) return false;

        std::uint64_t current = 0;
        if (!CopyFromProcess(reinterpret_cast<const void*>(address), &current, 8))
            return false;
        if (current == replacement)
            return false;

        auto& list = g_customImageBackups[targetIndex];
        const auto existing = std::find_if(list.begin(), list.end(),
            [address](const CustomImagePatch& p) { return p.address == address; });
        if (existing != list.end())
            return false;

        if (!CopyToProcess(reinterpret_cast<void*>(address), &replacement, 8))
            return false;

        list.push_back({ address, current, replacement });
        ++patchCount;
        return true;
    }

    std::vector<CamoImageCandidate> CollectImageCandidatesForCamo(
        unsigned int targetIndex,
        const XAssetPool& camoPool,
        const XAssetPool& bindingPool,
        const XAssetPool& materialPool,
        const XAssetPool& imagePool)
    {
        std::vector<CamoImageCandidate> out;

        auto addCandidate = [&](std::uintptr_t pointerAddress,
                                std::uint64_t imagePtr,
                                const char* source,
                                unsigned int ownerIndex,
                                std::uint64_t parentPtr,
                                std::size_t parentOffset)
        {
            unsigned int imageIndex = 0;
            if (!InPool(imagePtr, imagePool, imageIndex))
                return;

            const auto duplicate = std::find_if(out.begin(), out.end(),
                [pointerAddress](const CamoImageCandidate& c)
                {
                    return c.pointerAddress == pointerAddress;
                });
            if (duplicate != out.end())
                return;

            CamoImageCandidate c{};
            c.pointerAddress = pointerAddress;
            c.imagePtr = imagePtr;
            c.imageIndex = imageIndex;
            c.source = source;
            c.ownerIndex = ownerIndex;
            c.parentPtr = parentPtr;
            c.parentOffset = parentOffset;
            out.push_back(std::move(c));
        };

        // A) Binding +0x10 objects.
        const auto bindingObjects =
            CollectCamoBindingObjects(targetIndex, camoPool, bindingPool);

        for (const auto& pair : bindingObjects)
        {
            const unsigned int bindingIndex = pair.first;
            const std::uint64_t objectPtr = pair.second;

            std::vector<unsigned char> obj;
            if (!ReadBlock(objectPtr, obj, 0x4000))
                continue;

            for (std::size_t off = 0; off + 8 <= obj.size(); off += 8)
            {
                std::uint64_t value = 0;
                std::memcpy(&value, obj.data() + off, 8);
                addCandidate(static_cast<std::uintptr_t>(objectPtr + off),
                             value, "BINDING_OBJECT", bindingIndex,
                             objectPtr, off);
            }
        }

        // B) Material child tables.
        const auto materials =
            CollectCamoMaterials(targetIndex, camoPool, materialPool);

        std::vector<unsigned char> mat(materialPool.itemSize);
        std::unordered_map<std::uint64_t, bool> visitedChildren;

        for (unsigned int materialIndex : materials)
        {
            if (materialIndex >= static_cast<unsigned int>(materialPool.itemAllocCount))
                continue;

            const auto matAddr =
                reinterpret_cast<std::uintptr_t>(materialPool.pool.unk) +
                static_cast<std::uintptr_t>(materialIndex) * materialPool.itemSize;

            if (!CopyFromProcess(reinterpret_cast<const void*>(matAddr),
                                 mat.data(), mat.size()))
                continue;

            // Direct image qwords inside the material itself.
            for (std::size_t off = 0; off + 8 <= mat.size(); off += 8)
            {
                std::uint64_t value = 0;
                std::memcpy(&value, mat.data() + off, 8);
                addCandidate(matAddr + off, value, "MATERIAL_DIRECT",
                             materialIndex, matAddr, off);
            }

            // One-level child tables referenced by material pointers.
            for (std::size_t moff = 0; moff + 8 <= mat.size(); moff += 8)
            {
                std::uint64_t childPtr = 0;
                std::memcpy(&childPtr, mat.data() + moff, 8);
                if (!childPtr || visitedChildren.count(childPtr))
                    continue;

                const auto span = SafeReadableSpan(childPtr, 0x1000);
                if (span < 0x20)
                    continue;

                const char* type = RegionTypeName(childPtr);
                if (std::strcmp(type, "PRIVATE") && std::strcmp(type, "MAPPED"))
                    continue;

                visitedChildren[childPtr] = true;

                std::vector<unsigned char> child;
                if (!ReadBlock(childPtr, child, 0x1000))
                    continue;

                for (std::size_t coff = 0; coff + 8 <= child.size(); coff += 8)
                {
                    std::uint64_t value = 0;
                    std::memcpy(&value, child.data() + coff, 8);
                    addCandidate(static_cast<std::uintptr_t>(childPtr + coff),
                                 value, "MATERIAL_CHILD",
                                 materialIndex, childPtr, coff);
                }
            }
        }

        return out;
    }

    void DumpHexBytes(std::ofstream& file, const unsigned char* bytes, std::size_t size)
    {
        for (std::size_t i = 0; i < size; ++i)
        {
            if ((i % 16) == 0)
                file << "\n0x" << std::hex << std::uppercase
                     << std::setw(4) << std::setfill('0') << i << ": ";
            file << std::setw(2) << static_cast<unsigned int>(bytes[i]) << ' ';
        }
        file << std::dec << "\n";
    }

    bool LooksLikePointer(std::uint64_t value)
    {
        if (value < 0x10000) return false;
        MEMORY_BASIC_INFORMATION mbi{};
        return VirtualQuery(reinterpret_cast<LPCVOID>(value), &mbi, sizeof(mbi)) &&
               mbi.State == MEM_COMMIT &&
               !(mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD));
    }

    void RestoreCyclePatches(CamoImageCycleState& state)
    {
        for (auto it = state.activePatches.rbegin(); it != state.activePatches.rend(); ++it)
            CopyToProcess(reinterpret_cast<void*>(it->address), &it->originalValue, 8);
        state.activePatches.clear();
    }

    std::vector<ImageGroupCandidate> BuildPrioritizedImageQueue(
        const std::vector<CamoImageCandidate>& raw)
    {
        struct Temp
        {
            unsigned int imageIndex = 0;
            std::uint64_t imagePtr = 0;
            std::vector<std::size_t> rows;
            std::vector<unsigned int> owners;
        };

        std::unordered_map<unsigned int, Temp> grouped;
        for (std::size_t i = 0; i < raw.size(); ++i)
        {
            auto& g = grouped[raw[i].imageIndex];
            g.imageIndex = raw[i].imageIndex;
            g.imagePtr = raw[i].imagePtr;
            g.rows.push_back(i);
            if (std::find(g.owners.begin(), g.owners.end(), raw[i].ownerIndex) == g.owners.end())
                g.owners.push_back(raw[i].ownerIndex);
        }

        std::vector<ImageGroupCandidate> queue;
        queue.reserve(grouped.size());

        for (const auto& pair : grouped)
        {
            const auto& g = pair.second;

            // Very small image indices are overwhelmingly shared engine/default
            // resources in the current capture, so put them in the last tier.
            const bool genericSmall = g.imageIndex < 1000;
            const unsigned int refs = static_cast<unsigned int>(g.rows.size());
            const unsigned int owners = static_cast<unsigned int>(g.owners.size());

            unsigned int tier = 4;
            if (!genericSmall && refs == 1 && owners == 1)
                tier = 0; // strongest: unique image, one ref, one owner
            else if (!genericSmall && refs <= 2 && owners == 1)
                tier = 1; // strong
            else if (!genericSmall && refs <= 4 && owners <= 2)
                tier = 2; // useful fallback
            else if (!genericSmall && refs <= 8)
                tier = 3; // broader fallback

            ImageGroupCandidate out{};
            out.imageIndex = g.imageIndex;
            out.imagePtr = g.imagePtr;
            out.refCount = refs;
            out.ownerCount = owners;
            out.tier = tier;
            out.candidateRows = g.rows;
            queue.push_back(std::move(out));
        }

        std::sort(queue.begin(), queue.end(),
            [](const ImageGroupCandidate& a, const ImageGroupCandidate& b)
            {
                if (a.tier != b.tier) return a.tier < b.tier;
                if (a.refCount != b.refCount) return a.refCount < b.refCount;
                if (a.ownerCount != b.ownerCount) return a.ownerCount < b.ownerCount;
                return a.imageIndex < b.imageIndex;
            });

        return queue;
    }

    bool ApplyCyclePosition(unsigned int targetIndex, int requestedPosition, std::string& message)
    {
        auto rawIt = g_imageCandidates.find(targetIndex);
        auto stateIt = g_imageCycleStates.find(targetIndex);
        if (rawIt == g_imageCandidates.end() || stateIt == g_imageCycleStates.end() ||
            !stateIt->second.analyzed || stateIt->second.queue.empty())
        {
            message = "run /camo custom analyze <targetIndex> first";
            return false;
        }

        auto& state = stateIt->second;
        RestoreCyclePatches(state);

        const int count = static_cast<int>(state.queue.size());
        if (count <= 0)
        {
            message = "candidate queue is empty";
            return false;
        }

        int pos = requestedPosition;
        while (pos < 0) pos += count;
        while (pos >= count) pos -= count;
        state.position = pos;
        state.kept = false;
        state.keptRole.clear();

        const auto& group = state.queue[static_cast<std::size_t>(pos)];
        const auto& raw = rawIt->second;

        const auto& imagePool = g_assetPool[ASSET_TYPE_IMAGE];
        if (!imagePool.pool.unk || imagePool.itemSize == 0 || imagePool.itemAllocCount <= 4)
        {
            message = "image pool is not ready";
            return false;
        }

        constexpr unsigned int donorIndex = 4;
        const auto imageBase = reinterpret_cast<std::uintptr_t>(imagePool.pool.unk);
        const std::uint64_t donor =
            imageBase + static_cast<std::uint64_t>(donorIndex) * imagePool.itemSize;

        for (std::size_t rawRow : group.candidateRows)
        {
            if (rawRow >= raw.size()) continue;
            const auto& c = raw[rawRow];

            std::uint64_t current = 0;
            if (!CopyFromProcess(reinterpret_cast<const void*>(c.pointerAddress), &current, 8))
                continue;

            // Only patch if this pointer still points to the expected image.
            // This prevents stale analysis data from overwriting changed runtime state.
            if (current != c.imagePtr)
                continue;

            if (!CopyToProcess(reinterpret_cast<void*>(c.pointerAddress), &donor, 8))
                continue;

            state.activePatches.push_back({ c.pointerAddress, current, donor });
        }

        if (state.activePatches.empty())
        {
            message = "selected image group had no currently valid patchable references";
            return false;
        }

        // Save current test to a small live log.
        CreateDirectoryA("logs", nullptr);
        std::ofstream log("logs\\camo\\camo_candidate_cycle.csv", std::ios::app);
        if (log)
        {
            if (log.tellp() == 0)
                log << "target,queue_position,tier,image_index,ref_count,owner_count,patched_count\n";
            log << targetIndex << ',' << pos << ',' << group.tier << ','
                << group.imageIndex << ',' << group.refCount << ','
                << group.ownerCount << ',' << state.activePatches.size() << "\n";
        }

        std::ostringstream out;
        out << "candidate " << (pos + 1) << "/" << count
            << " tier=" << group.tier
            << " image=" << group.imageIndex
            << " refs=" << group.refCount
            << " owners=" << group.ownerCount
            << " patched=" << state.activePatches.size()
            << " -> donor #4. "
            << "Watch the camo. Use /camo custom next " << targetIndex
            << ", /prev, /keep " << targetIndex << " color, or /testrestore.";
        message = out.str();
        return true;
    }

namespace camo_manager
{

    static AllocatorResearchSnapshot g_allocatorResearchSnapshot{};
    static std::mutex g_allocatorResearchSnapshotMutex;

    bool Status(std::string& message)
    {
        if (!g_assetPool)
        {
            message = "asset pool table is unavailable";
            return false;
        }

        const auto& camo = g_assetPool[ASSET_TYPE_WEAPONCAMO];
        const auto& binding = g_assetPool[ASSET_TYPE_WEAPONCAMOBINDING];
        const auto& material = g_assetPool[ASSET_TYPE_MATERIAL];
        const auto& image = g_assetPool[ASSET_TYPE_IMAGE];

        std::ostringstream out;
        out << "weaponCamo{base=" << camo.pool.unk << ",itemSize=" << camo.itemSize
            << ",count=" << camo.itemCount << ",allocated=" << camo.itemAllocCount << "} "
            << "binding{base=" << binding.pool.unk << ",itemSize=" << binding.itemSize
            << ",count=" << binding.itemCount << ",allocated=" << binding.itemAllocCount << "} "
            << "material{base=" << material.pool.unk << ",itemSize=" << material.itemSize
            << ",count=" << material.itemCount << ",allocated=" << material.itemAllocCount << "} "
            << "image{base=" << image.pool.unk << ",itemSize=" << image.itemSize
            << ",count=" << image.itemCount << ",allocated=" << image.itemAllocCount << "} "
            << "customRoot=\"" << CamoRoot() << "\"";
        message = out.str();
        return camo.pool.unk && camo.itemSize != 0;
    }

    bool Dump(std::string& message)
    {
        std::lock_guard<std::mutex> lock(g_camoMutex);
        XAssetPool* pool = nullptr;
        if (!PoolReady(pool, message)) return false;

        CreateDirectoryA("logs", nullptr);
        std::ofstream file("logs\\camo\\weapon_camo_pool.csv", std::ios::trunc);
        if (!file)
        {
            message = "could not create logs\\camo\\weapon_camo_pool.csv";
            return false;
        }

        file << "index,address,name_hash,flags_or_type,definition_ptr,reserved\n";
        const auto base = reinterpret_cast<std::uintptr_t>(pool->pool.unk);
        const unsigned int count = static_cast<unsigned int>(std::max(0, pool->itemAllocCount));
        unsigned int readable = 0;

        for (unsigned int i = 0; i < count; ++i)
        {
            const auto address = base + static_cast<std::uintptr_t>(i) * pool->itemSize;
            unsigned char bytes[32]{};
            if (!CopyFromProcess(reinterpret_cast<const void*>(address), bytes, sizeof(bytes)))
                continue;

            std::uint64_t nameHash = 0, flagsOrType = 0, definition = 0, reserved = 0;
            std::memcpy(&nameHash, bytes + 0x00, 8);
            std::memcpy(&flagsOrType, bytes + 0x08, 8);
            std::memcpy(&definition, bytes + 0x10, 8);
            std::memcpy(&reserved, bytes + 0x18, 8);

            ++readable;
            file << i << ",0x" << std::hex << std::uppercase << address
                 << ",0x" << nameHash << ",0x" << flagsOrType
                 << ",0x" << definition << ",0x" << reserved
                 << std::dec << "\n";
        }

        std::ostringstream out;
        out << "dumped " << readable << "/" << count
            << " parsed weapon-camo entries to logs\\camo\\weapon_camo_pool.csv";
        message = out.str();
        return true;
    }

    bool InspectAll(std::string& message)
    {
        std::lock_guard<std::mutex> lock(g_camoMutex);
        XAssetPool* camoPool = nullptr;
        if (!PoolReady(camoPool, message)) return false;

        const auto& bindingPool = g_assetPool[ASSET_TYPE_WEAPONCAMOBINDING];
        const auto& materialPool = g_assetPool[ASSET_TYPE_MATERIAL];
        const auto& imagePool = g_assetPool[ASSET_TYPE_IMAGE];

        if (!bindingPool.pool.unk || !materialPool.pool.unk || !imagePool.pool.unk)
        {
            message = "binding/material/image pools are not ready";
            return false;
        }

        CreateDirectoryA("logs", nullptr);
        const std::string stamp = SnapshotStamp();
        const std::string prefix = "logs\\camo\\camo_snapshot_" + stamp;

        std::ofstream summary(prefix + "_00_summary.txt", std::ios::trunc);
        std::ofstream camoMap(prefix + "_camo_map.csv", std::ios::trunc);
        std::ofstream bindings(prefix + "_bindings.csv", std::ios::trunc);
        std::ofstream materials(prefix + "_materials.csv", std::ios::trunc);
        std::ofstream directImages(prefix + "_direct_images.csv", std::ios::trunc);
        std::ofstream bindingObjects(prefix + "_binding_objects.csv", std::ios::trunc);
        std::ofstream bindingObjectRefs(prefix + "_binding_object_refs.csv", std::ios::trunc);
        std::ofstream materialPointers(prefix + "_material_pointers.csv", std::ios::trunc);
        std::ofstream materialIndirect(prefix + "_material_indirect_refs.csv", std::ios::trunc);
        std::ofstream hotTransitions(prefix + "_transition_watch.csv", std::ios::trunc);

        if (!summary || !camoMap || !bindings || !materials || !directImages ||
            !bindingObjects || !bindingObjectRefs || !materialPointers ||
            !materialIndirect || !hotTransitions)
        {
            message = "could not create recursive camo inspection logs";
            return false;
        }

        struct CamoGroup
        {
            std::uint64_t nameHash = 0;
            std::uint64_t definition = 0;
            bool definitionReadable = false;
            std::vector<unsigned int> bindings;
            std::vector<unsigned int> materials;
            std::vector<unsigned int> images;
        };

        const auto camoBase = reinterpret_cast<std::uintptr_t>(camoPool->pool.unk);
        const auto bindingBase = reinterpret_cast<std::uintptr_t>(bindingPool.pool.unk);
        const auto materialBase = reinterpret_cast<std::uintptr_t>(materialPool.pool.unk);
        const auto imageBase = reinterpret_cast<std::uintptr_t>(imagePool.pool.unk);

        const unsigned int camoCount = static_cast<unsigned int>(std::max(0, camoPool->itemAllocCount));
        const unsigned int bindingCount = static_cast<unsigned int>(std::max(0, bindingPool.itemAllocCount));
        const unsigned int materialCount = static_cast<unsigned int>(std::max(0, materialPool.itemAllocCount));
        const unsigned int imageCount = static_cast<unsigned int>(std::max(0, imagePool.itemAllocCount));

        std::vector<CamoGroup> groups(camoCount);

        summary << "snapshot=" << stamp << "\n";
        summary << "weaponCamo_allocated=" << camoCount << "\n";
        summary << "binding_allocated=" << bindingCount << "\n";
        summary << "material_allocated=" << materialCount << "\n";
        summary << "image_allocated=" << imageCount << "\n";
        summary << "known_three_state_note=weapon-menu and camo-menu were identical; in-game previously removed slot57 and bindings 2661,2666,2667 and unloaded frontend material/image assets.\n";

        camoMap << "camo_index,name_hash,definition_ptr,readable,binding_count,material_count,direct_image_count\n";
        bindings << "camo_index,binding_index,binding_address,name_hash,flags,binding_object_ptr,owner_camo_ptr,object_region_type,object_readable_span\n";
        materials << "camo_index,definition_offset,material_index,material_address\n";
        directImages << "camo_index,definition_offset,image_index,image_address,image_interior_offset\n";
        bindingObjects << "camo_index,binding_index,object_ptr,region_type,read_span,unique_object\n";
        bindingObjectRefs << "camo_index,binding_index,object_ptr,object_offset,value,classification,pool_index,item_base,interior_offset\n";
        materialPointers << "camo_index,material_index,material_offset,pointer_value,region_type,read_span\n";
        materialIndirect << "camo_index,material_index,material_offset,pointer_value,child_offset,value,classification,pool_index,item_base,interior_offset\n";
        hotTransitions << "watch_type,index,reason,current_present,detail\n";

        // 1) Parse camo definitions and resource table.
        for (unsigned int i = 0; i < camoCount; ++i)
        {
            const auto entry = camoBase + static_cast<std::uintptr_t>(i) * camoPool->itemSize;
            unsigned char e[32]{};
            if (!CopyFromProcess(reinterpret_cast<const void*>(entry), e, sizeof(e))) continue;

            std::memcpy(&groups[i].nameHash, e + 0x00, 8);
            std::memcpy(&groups[i].definition, e + 0x10, 8);

            std::vector<unsigned char> def;
            if (!groups[i].definition || !ReadBlock(groups[i].definition, def, 0x2000))
                continue;
            groups[i].definitionReadable = true;

            for (std::size_t off = 0; off + 8 <= def.size(); off += 8)
            {
                std::uint64_t value = 0;
                std::memcpy(&value, def.data() + off, 8);
                PoolHit hit{};
                if (!ClassifyPoolPointerDeep(value, *camoPool, bindingPool, materialPool, imagePool, hit))
                    continue;

                if (!std::strcmp(hit.type, "MATERIAL"))
                {
                    if (std::find(groups[i].materials.begin(), groups[i].materials.end(), hit.index) == groups[i].materials.end())
                        groups[i].materials.push_back(hit.index);
                    materials << i << ",0x" << std::hex << std::uppercase << off << std::dec
                              << ',' << hit.index << ",0x" << std::hex << hit.itemBase << std::dec << "\n";
                }
                else if (!std::strcmp(hit.type, "IMAGE"))
                {
                    if (std::find(groups[i].images.begin(), groups[i].images.end(), hit.index) == groups[i].images.end())
                        groups[i].images.push_back(hit.index);
                    directImages << i << ",0x" << std::hex << std::uppercase << off << std::dec
                                 << ',' << hit.index << ",0x" << std::hex << hit.itemBase
                                 << ",0x" << hit.interiorOffset << std::dec << "\n";
                }
            }
        }

        // 2) Binding ownership + recursive follow of qword2 / +0x10.
        std::unordered_map<std::uint64_t, unsigned int> seenBindingObjects;
        unsigned int readableBindingObjects = 0;
        unsigned int bindingObjectPoolHits = 0;

        for (unsigned int i = 0; i < bindingCount; ++i)
        {
            const auto address = bindingBase + static_cast<std::uintptr_t>(i) * bindingPool.itemSize;
            unsigned char b[32]{};
            if (!CopyFromProcess(reinterpret_cast<const void*>(address), b, sizeof(b))) continue;

            std::uint64_t q[4]{};
            std::memcpy(q, b, sizeof(q));

            unsigned int camoIndex = 0;
            const bool owned = InPool(q[3], *camoPool, camoIndex) && camoIndex < groups.size();
            if (owned)
                groups[camoIndex].bindings.push_back(i);

            const auto span = SafeReadableSpan(q[2], 0x4000);
            const bool uniqueObject = q[2] && !seenBindingObjects.count(q[2]);
            if (uniqueObject) seenBindingObjects[q[2]] = i;

            bindings << (owned ? std::to_string(camoIndex) : std::string("-1")) << ',' << i
                     << ",0x" << std::hex << std::uppercase << address
                     << ",0x" << q[0] << ",0x" << q[1] << ",0x" << q[2] << ",0x" << q[3]
                     << std::dec << ',' << RegionTypeName(q[2]) << ',' << span << "\n";

            if (owned)
                bindingObjects << camoIndex << ',' << i << ",0x" << std::hex << std::uppercase << q[2]
                               << std::dec << ',' << RegionTypeName(q[2]) << ',' << span
                               << ',' << (uniqueObject ? 1 : 0) << "\n";

            if (!owned || !uniqueObject || span < 8)
                continue;

            std::vector<unsigned char> obj;
            if (!ReadBlock(q[2], obj, 0x4000))
                continue;
            ++readableBindingObjects;

            for (std::size_t off = 0; off + 8 <= obj.size(); off += 8)
            {
                std::uint64_t value = 0;
                std::memcpy(&value, obj.data() + off, 8);
                PoolHit hit{};
                if (!ClassifyPoolPointerDeep(value, *camoPool, bindingPool, materialPool, imagePool, hit))
                    continue;

                ++bindingObjectPoolHits;
                bindingObjectRefs << camoIndex << ',' << i
                                  << ",0x" << std::hex << std::uppercase << q[2]
                                  << ",0x" << off << ",0x" << value << ',' << hit.type
                                  << std::dec << ',' << hit.index
                                  << ",0x" << std::hex << hit.itemBase
                                  << ",0x" << hit.interiorOffset << std::dec << "\n";
            }
        }

        // 3) Follow pointer-valued fields from only the materials referenced by camo definitions.
        // First classify direct pool/interior hits; then dereference readable PRIVATE/MAPPED pointers
        // one level and search the child object for pool refs. This is the missing bridge candidate.
        std::unordered_map<std::uint64_t, bool> scannedChildPointers;
        unsigned int followedMaterials = 0;
        unsigned int readableMaterialPointers = 0;
        unsigned int materialIndirectPoolHits = 0;

        std::vector<unsigned char> mat(materialPool.itemSize);
        for (unsigned int camoIndex = 0; camoIndex < groups.size(); ++camoIndex)
        {
            for (unsigned int materialIndex : groups[camoIndex].materials)
            {
                if (materialIndex >= materialCount) continue;
                const auto matAddr = materialBase + static_cast<std::uintptr_t>(materialIndex) * materialPool.itemSize;
                if (!CopyFromProcess(reinterpret_cast<const void*>(matAddr), mat.data(), mat.size()))
                    continue;
                ++followedMaterials;

                for (std::size_t moff = 0; moff + 8 <= mat.size(); moff += 8)
                {
                    std::uint64_t ptr = 0;
                    std::memcpy(&ptr, mat.data() + moff, 8);

                    PoolHit direct{};
                    if (ClassifyPoolPointerDeep(ptr, *camoPool, bindingPool, materialPool, imagePool, direct))
                    {
                        materialIndirect << camoIndex << ',' << materialIndex
                                         << ",0x" << std::hex << std::uppercase << moff
                                         << ",0x" << ptr << ",0x0,0x" << ptr << ',' << direct.type
                                         << std::dec << ',' << direct.index
                                         << ",0x" << std::hex << direct.itemBase
                                         << ",0x" << direct.interiorOffset << std::dec << "\n";
                        ++materialIndirectPoolHits;
                        continue;
                    }

                    const auto span = SafeReadableSpan(ptr, 0x1000);
                    if (span < 16) continue;
                    const char* rtype = RegionTypeName(ptr);
                    if (std::strcmp(rtype, "PRIVATE") && std::strcmp(rtype, "MAPPED"))
                        continue;

                    materialPointers << camoIndex << ',' << materialIndex
                                     << ",0x" << std::hex << std::uppercase << moff
                                     << ",0x" << ptr << std::dec << ',' << rtype << ',' << span << "\n";
                    ++readableMaterialPointers;

                    // Deduplicate child scan globally. We still record which material pointed to it above.
                    if (scannedChildPointers.count(ptr))
                        continue;
                    scannedChildPointers[ptr] = true;

                    std::vector<unsigned char> child;
                    if (!ReadBlock(ptr, child, 0x1000))
                        continue;

                    for (std::size_t coff = 0; coff + 8 <= child.size(); coff += 8)
                    {
                        std::uint64_t value = 0;
                        std::memcpy(&value, child.data() + coff, 8);
                        PoolHit hit{};
                        if (!ClassifyPoolPointerDeep(value, *camoPool, bindingPool, materialPool, imagePool, hit))
                            continue;

                        ++materialIndirectPoolHits;
                        materialIndirect << camoIndex << ',' << materialIndex
                                         << ",0x" << std::hex << std::uppercase << moff
                                         << ",0x" << ptr << ",0x" << coff << ",0x" << value << ',' << hit.type
                                         << std::dec << ',' << hit.index
                                         << ",0x" << std::hex << hit.itemBase
                                         << ",0x" << hit.interiorOffset << std::dec << "\n";
                    }
                }
            }
        }

        // 4) Explicitly watch the state-sensitive records identified by the three real snapshots.
        const bool slot57 = camoCount > 57;
        hotTransitions << "CAMO,57,frontend-only slot observed in weapon/camo menus and absent in-game,"
                       << (slot57 ? 1 : 0) << ",allocated_camos=" << camoCount << "\n";

        for (unsigned int watchBinding : { 2660u, 2661u, 2666u, 2667u })
        {
            const bool present = watchBinding < bindingCount;
            hotTransitions << "BINDING," << watchBinding
                           << ",state-sensitive tail binding from three-state comparison,"
                           << (present ? 1 : 0);
            if (present)
            {
                const auto addr = bindingBase + static_cast<std::uintptr_t>(watchBinding) * bindingPool.itemSize;
                unsigned char b[32]{};
                if (CopyFromProcess(reinterpret_cast<const void*>(addr), b, sizeof(b)))
                {
                    std::uint64_t q[4]{};
                    std::memcpy(q, b, sizeof(q));
                    hotTransitions << ",q2=0x" << std::hex << std::uppercase << q[2]
                                   << " owner=0x" << q[3] << std::dec;
                }
            }
            hotTransitions << "\n";
        }

        // 5) Per-camo summary.
        unsigned int withBindings = 0, withMaterials = 0, withImages = 0;
        for (unsigned int i = 0; i < groups.size(); ++i)
        {
            const auto& g = groups[i];
            if (!g.bindings.empty()) ++withBindings;
            if (!g.materials.empty()) ++withMaterials;
            if (!g.images.empty()) ++withImages;

            camoMap << i << ",0x" << std::hex << std::uppercase << g.nameHash
                    << ",0x" << g.definition << std::dec
                    << ',' << (g.definitionReadable ? 1 : 0)
                    << ',' << g.bindings.size()
                    << ',' << g.materials.size()
                    << ',' << g.images.size() << "\n";
        }

        summary << "camos_with_bindings=" << withBindings << "\n";
        summary << "camos_with_materials=" << withMaterials << "\n";
        summary << "camos_with_direct_images=" << withImages << "\n";
        summary << "unique_binding_objects=" << seenBindingObjects.size() << "\n";
        summary << "readable_binding_objects=" << readableBindingObjects << "\n";
        summary << "binding_object_pool_hits=" << bindingObjectPoolHits << "\n";
        summary << "followed_materials=" << followedMaterials << "\n";
        summary << "readable_material_pointer_fields=" << readableMaterialPointers << "\n";
        summary << "material_indirect_pool_hits=" << materialIndirectPoolHits << "\n";
        summary << "transition_watch=slot57 plus bindings 2660/2661/2666/2667\n";

        std::ostringstream out;
        out << "recursive camo snapshot " << stamp
            << " complete: bindingObjects=" << seenBindingObjects.size()
            << " readableBindingObjects=" << readableBindingObjects
            << " bindingObjectRefs=" << bindingObjectPoolHits
            << " materialPointers=" << readableMaterialPointers
            << " indirectRefs=" << materialIndirectPoolHits
            << " prefix=" << prefix;
        message = out.str();
        return true;
    }

    bool ScanCamo(std::string& message, bool deep)
    {
        std::lock_guard<std::mutex> lock(g_camoMutex);

        if (!g_assetPool)
        {
            message = "asset pool table is unavailable";
            return false;
        }

        XAssetPool* camoPool =
            &g_assetPool[ASSET_TYPE_WEAPONCAMO];

        XAssetPool* bindingPool =
            &g_assetPool[ASSET_TYPE_WEAPONCAMOBINDING];

        XAssetPool* imagePool =
            &g_assetPool[ASSET_TYPE_IMAGE];

        if (!camoPool->pool.unk ||
            !bindingPool->pool.unk ||
            camoPool->itemSize == 0 ||
            bindingPool->itemSize == 0 ||
            camoPool->itemCount <= 0 ||
            bindingPool->itemCount <= 0)
        {
            message =
                "weapon-features/camo/binding pools are not ready";
            return false;
        }

        CreateDirectoryA("logs", nullptr);

        const std::string stamp =
            SnapshotStamp();

        const std::string prefix =
            "logs\\camo\\camo_scan_" +
            stamp;

        std::ofstream summary(
            prefix + "_00_summary.txt",
            std::ios::trunc);

        std::ofstream camoSlots(
            prefix + "_10_camo_slots.csv",
            std::ios::trunc);

        std::ofstream bindingSlots(
            prefix + "_20_camo_bindings.csv",
            std::ios::trunc);

        std::ofstream freeRanges(
            prefix + "_30_free_ranges.csv",
            std::ios::trunc);

        std::ofstream freeList(
            prefix + "_31_free_lists.csv",
            std::ios::trunc);

        std::ofstream poolFields(
            prefix + "_40_asset_pool_fields.csv",
            std::ios::trunc);

        std::ofstream imageTargets(
            prefix + "_50_image_gfx_targets.csv",
            std::ios::trunc);

        std::ofstream runtimeCandidates(
            prefix + "_60_runtime_camo_candidates.csv",
            std::ios::trunc);

        std::ofstream loadingCandidates(
            prefix + "_70_loading_enroll_render_candidates.txt",
            std::ios::trunc);

        std::ofstream runtimeArrays(
            prefix + "_61_runtime_array_scan.csv",
            std::ios::trunc);

        std::ofstream runtimeCounts(
            prefix + "_62_runtime_count_scan.csv",
            std::ios::trunc);

        std::ofstream execXrefs(
            prefix + "_80_exec_xrefs.csv",
            std::ios::trunc);

        std::ofstream heapArrays(
            prefix + "_81_heap_runtime_arrays.csv",
            std::ios::trunc);

        std::ofstream indexArrays(
            prefix + "_82_index_hash_arrays.csv",
            std::ios::trunc);

        std::ofstream candidateSummary(
            prefix + "_90_candidate_summary.txt",
            std::ios::trunc);

        std::ofstream targetedSnapshots(
            prefix + "_83_targeted_candidate_snapshots.csv",
            std::ios::trunc);

        std::ofstream pointerGraph(
            prefix + "_53_camo_pointer_graph.csv",
            std::ios::trunc);
        std::ofstream gfxChain(
            prefix + "_54_gfximage_chain.csv",
            std::ios::trunc);
        std::ofstream allocatorXrefs(
            prefix + "_72_allocator_xrefs.csv",
            std::ios::trunc);

        std::ofstream shaderLayers(
            prefix + "_51_shader_material_layers.csv",
            std::ios::trunc);

        std::ofstream shaderFloats(
            prefix + "_52_shader_float_candidates.csv",
            std::ios::trunc);

        std::ofstream extraSlots(
            prefix + "_71_extra_slot_candidates.csv",
            std::ios::trunc);

        std::ofstream fastIndexCandidates(
            prefix + "_84_fast_index_candidates.csv",
            std::ios::trunc);

        std::ofstream shaderSummary(
            prefix + "_91_shader_slot_summary.txt",
            std::ios::trunc);

        std::ofstream materialImages(
            prefix + "_55_material_image_endpoints.csv",
            std::ios::trunc);

        std::ofstream additiveRegistration(
            prefix + "_73_additive_registration.csv",
            std::ios::trunc);

        std::ofstream focusedSummary(
            prefix + "_92_focused_camo_summary.txt",
            std::ios::trunc);

        std::ofstream rankedLayers(
            prefix + "_57_ranked_layer_candidates.csv",
            std::ios::trunc);

        std::ofstream materialTables(
            prefix + "_58_material_texture_tables.csv",
            std::ios::trunc);

        std::ofstream genericPoolXrefs(
            prefix + "_74_generic_pool_allocator_xrefs.csv",
            std::ios::trunc);

        std::ofstream rankedSummary(
            prefix + "_93_ranked_layer_allocator_summary.txt",
            std::ios::trunc);

        std::ofstream material30Entries(
            prefix + "_59_material30_texture_entries.csv",
            std::ios::trunc);

        std::ofstream assetPoolBaseXrefs(
            prefix + "_75_assetpool_base_index_xrefs.csv",
            std::ios::trunc);

        std::ofstream phaseSummary(
            prefix + "_94_material30_assetpool_summary.txt",
            std::ios::trunc);

        std::ofstream material30Q0(
            prefix + "_60_material30_q0_table.csv",
            std::ios::trunc);

        std::ofstream bindingFreeWalk(
            prefix + "_76_binding_freelist_walk.csv",
            std::ios::trunc);

        std::ofstream assetPoolIndirect(
            prefix + "_77_assetpool_indirect_candidates.csv",
            std::ios::trunc);

        std::ofstream finalFocusedSummary(
            prefix + "_95_material_binding_pool_summary.txt",
            std::ios::trunc);

        std::ofstream semanticClusters(
            prefix + "_61_material_semantic_clusters.csv",
            std::ios::trunc);

        std::ofstream syntheticPreview(
            prefix + "_78_synthetic_additive_preview.txt",
            std::ios::trunc);

        std::ofstream menuCandidates(
            prefix + "_85_menu_enumeration_candidates.csv",
            std::ios::trunc);

        std::ofstream menuSummary(
            prefix + "_96_menu_vs_asset_summary.txt",
            std::ios::trunc);

        std::ofstream rankedMenuLists(
            prefix + "_86_ranked_menu_lists.csv",
            std::ios::trunc);

        std::ofstream menuStructureXrefs(
            prefix + "_87_menu_structure_xrefs.csv",
            std::ios::trunc);

        std::ofstream prototypeReadiness(
            prefix + "_97_prototype_readiness.txt",
            std::ios::trunc);

        std::ofstream registrationFieldCandidates(
            prefix + "_98_registration_field_candidates.csv",
            std::ios::trunc);

        std::ofstream registrationWindows(
            prefix + "_99_registration_function_windows.txt",
            std::ios::trunc);

        std::ofstream prototypeGateV2(
            prefix + "_100_prototype_gate_v2.txt",
            std::ios::trunc);

        std::ofstream decodedRegistration(
            prefix + "_101_decoded_registration_candidates.csv",
            std::ios::trunc);

        std::ofstream decodedWindows(
            prefix + "_102_decoded_registration_windows.txt",
            std::ios::trunc);

        std::ofstream prototypeGateV3(
            prefix + "_103_prototype_gate_v3.txt",
            std::ios::trunc);

        std::ofstream strictRegistration(
            prefix + "_104_strict_registration_candidates.csv",
            std::ios::trunc);

        std::ofstream strictWindows(
            prefix + "_105_strict_registration_windows.txt",
            std::ios::trunc);

        std::ofstream prototypeGateV4(
            prefix + "_106_prototype_gate_v4.txt",
            std::ios::trunc);

        if (!summary ||
            !camoSlots ||
            !bindingSlots ||
            !freeRanges ||
            !freeList ||
            !poolFields ||
            !imageTargets ||
            !runtimeCandidates ||
            !loadingCandidates ||
            !runtimeArrays ||
            !runtimeCounts ||
            !execXrefs ||
            !heapArrays ||
            !indexArrays ||
            !candidateSummary ||
            !targetedSnapshots ||
            !pointerGraph ||
            !gfxChain ||
            !allocatorXrefs ||
            !shaderLayers ||
            !shaderFloats ||
            !extraSlots ||
            !fastIndexCandidates ||
            !shaderSummary ||
            !materialImages ||
            !additiveRegistration ||
            !focusedSummary ||
            !rankedLayers ||
            !materialTables ||
            !genericPoolXrefs ||
            !rankedSummary ||
            !material30Entries ||
            !assetPoolBaseXrefs ||
            !phaseSummary ||
            !material30Q0 ||
            !bindingFreeWalk ||
            !assetPoolIndirect ||
            !finalFocusedSummary ||
            !semanticClusters ||
            !syntheticPreview ||
            !menuCandidates ||
            !menuSummary ||
            !rankedMenuLists ||
            !menuStructureXrefs ||
            !prototypeReadiness ||
            !registrationFieldCandidates ||
            !registrationWindows ||
            !prototypeGateV2 ||
            !decodedRegistration ||
            !decodedWindows ||
            !prototypeGateV3 ||
            !strictRegistration ||
            !strictWindows ||
            !prototypeGateV4)
        {
            message =
                "could not create camo slot scan logs";
            return false;
        }

        const auto camoBase =
            reinterpret_cast<std::uintptr_t>(
                camoPool->pool.unk);

        const auto bindingBase =
            reinterpret_cast<std::uintptr_t>(
                bindingPool->pool.unk);

        const unsigned int camoCapacity =
            static_cast<unsigned int>(
                std::max(0, camoPool->itemCount));

        const unsigned int camoAllocated =
            static_cast<unsigned int>(
                std::max(0, camoPool->itemAllocCount));

        const unsigned int bindingCapacity =
            static_cast<unsigned int>(
                std::max(0, bindingPool->itemCount));

        const unsigned int bindingAllocated =
            static_cast<unsigned int>(
                std::max(0, bindingPool->itemAllocCount));

        auto nonZeroRecord =
            [](const unsigned char* bytes,
               std::size_t size)
            {
                for (std::size_t i = 0;
                     i < size;
                     ++i)
                {
                    if (bytes[i] != 0)
                        return true;
                }

                return false;
            };

        struct SlotState
        {
            bool readable = false;
            bool nonZero = false;
        };

        std::vector<SlotState> camoStates(
            camoCapacity);

        std::vector<SlotState> bindingStates(
            bindingCapacity);

        camoSlots
            << "index,address,inside_allocated_count,"
               "readable,nonzero,state,"
               "q0_name_hash,q1_flags_type,"
               "q2_definition,q3_reserved,"
               "q2_region,q2_readable_span\n";

        unsigned int camoReadable = 0;
        unsigned int camoNonZero = 0;
        unsigned int camoNonZeroPastAllocated = 0;
        unsigned int camoZeroInsideAllocated = 0;

        for (unsigned int i = 0;
             i < camoCapacity;
             ++i)
        {
            const auto address =
                camoBase +
                static_cast<std::uintptr_t>(i) *
                camoPool->itemSize;

            unsigned char bytes[32]{};

            const bool readable =
                CopyFromProcess(
                    reinterpret_cast<const void*>(
                        address),
                    bytes,
                    sizeof(bytes));

            const bool nonzero =
                readable &&
                nonZeroRecord(
                    bytes,
                    sizeof(bytes));

            camoStates[i] =
                { readable, nonzero };

            if (readable)
                ++camoReadable;

            if (nonzero)
                ++camoNonZero;

            if (i >= camoAllocated &&
                nonzero)
            {
                ++camoNonZeroPastAllocated;
            }

            if (i < camoAllocated &&
                readable &&
                !nonzero)
            {
                ++camoZeroInsideAllocated;
            }

            std::uint64_t q[4]{};

            if (readable)
                std::memcpy(q, bytes, sizeof(q));

            const char* state =
                !readable
                ? "UNREADABLE"
                : nonzero
                    ? (i < camoAllocated
                        ? "ALLOCATED_NONZERO"
                        : "TAIL_NONZERO")
                    : (i < camoAllocated
                        ? "ALLOCATED_ZERO"
                        : "FREE_ZERO");

            camoSlots
                << i
                << ",0x"
                << std::hex
                << std::uppercase
                << address
                << std::dec
                << ','
                << (i < camoAllocated ? 1 : 0)
                << ','
                << (readable ? 1 : 0)
                << ','
                << (nonzero ? 1 : 0)
                << ','
                << state
                << ",0x"
                << std::hex
                << std::uppercase
                << q[0]
                << ",0x"
                << q[1]
                << ",0x"
                << q[2]
                << ",0x"
                << q[3]
                << std::dec
                << ','
                << RegionTypeName(q[2])
                << ','
                << SafeReadableSpan(
                       q[2],
                       0x4000)
                << "\n";
        }

        bindingSlots
            << "index,address,inside_allocated_count,"
               "readable,nonzero,state,"
               "q0_name_hash,q1_flags,"
               "q2_binding_object,q3_owner_camo,"
               "owner_camo_index,owner_is_pool_slot,"
               "object_region,object_readable_span\n";

        unsigned int bindingReadable = 0;
        unsigned int bindingNonZero = 0;
        unsigned int bindingNonZeroPastAllocated = 0;
        unsigned int bindingZeroInsideAllocated = 0;
        unsigned int bindingOwnersInCamoPool = 0;

        for (unsigned int i = 0;
             i < bindingCapacity;
             ++i)
        {
            const auto address =
                bindingBase +
                static_cast<std::uintptr_t>(i) *
                bindingPool->itemSize;

            unsigned char bytes[32]{};

            const bool readable =
                CopyFromProcess(
                    reinterpret_cast<const void*>(
                        address),
                    bytes,
                    sizeof(bytes));

            const bool nonzero =
                readable &&
                nonZeroRecord(
                    bytes,
                    sizeof(bytes));

            bindingStates[i] =
                { readable, nonzero };

            if (readable)
                ++bindingReadable;

            if (nonzero)
                ++bindingNonZero;

            if (i >= bindingAllocated &&
                nonzero)
            {
                ++bindingNonZeroPastAllocated;
            }

            if (i < bindingAllocated &&
                readable &&
                !nonzero)
            {
                ++bindingZeroInsideAllocated;
            }

            std::uint64_t q[4]{};

            if (readable)
                std::memcpy(q, bytes, sizeof(q));

            unsigned int ownerIndex = 0;

            const bool ownerInPool =
                InPool(
                    q[3],
                    *camoPool,
                    ownerIndex);

            if (ownerInPool)
                ++bindingOwnersInCamoPool;

            const char* state =
                !readable
                ? "UNREADABLE"
                : nonzero
                    ? (i < bindingAllocated
                        ? "ALLOCATED_NONZERO"
                        : "TAIL_NONZERO")
                    : (i < bindingAllocated
                        ? "ALLOCATED_ZERO"
                        : "FREE_ZERO");

            bindingSlots
                << i
                << ",0x"
                << std::hex
                << std::uppercase
                << address
                << std::dec
                << ','
                << (i < bindingAllocated ? 1 : 0)
                << ','
                << (readable ? 1 : 0)
                << ','
                << (nonzero ? 1 : 0)
                << ','
                << state
                << ",0x"
                << std::hex
                << std::uppercase
                << q[0]
                << ",0x"
                << q[1]
                << ",0x"
                << q[2]
                << ",0x"
                << q[3]
                << std::dec
                << ','
                << (ownerInPool
                    ? std::to_string(ownerIndex)
                    : std::string("-1"))
                << ','
                << (ownerInPool ? 1 : 0)
                << ','
                << RegionTypeName(q[2])
                << ','
                << SafeReadableSpan(
                       q[2],
                       0x4000)
                << "\n";
        }

        auto dumpFreeRanges =
            [&](const char* poolName,
                const std::vector<SlotState>& states,
                unsigned int allocated)
            {
                unsigned int i = 0;

                while (i < states.size())
                {
                    const bool freeCandidate =
                        states[i].readable &&
                        !states[i].nonZero;

                    if (!freeCandidate)
                    {
                        ++i;
                        continue;
                    }

                    const unsigned int begin = i;

                    while (i + 1 < states.size() &&
                           states[i + 1].readable &&
                           !states[i + 1].nonZero)
                    {
                        ++i;
                    }

                    const unsigned int finish = i;

                    freeRanges
                        << poolName
                        << ','
                        << begin
                        << ','
                        << finish
                        << ','
                        << (finish - begin + 1)
                        << ','
                        << (begin >= allocated
                            ? "AFTER_ALLOCATED_COUNT"
                            : finish < allocated
                                ? "INSIDE_ALLOCATED_COUNT"
                                : "CROSSES_ALLOCATED_COUNT")
                        << "\n";

                    ++i;
                }
            };

        freeRanges
            << "pool,start_index,end_index,length,location\n";

        dumpFreeRanges(
            "WEAPONCAMO",
            camoStates,
            camoAllocated);

        dumpFreeRanges(
            "WEAPONCAMOBINDING",
            bindingStates,
            bindingAllocated);

        // Dump XAssetPool field addresses as well as values. These addresses
        // are useful later when correlating UI/menu code that reads pool
        // capacity/allocation counts.
        auto dumpPoolFields =
            [&](const char* name,
                XAssetPool* pool)
            {
                const auto poolStruct =
                    reinterpret_cast<std::uintptr_t>(
                        pool);

                poolFields
                    << name
                    << ",pool_struct,0x"
                    << std::hex
                    << std::uppercase
                    << poolStruct
                    << std::dec
                    << "\n";

                poolFields
                    << name
                    << ",pool_base_field,0x"
                    << std::hex
                    << std::uppercase
                    << reinterpret_cast<std::uintptr_t>(
                           &pool->pool)
                    << ",value=0x"
                    << reinterpret_cast<std::uintptr_t>(
                           pool->pool.unk)
                    << std::dec
                    << "\n";

                poolFields
                    << name
                    << ",itemSize_field,0x"
                    << std::hex
                    << std::uppercase
                    << reinterpret_cast<std::uintptr_t>(
                           &pool->itemSize)
                    << std::dec
                    << ",value="
                    << pool->itemSize
                    << "\n";

                poolFields
                    << name
                    << ",itemCount_field,0x"
                    << std::hex
                    << std::uppercase
                    << reinterpret_cast<std::uintptr_t>(
                           &pool->itemCount)
                    << std::dec
                    << ",value="
                    << pool->itemCount
                    << "\n";

                poolFields
                    << name
                    << ",itemAllocCount_field,0x"
                    << std::hex
                    << std::uppercase
                    << reinterpret_cast<std::uintptr_t>(
                           &pool->itemAllocCount)
                    << std::dec
                    << ",value="
                    << pool->itemAllocCount
                    << "\n";

                poolFields
                    << name
                    << ",freeHead_field,0x"
                    << std::hex
                    << std::uppercase
                    << reinterpret_cast<std::uintptr_t>(
                           &pool->freeHead)
                    << ",value=0x"
                    << reinterpret_cast<std::uintptr_t>(
                           pool->freeHead)
                    << std::dec
                    << "\n";
            };

        poolFields
            << "pool,field,address_or_value,extra\n";

        dumpPoolFields(
            "WEAPONCAMO",
            camoPool);

        dumpPoolFields(
            "WEAPONCAMOBINDING",
            bindingPool);

        // Follow each pool's AssetLink free list read-only. Stop on loops,
        // invalid pointers, or a conservative capacity-sized limit.
        auto dumpFreeList =
            [&](const char* poolName,
                XAssetPool* pool,
                std::uintptr_t base,
                unsigned int capacity)
            {
                std::unordered_map<
                    std::uintptr_t,
                    bool> seen;

                AssetLink* node =
                    pool->freeHead;

                unsigned int ordinal = 0;

                while (node &&
                       ordinal <= capacity)
                {
                    const auto address =
                        reinterpret_cast<std::uintptr_t>(
                            node);

                    if (seen.count(address))
                    {
                        freeList
                            << poolName
                            << ','
                            << ordinal
                            << ",0x"
                            << std::hex
                            << std::uppercase
                            << address
                            << std::dec
                            << ",-1,LOOP\n";
                        break;
                    }

                    seen[address] = true;

                    long long slotIndex = -1;

                    if (address >= base &&
                        pool->itemSize != 0)
                    {
                        const auto delta =
                            address - base;

                        if (delta %
                                pool->itemSize ==
                            0)
                        {
                            const auto candidate =
                                delta /
                                pool->itemSize;

                            if (candidate <
                                capacity)
                            {
                                slotIndex =
                                    static_cast<long long>(
                                        candidate);
                            }
                        }
                    }

                    AssetLink next{};

                    if (!CopyFromProcess(
                            node,
                            &next,
                            sizeof(next)))
                    {
                        freeList
                            << poolName
                            << ','
                            << ordinal
                            << ",0x"
                            << std::hex
                            << std::uppercase
                            << address
                            << std::dec
                            << ','
                            << slotIndex
                            << ",UNREADABLE\n";
                        break;
                    }

                    freeList
                        << poolName
                        << ','
                        << ordinal
                        << ",0x"
                        << std::hex
                        << std::uppercase
                        << address
                        << ",0x"
                        << reinterpret_cast<std::uintptr_t>(
                               next.next)
                        << std::dec
                        << ','
                        << slotIndex
                        << ",OK\n";

                    node =
                        next.next;

                    ++ordinal;
                }
            };

        freeList
            << "pool,ordinal,address,next,slot_index,state\n";

        dumpFreeList(
            "WEAPONCAMO",
            camoPool,
            camoBase,
            camoCapacity);

        dumpFreeList(
            "WEAPONCAMOBINDING",
            bindingPool,
            bindingBase,
            bindingCapacity);



        // [CAMO POINTER GRAPH]
        pointerGraph
            << "label,camo_slot,depth,path,node_address,node_offset,raw64,"
               "target_class,pool_index,target_region,target_readable_span,"
               "confidence,notes\n";

        struct CamoGraphNode
        {
            std::uint64_t address = 0;
            unsigned int depth = 0;
            std::string path;
        };

        const unsigned int graphMaxDepth = deep ? 3u : 2u;
        const std::size_t graphNodeBytes = deep ? 0x400u : 0x180u;
        const unsigned int graphBudgetPerCamo = deep ? 160u : 48u;

        XAssetPool* graphMaterialPool =
            &g_assetPool[ASSET_TYPE_MATERIAL];

        auto classifyGraphTarget =
            [&](std::uint64_t value,
                const char*& klass,
                long long& poolIndex)
            {
                klass = "READABLE_POINTER";
                poolIndex = -1;

                if (!value)
                {
                    klass = "NULL";
                    return;
                }

                unsigned int idx = 0;

                if (imagePool && InPool(value, *imagePool, idx))
                {
                    klass = "CAMO_IMAGE_TARGET";
                    poolIndex = static_cast<long long>(idx);
                    return;
                }

                if (graphMaterialPool &&
                    graphMaterialPool->pool.unk &&
                    InPool(value, *graphMaterialPool, idx))
                {
                    klass = "CAMO_MATERIAL_TARGET";
                    poolIndex = static_cast<long long>(idx);
                    return;
                }

                if (InPool(value, *camoPool, idx))
                {
                    klass = "WEAPONCAMO_TARGET";
                    poolIndex = static_cast<long long>(idx);
                    return;
                }

                if (bindingPool &&
                    InPool(value, *bindingPool, idx))
                {
                    klass = "CAMOBINDING_TARGET";
                    poolIndex = static_cast<long long>(idx);
                    return;
                }
            };

        unsigned int pointerGraphHits = 0;
        unsigned int imageGraphHits = 0;
        unsigned int materialGraphHits = 0;

        for (unsigned int ci = 0; ci < camoAllocated; ++ci)
        {
            const auto recAddr =
                camoBase +
                static_cast<std::uintptr_t>(ci) *
                camoPool->itemSize;

            unsigned char rec[32]{};

            if (!CopyFromProcess(
                    reinterpret_cast<const void*>(recAddr),
                    rec,
                    sizeof(rec)))
            {
                continue;
            }

            std::uint64_t definition = 0;
            std::memcpy(&definition, rec + 0x10, sizeof(definition));

            if (!definition)
                continue;

            std::vector<CamoGraphNode> queue;
            std::vector<std::uint64_t> visited;
            queue.push_back({definition, 0u, "+0x10"});

            unsigned int budget = graphBudgetPerCamo;

            for (std::size_t qi = 0;
                 qi < queue.size() && budget > 0;
                 ++qi)
            {
                const auto node = queue[qi];

                if (!node.address || node.depth > graphMaxDepth)
                    continue;

                if (std::find(
                        visited.begin(),
                        visited.end(),
                        node.address) != visited.end())
                {
                    continue;
                }

                visited.push_back(node.address);

                const auto span =
                    SafeReadableSpan(node.address, graphNodeBytes);

                if (span < 8)
                    continue;

                std::vector<unsigned char> bytes(span);

                if (!CopyFromProcess(
                        reinterpret_cast<const void*>(node.address),
                        bytes.data(),
                        bytes.size()))
                {
                    continue;
                }

                for (std::size_t off = 0;
                     off + 8 <= bytes.size() && budget > 0;
                     off += 8)
                {
                    std::uint64_t value = 0;
                    std::memcpy(&value, bytes.data() + off, sizeof(value));

                    if (!value)
                        continue;

                    const char* klass = nullptr;
                    long long poolIndex = -1;
                    classifyGraphTarget(value, klass, poolIndex);

                    const auto readable =
                        SafeReadableSpan(value, 0x200);

                    const bool imageHit =
                        std::strcmp(klass, "CAMO_IMAGE_TARGET") == 0;
                    const bool materialHit =
                        std::strcmp(klass, "CAMO_MATERIAL_TARGET") == 0;
                    const bool terminal =
                        imageHit || materialHit;

                    if (!terminal && readable < 8)
                        continue;

                    std::ostringstream path;
                    path
                        << node.path
                        << "->+0x"
                        << std::hex
                        << std::uppercase
                        << off;

                    const char* confidence =
                        terminal
                        ? (node.depth <= 1 ? "HIGH" : "MEDIUM")
                        : "LOW";

                    pointerGraph
                        << (terminal
                            ? "CAMO_LAYER_GRAPH_HIT"
                            : "CAMO_POINTER_GRAPH")
                        << ','
                        << ci
                        << ','
                        << node.depth
                        << ",\""
                        << path.str()
                        << "\",0x"
                        << std::hex
                        << std::uppercase
                        << node.address
                        << std::dec
                        << ','
                        << off
                        << ",0x"
                        << std::hex
                        << std::uppercase
                        << value
                        << std::dec
                        << ','
                        << klass
                        << ','
                        << poolIndex
                        << ','
                        << RegionTypeName(value)
                        << ','
                        << readable
                        << ','
                        << confidence
                        << ','
                        << (terminal
                            ? "candidate shader layer endpoint; compare path across stock camos"
                            : "intermediate readable pointer")
                        << "\n";

                    ++pointerGraphHits;
                    if (imageHit) ++imageGraphHits;
                    if (materialHit) ++materialGraphHits;
                    --budget;

                    if (!terminal &&
                        node.depth < graphMaxDepth &&
                        readable >= 8)
                    {
                        queue.push_back({
                            value,
                            node.depth + 1,
                            path.str()
                        });
                    }
                }
            }
        }

        pointerGraph.flush();

        // [GFXIMAGE 23956 RAW CHAIN]
        gfxChain
            << "label,field_offset,field_name,raw64,region,readable_span,"
               "q0,q1,q2,q3,q4,q5,q6,q7,notes\n";

        if (imagePool &&
            imagePool->pool.unk &&
            imagePool->itemSize >= 0x28 &&
            imagePool->itemAllocCount > 23956)
        {
            const auto imageRecord =
                reinterpret_cast<std::uintptr_t>(imagePool->pool.unk) +
                static_cast<std::uintptr_t>(23956) *
                imagePool->itemSize;

            unsigned char imageRec[64]{};

            if (CopyFromProcess(
                    reinterpret_cast<const void*>(imageRecord),
                    imageRec,
                    sizeof(imageRec)))
            {
                const std::size_t fields[] = {0x10u, 0x18u, 0x20u};

                for (const auto fieldOff : fields)
                {
                    std::uint64_t value = 0;
                    std::memcpy(
                        &value,
                        imageRec + fieldOff,
                        sizeof(value));

                    std::uint64_t q[8]{};
                    const auto span =
                        SafeReadableSpan(value, sizeof(q));

                    if (span >= sizeof(q))
                    {
                        CopyFromProcess(
                            reinterpret_cast<const void*>(value),
                            q,
                            sizeof(q));
                    }

                    const char* name =
                        fieldOff == 0x10
                        ? "Q2_STREAM_OR_TEXTURE_DESCRIPTOR"
                        : fieldOff == 0x18
                            ? "Q3_CONFIRMED_D3D12_RESOURCE"
                            : "Q4_RUNTIME_TEXTURE_STATE";

                    gfxChain
                        << "GFXIMAGE_23956_CHAIN,"
                        << fieldOff
                        << ','
                        << name
                        << ",0x"
                        << std::hex
                        << std::uppercase
                        << value
                        << std::dec
                        << ','
                        << RegionTypeName(value)
                        << ','
                        << span;

                    for (const auto x : q)
                    {
                        gfxChain
                            << ",0x"
                            << std::hex
                            << std::uppercase
                            << x
                            << std::dec;
                    }

                    gfxChain
                        << ','
                        << (fieldOff == 0x18
                            ? "confirmed resource; raw inspection only, no recursive COM probing"
                            : "raw readable child candidate; diff across texture/camo states")
                        << "\n";
                }
            }
        }

        gfxChain.flush();

        // -----------------------------------------------------------------
        // [IMAGE/GFXIMAGE TARGETS]
        // Dump current image-pool metadata and the confirmed image 23956
        // record plus nearby records. This helps us move from overwrite-only
        // uploads toward creating/registering resident images like MW2019.
        // -----------------------------------------------------------------
        imageTargets
            << "section,index,address,item_size,allocated,readable,"
               "q0,q1,q2,q3,q4,q5,q6,q7\n";

        if (imagePool->pool.unk &&
            imagePool->itemSize > 0 &&
            imagePool->itemCount > 0)
        {
            const auto imageBase =
                reinterpret_cast<std::uintptr_t>(
                    imagePool->pool.unk);

            const unsigned int imageCapacity =
                static_cast<unsigned int>(
                    std::max(0, imagePool->itemCount));

            const unsigned int imageAllocated =
                static_cast<unsigned int>(
                    std::max(0, imagePool->itemAllocCount));

            const unsigned int watchBegin =
                23956 > 8 ? 23956 - 8 : 0;

            const unsigned int watchEnd =
                std::min<unsigned int>(
                    imageCapacity,
                    23956 + 9);

            for (unsigned int i = watchBegin;
                 i < watchEnd;
                 ++i)
            {
                const auto address =
                    imageBase +
                    static_cast<std::uintptr_t>(i) *
                    imagePool->itemSize;

                unsigned char bytes[64]{};

                const bool readable =
                    CopyFromProcess(
                        reinterpret_cast<const void*>(
                            address),
                        bytes,
                        sizeof(bytes));

                std::uint64_t q[8]{};

                if (readable)
                    std::memcpy(q, bytes, sizeof(q));

                imageTargets
                    << "GFXIMAGE_NEAR_CONFIRMED,"
                    << i
                    << ",0x"
                    << std::hex
                    << std::uppercase
                    << address
                    << std::dec
                    << ','
                    << imagePool->itemSize
                    << ','
                    << (i < imageAllocated ? 1 : 0)
                    << ','
                    << (readable ? 1 : 0);

                for (const auto value : q)
                {
                    imageTargets
                        << ",0x"
                        << std::hex
                        << std::uppercase
                        << value
                        << std::dec;
                }

                imageTargets << "\n";
            }

            imageTargets
                << "IMAGE_POOL_META,-1,0x"
                << std::hex
                << std::uppercase
                << imageBase
                << std::dec
                << ','
                << imagePool->itemSize
                << ','
                << imageAllocated
                << ",1,0x"
                << std::hex
                << std::uppercase
                << reinterpret_cast<std::uintptr_t>(
                       imagePool->freeHead)
                << std::dec
                << ",0x"
                << imageCapacity
                << ",0x0,0x0,0x0,0x0,0x0,0x0\n";
        }
        else
        {
            imageTargets
                << "IMAGE_POOL_UNAVAILABLE,-1,0,0,0,0,0,0,0,0,0,0,0,0\n";
        }


        // -----------------------------------------------------------------
        // [CAMO SHADER / MATERIAL LAYER DISCOVERY]
        // -----------------------------------------------------------------
        shaderLayers
            << "label,camo_slot,record,definition,offset,raw64,pointer_class,pool_index,notes\n";

        shaderFloats
            << "label,camo_slot,definition,offset,value,raw32,near_pointer,notes\n";

        XAssetPool* materialPool =
            &g_assetPool[ASSET_TYPE_MATERIAL];

        const auto materialBase =
            materialPool && materialPool->pool.unk
            ? reinterpret_cast<std::uintptr_t>(materialPool->pool.unk)
            : 0;

        const unsigned int materialCapacity =
            materialPool
            ? static_cast<unsigned int>(std::max(0, materialPool->itemCount))
            : 0;

        unsigned int readableDefinitions = 0;
        unsigned int shaderImagePtrs = 0;
        unsigned int shaderMaterialPtrs = 0;
        unsigned int shaderFloatCount = 0;

        const std::size_t definitionLimit =
            deep ? 0x800u : 0x200u;

        for (unsigned int ci = 0;
             ci < camoAllocated;
             ++ci)
        {
            const auto recordAddress =
                camoBase +
                static_cast<std::uintptr_t>(ci) *
                camoPool->itemSize;

            unsigned char record[32]{};

            if (!CopyFromProcess(
                    reinterpret_cast<const void*>(recordAddress),
                    record,
                    sizeof(record)))
            {
                continue;
            }

            std::uint64_t definition = 0;
            std::memcpy(
                &definition,
                record + 0x10,
                sizeof(definition));

            const auto span =
                SafeReadableSpan(
                    definition,
                    definitionLimit);

            if (!definition || span < 8)
                continue;

            ++readableDefinitions;

            std::vector<unsigned char> bytes(span);

            if (!CopyFromProcess(
                    reinterpret_cast<const void*>(definition),
                    bytes.data(),
                    bytes.size()))
            {
                continue;
            }

            std::vector<std::size_t> pointerOffsets;

            for (std::size_t off = 0;
                 off + 8 <= bytes.size();
                 off += 8)
            {
                std::uint64_t value = 0;
                std::memcpy(
                    &value,
                    bytes.data() + off,
                    sizeof(value));

                const char* label = nullptr;
                long long poolIndex = -1;
                unsigned int poolIdx = 0;

                if (imagePool &&
                    InPool(value, *imagePool, poolIdx))
                {
                    label = "CAMO_IMAGE_PTR";
                    poolIndex = static_cast<long long>(poolIdx);
                    ++shaderImagePtrs;
                }
                else if (materialPool &&
                         materialPool->pool.unk &&
                         materialPool->itemSize > 0 &&
                         value >= materialBase &&
                         value < materialBase +
                            static_cast<std::uintptr_t>(materialCapacity) *
                            materialPool->itemSize)
                {
                    const auto delta =
                        static_cast<std::uintptr_t>(value) - materialBase;

                    if ((delta % materialPool->itemSize) == 0)
                    {
                        label = "CAMO_MATERIAL_PTR";
                        poolIndex = static_cast<long long>(delta / materialPool->itemSize);
                        ++shaderMaterialPtrs;
                    }
                }

                if (!label)
                    continue;

                pointerOffsets.push_back(off);

                shaderLayers
                    << label << ',' << ci
                    << ",0x" << std::hex << std::uppercase << recordAddress
                    << ",0x" << definition << std::dec
                    << ',' << off
                    << ",0x" << std::hex << std::uppercase << value << std::dec
                    << ',' << label
                    << ',' << poolIndex
                    << ",candidate layer/material pointer; diff stock camos to classify color/normal/mask/layer0/layer1\n";
            }

            for (std::size_t off = 0;
                 off + 4 <= bytes.size();
                 off += 4)
            {
                float value = 0.0f;
                std::uint32_t raw = 0;

                std::memcpy(&value, bytes.data() + off, sizeof(value));
                std::memcpy(&raw, bytes.data() + off, sizeof(raw));

                if (!std::isfinite(value) || value < -64.0f || value > 64.0f)
                    continue;

                if (value != 0.0f && std::fabs(value) < 0.000001f)
                    continue;

                bool nearPointer = false;

                for (const auto p : pointerOffsets)
                {
                    const auto d = off > p ? off - p : p - off;
                    if (d <= 0x30)
                    {
                        nearPointer = true;
                        break;
                    }
                }

                if (!deep && !nearPointer && (value < -8.0f || value > 8.0f))
                    continue;

                ++shaderFloatCount;

                shaderFloats
                    << "CAMO_SHADER_FLOAT," << ci
                    << ",0x" << std::hex << std::uppercase << definition << std::dec
                    << ',' << off
                    << ',' << value
                    << ",0x" << std::hex << std::uppercase << raw << std::dec
                    << ',' << (nearPointer ? 1 : 0)
                    << ','
                    << (nearPointer
                        ? "high-interest UV/scroll/scale/rotate/blend/tint candidate"
                        : "diff before assigning semantic role")
                    << "\n";
            }
        }

        shaderLayers.flush();
        shaderFloats.flush();

        // -----------------------------------------------------------------
        // [EXTRA CAMO SLOT / ADDITIVE CAPACITY CANDIDATES]
        // -----------------------------------------------------------------
        extraSlots
            << "label,pool,candidate_index,address,item_count,item_alloc_count,free_head,confidence,notes\n";

        if (camoAllocated < camoCapacity)
        {
            extraSlots
                << "NEXT_ALLOC_INDEX,WEAPONCAMO," << camoAllocated
                << ",0x" << std::hex << std::uppercase
                << (camoBase + static_cast<std::uintptr_t>(camoAllocated) * camoPool->itemSize)
                << std::dec << ',' << camoCapacity << ',' << camoAllocated
                << ",0x" << std::hex << std::uppercase
                << reinterpret_cast<std::uintptr_t>(camoPool->freeHead)
                << std::dec
                << ",MEDIUM,candidate only; resolve DB/add-asset path before writing\n";
        }

        if (bindingAllocated < bindingCapacity)
        {
            extraSlots
                << "NEXT_ALLOC_INDEX,WEAPONCAMOBINDING," << bindingAllocated
                << ",0x" << std::hex << std::uppercase
                << (bindingBase + static_cast<std::uintptr_t>(bindingAllocated) * bindingPool->itemSize)
                << std::dec << ',' << bindingCapacity << ',' << bindingAllocated
                << ",0x" << std::hex << std::uppercase
                << reinterpret_cast<std::uintptr_t>(bindingPool->freeHead)
                << std::dec
                << ",MEDIUM,candidate only; resolve allocator/enrollment first\n";
        }

        extraSlots
            << "FREEHEAD,WEAPONCAMO,-1,0x"
            << std::hex << std::uppercase
            << reinterpret_cast<std::uintptr_t>(camoPool->freeHead)
            << std::dec << ',' << camoCapacity << ',' << camoAllocated
            << ",0x" << std::hex << std::uppercase
            << reinterpret_cast<std::uintptr_t>(camoPool->freeHead)
            << std::dec
            << ",HIGH,actual asset-pool allocator freeHead\n";

        extraSlots.flush();

        shaderSummary
            << "[CAMO SHADER / EXTRA SLOT RESEARCH]\n"
            << "mode=" << (deep ? "DEEP" : "FAST") << "\n"
            << "readable_definitions=" << readableDefinitions << "\n"
            << "image_pointer_fields=" << shaderImagePtrs << "\n"
            << "material_pointer_fields=" << shaderMaterialPtrs << "\n"
            << "shader_float_fields=" << shaderFloatCount << "\n"
            << "weaponCamo=" << camoAllocated << '/' << camoCapacity << "\n"
            << "binding=" << bindingAllocated << '/' << bindingCapacity << "\n\n"
            << "[ROLES TO CONFIRM]\n"
            << "CAMO_LAYER0_COLOR\nCAMO_LAYER1_COLOR\n"
            << "CAMO_LAYER0_NORMAL\nCAMO_LAYER1_NORMAL\n"
            << "CAMO_LAYER0_MASK_OR_GRAY\nCAMO_LAYER1_MASK_OR_GRAY\n"
            << "CAMO_UV_SCALE\nCAMO_UV_OFFSET_OR_SCROLL\nCAMO_UV_ROTATE\n"
            << "CAMO_BLEND_MODE\nCAMO_TINT\nCAMO_MATERIAL_PTR\n\n"
            << "[TEST]\n"
            << "Scan plain stock camo, then multi-layer/animated stock camo, then another category. Diff _51/_52.\n"
            << "Use _71 with free-list/xref logs to find additive registration rather than overwriting stock camos.\n";

        shaderSummary.flush();

        // -----------------------------------------------------------------
        // [FOCUSED MATERIAL -> GFXIMAGE ENDPOINT DISCOVERY]
        //
        // Prior scans showed hundreds of material endpoints. Walk each
        // reachable material record one level deeper and report direct Image
        // pool pointers plus readable child-table Image pointers.
        // -----------------------------------------------------------------
        materialImages
            << "label,camo_slot,material_index,material_address,path,"
               "image_index,image_address,image_q0,image_q1,image_q2,"
               "image_q3,image_q4,confidence,notes\n";

        unsigned int focusedMaterialCount = 0;
        unsigned int focusedImageHits = 0;

        if (materialPool &&
            materialPool->pool.unk &&
            materialPool->itemSize > 0 &&
            imagePool &&
            imagePool->pool.unk)
        {
            for (unsigned int ci = 0;
                 ci < camoAllocated;
                 ++ci)
            {
                const auto recordAddress =
                    camoBase +
                    static_cast<std::uintptr_t>(ci) *
                    camoPool->itemSize;

                unsigned char record[32]{};

                if (!CopyFromProcess(
                        reinterpret_cast<const void*>(recordAddress),
                        record,
                        sizeof(record)))
                {
                    continue;
                }

                std::uint64_t definition = 0;
                std::memcpy(
                    &definition,
                    record + 0x10,
                    sizeof(definition));

                if (!definition)
                    continue;

                // Previous scans showed the useful material list under the
                // definition itself and its first child.
                std::vector<std::uint64_t> roots;
                roots.push_back(definition);

                std::uint64_t firstChild = 0;
                if (CopyFromProcess(
                        reinterpret_cast<const void*>(definition),
                        &firstChild,
                        sizeof(firstChild)) &&
                    firstChild)
                {
                    roots.push_back(firstChild);
                }

                std::vector<std::uint64_t> seenMaterials;

                for (const auto rootAddr : roots)
                {
                    const auto rootSpan =
                        SafeReadableSpan(rootAddr, 0x200);

                    if (rootSpan < 8)
                        continue;

                    std::vector<unsigned char> rootBytes(rootSpan);

                    if (!CopyFromProcess(
                            reinterpret_cast<const void*>(rootAddr),
                            rootBytes.data(),
                            rootBytes.size()))
                    {
                        continue;
                    }

                    for (std::size_t off = 0;
                         off + 8 <= rootBytes.size();
                         off += 8)
                    {
                        std::uint64_t materialAddress = 0;
                        std::memcpy(
                            &materialAddress,
                            rootBytes.data() + off,
                            sizeof(materialAddress));

                        unsigned int materialIndex = 0;

                        if (!InPool(
                                materialAddress,
                                *materialPool,
                                materialIndex))
                        {
                            continue;
                        }

                        if (std::find(
                                seenMaterials.begin(),
                                seenMaterials.end(),
                                materialAddress) !=
                            seenMaterials.end())
                        {
                            continue;
                        }

                        seenMaterials.push_back(materialAddress);
                        ++focusedMaterialCount;

                        const auto materialSpan =
                            SafeReadableSpan(
                                materialAddress,
                                deep ? 0x400u : 0x200u);

                        if (materialSpan < 8)
                            continue;

                        std::vector<unsigned char> materialBytes(
                            materialSpan);

                        if (!CopyFromProcess(
                                reinterpret_cast<const void*>(materialAddress),
                                materialBytes.data(),
                                materialBytes.size()))
                        {
                            continue;
                        }

                        auto emitImage =
                            [&](const char* label,
                                const std::string& path,
                                std::uint64_t imageAddress,
                                unsigned int imageIndex)
                            {
                                std::uint64_t iq[5]{};

                                if (SafeReadableSpan(
                                        imageAddress,
                                        sizeof(iq)) >= sizeof(iq))
                                {
                                    CopyFromProcess(
                                        reinterpret_cast<const void*>(imageAddress),
                                        iq,
                                        sizeof(iq));
                                }

                                materialImages
                                    << label
                                    << ','
                                    << ci
                                    << ','
                                    << materialIndex
                                    << ",0x"
                                    << std::hex
                                    << std::uppercase
                                    << materialAddress
                                    << ",\""
                                    << path
                                    << "\","
                                    << std::dec
                                    << imageIndex
                                    << ",0x"
                                    << std::hex
                                    << std::uppercase
                                    << imageAddress
                                    << ",0x" << iq[0]
                                    << ",0x" << iq[1]
                                    << ",0x" << iq[2]
                                    << ",0x" << iq[3]
                                    << ",0x" << iq[4]
                                    << std::dec
                                    << ",HIGH,"
                                    << "candidate material texture layer; recurring offsets can map color/normal/mask/layer0/layer1"
                                    << "\n";

                                ++focusedImageHits;
                            };

                        for (std::size_t moff = 0;
                             moff + 8 <= materialBytes.size();
                             moff += 8)
                        {
                            std::uint64_t value = 0;
                            std::memcpy(
                                &value,
                                materialBytes.data() + moff,
                                sizeof(value));

                            unsigned int imageIndex = 0;

                            if (InPool(value, *imagePool, imageIndex))
                            {
                                std::ostringstream path;
                                path << "material->+0x"
                                     << std::hex << std::uppercase << moff;

                                emitImage(
                                    "MATERIAL_IMAGE_DIRECT",
                                    path.str(),
                                    value,
                                    imageIndex);

                                continue;
                            }

                            // One bounded child-table level in FAST mode.
                            const auto childSpan =
                                SafeReadableSpan(value, deep ? 0x300u : 0x100u);

                            if (childSpan < 8)
                                continue;

                            std::vector<unsigned char> childBytes(childSpan);

                            if (!CopyFromProcess(
                                    reinterpret_cast<const void*>(value),
                                    childBytes.data(),
                                    childBytes.size()))
                            {
                                continue;
                            }

                            for (std::size_t coff = 0;
                                 coff + 8 <= childBytes.size();
                                 coff += 8)
                            {
                                std::uint64_t childValue = 0;
                                std::memcpy(
                                    &childValue,
                                    childBytes.data() + coff,
                                    sizeof(childValue));

                                unsigned int childImageIndex = 0;

                                if (!InPool(
                                        childValue,
                                        *imagePool,
                                        childImageIndex))
                                {
                                    continue;
                                }

                                std::ostringstream path;
                                path << "material->+0x"
                                     << std::hex << std::uppercase << moff
                                     << "->+0x" << coff;

                                emitImage(
                                    "MATERIAL_IMAGE_CHILD",
                                    path.str(),
                                    childValue,
                                    childImageIndex);
                            }
                        }
                    }
                }
            }
        }

        materialImages.flush();

        // -----------------------------------------------------------------
        // [RANKED MATERIAL TEXTURE-TABLE / LAYER CANDIDATES]
        //
        // _55 intentionally over-collected to prove we reached Material->Image.
        // This pass deduplicates and ranks recurring offsets so the next log is
        // small enough to reason about.
        // -----------------------------------------------------------------
        rankedLayers
            << "rank,label,camo_slot,material_index,material_address,"
               "material_offset,child_offset,image_index,image_address,"
               "path_frequency,material_frequency,score,role_hint,notes\n";

        materialTables
            << "label,material_index,material_address,table_offset,"
               "image_count,distinct_images,first_image_index,last_image_index,"
               "stride_hint,confidence,notes\n";

        struct LayerHit
        {
            unsigned int camoSlot = 0;
            unsigned int materialIndex = 0;
            std::uint64_t materialAddress = 0;
            std::size_t materialOffset = 0;
            std::size_t childOffset = static_cast<std::size_t>(-1);
            unsigned int imageIndex = 0;
            std::uint64_t imageAddress = 0;
        };

        std::vector<LayerHit> layerHits;

        if (materialPool &&
            materialPool->pool.unk &&
            materialPool->itemSize > 0 &&
            imagePool &&
            imagePool->pool.unk)
        {
            for (unsigned int ci = 0;
                 ci < camoAllocated;
                 ++ci)
            {
                const auto recordAddress =
                    camoBase +
                    static_cast<std::uintptr_t>(ci) *
                    camoPool->itemSize;

                unsigned char record[32]{};

                if (!CopyFromProcess(
                        reinterpret_cast<const void*>(recordAddress),
                        record,
                        sizeof(record)))
                {
                    continue;
                }

                std::uint64_t definition = 0;
                std::memcpy(
                    &definition,
                    record + 0x10,
                    sizeof(definition));

                if (!definition)
                    continue;

                std::vector<std::uint64_t> roots;
                roots.push_back(definition);

                std::uint64_t firstChild = 0;
                if (CopyFromProcess(
                        reinterpret_cast<const void*>(definition),
                        &firstChild,
                        sizeof(firstChild)) &&
                    firstChild)
                {
                    roots.push_back(firstChild);
                }

                std::vector<std::uint64_t> seenMaterials;

                for (const auto rootAddress : roots)
                {
                    const auto rootSpan =
                        SafeReadableSpan(rootAddress, 0x200);

                    if (rootSpan < 8)
                        continue;

                    std::vector<unsigned char> rootBytes(rootSpan);

                    if (!CopyFromProcess(
                            reinterpret_cast<const void*>(rootAddress),
                            rootBytes.data(),
                            rootBytes.size()))
                    {
                        continue;
                    }

                    for (std::size_t roff = 0;
                         roff + 8 <= rootBytes.size();
                         roff += 8)
                    {
                        std::uint64_t materialAddress = 0;
                        std::memcpy(
                            &materialAddress,
                            rootBytes.data() + roff,
                            sizeof(materialAddress));

                        unsigned int materialIndex = 0;

                        if (!InPool(
                                materialAddress,
                                *materialPool,
                                materialIndex))
                        {
                            continue;
                        }

                        if (std::find(
                                seenMaterials.begin(),
                                seenMaterials.end(),
                                materialAddress) !=
                            seenMaterials.end())
                        {
                            continue;
                        }

                        seenMaterials.push_back(materialAddress);

                        const auto materialSpan =
                            SafeReadableSpan(
                                materialAddress,
                                deep ? 0x300u : 0x200u);

                        if (materialSpan < 8)
                            continue;

                        std::vector<unsigned char> materialBytes(materialSpan);

                        if (!CopyFromProcess(
                                reinterpret_cast<const void*>(materialAddress),
                                materialBytes.data(),
                                materialBytes.size()))
                        {
                            continue;
                        }

                        // Track child tables that contain multiple Image* values.
                        for (std::size_t moff = 0;
                             moff + 8 <= materialBytes.size();
                             moff += 8)
                        {
                            std::uint64_t value = 0;
                            std::memcpy(
                                &value,
                                materialBytes.data() + moff,
                                sizeof(value));

                            unsigned int imageIndex = 0;

                            if (InPool(value, *imagePool, imageIndex))
                            {
                                layerHits.push_back({
                                    ci,
                                    materialIndex,
                                    materialAddress,
                                    moff,
                                    static_cast<std::size_t>(-1),
                                    imageIndex,
                                    value
                                });
                                continue;
                            }

                            const auto childSpan =
                                SafeReadableSpan(
                                    value,
                                    deep ? 0x180u : 0x100u);

                            if (childSpan < 0x20)
                                continue;

                            std::vector<unsigned char> childBytes(childSpan);

                            if (!CopyFromProcess(
                                    reinterpret_cast<const void*>(value),
                                    childBytes.data(),
                                    childBytes.size()))
                            {
                                continue;
                            }

                            std::vector<unsigned int> tableImages;
                            std::vector<std::size_t> tableOffsets;

                            for (std::size_t coff = 0;
                                 coff + 8 <= childBytes.size();
                                 coff += 8)
                            {
                                std::uint64_t childValue = 0;
                                std::memcpy(
                                    &childValue,
                                    childBytes.data() + coff,
                                    sizeof(childValue));

                                unsigned int childImageIndex = 0;

                                if (!InPool(
                                        childValue,
                                        *imagePool,
                                        childImageIndex))
                                {
                                    continue;
                                }

                                layerHits.push_back({
                                    ci,
                                    materialIndex,
                                    materialAddress,
                                    moff,
                                    coff,
                                    childImageIndex,
                                    childValue
                                });

                                tableImages.push_back(childImageIndex);
                                tableOffsets.push_back(coff);
                            }

                            if (tableImages.size() >= 2)
                            {
                                std::vector<unsigned int> distinct =
                                    tableImages;

                                std::sort(
                                    distinct.begin(),
                                    distinct.end());

                                distinct.erase(
                                    std::unique(
                                        distinct.begin(),
                                        distinct.end()),
                                    distinct.end());

                                std::size_t stride = 0;

                                if (tableOffsets.size() >= 2)
                                {
                                    stride =
                                        tableOffsets[1] -
                                        tableOffsets[0];
                                }

                                const char* confidence =
                                    tableImages.size() >= 4 &&
                                    distinct.size() >= 3
                                    ? "HIGH"
                                    : "MEDIUM";

                                materialTables
                                    << "MATERIAL_TEXTURE_TABLE,"
                                    << materialIndex
                                    << ",0x"
                                    << std::hex
                                    << std::uppercase
                                    << materialAddress
                                    << std::dec
                                    << ','
                                    << moff
                                    << ','
                                    << tableImages.size()
                                    << ','
                                    << distinct.size()
                                    << ','
                                    << tableImages.front()
                                    << ','
                                    << tableImages.back()
                                    << ','
                                    << stride
                                    << ','
                                    << confidence
                                    << ','
                                    << "multiple GfxImage pointers in one child table; strong texture-layer table candidate"
                                    << "\n";
                            }
                        }
                    }
                }
            }
        }

        // Deduplicate exact hits.
        std::sort(
            layerHits.begin(),
            layerHits.end(),
            [](const LayerHit& a,
               const LayerHit& b)
            {
                if (a.camoSlot != b.camoSlot)
                    return a.camoSlot < b.camoSlot;
                if (a.materialIndex != b.materialIndex)
                    return a.materialIndex < b.materialIndex;
                if (a.materialOffset != b.materialOffset)
                    return a.materialOffset < b.materialOffset;
                if (a.childOffset != b.childOffset)
                    return a.childOffset < b.childOffset;
                return a.imageIndex < b.imageIndex;
            });

        layerHits.erase(
            std::unique(
                layerHits.begin(),
                layerHits.end(),
                [](const LayerHit& a,
                   const LayerHit& b)
                {
                    return
                        a.camoSlot == b.camoSlot &&
                        a.materialIndex == b.materialIndex &&
                        a.materialOffset == b.materialOffset &&
                        a.childOffset == b.childOffset &&
                        a.imageIndex == b.imageIndex;
                }),
            layerHits.end());

        struct PathStats
        {
            std::size_t materialOffset = 0;
            std::size_t childOffset = static_cast<std::size_t>(-1);
            unsigned int frequency = 0;
            unsigned int materialFrequency = 0;
            std::vector<unsigned int> materials;
        };

        std::vector<PathStats> stats;

        for (const auto& hit : layerHits)
        {
            auto it =
                std::find_if(
                    stats.begin(),
                    stats.end(),
                    [&](const PathStats& p)
                    {
                        return
                            p.materialOffset == hit.materialOffset &&
                            p.childOffset == hit.childOffset;
                    });

            if (it == stats.end())
            {
                stats.push_back({
                    hit.materialOffset,
                    hit.childOffset,
                    0u,
                    0u,
                    {}
                });

                it = stats.end() - 1;
            }

            ++it->frequency;

            if (std::find(
                    it->materials.begin(),
                    it->materials.end(),
                    hit.materialIndex) ==
                it->materials.end())
            {
                it->materials.push_back(hit.materialIndex);
                ++it->materialFrequency;
            }
        }

        std::sort(
            stats.begin(),
            stats.end(),
            [](const PathStats& a,
               const PathStats& b)
            {
                const unsigned int scoreA =
                    a.materialFrequency * 10u +
                    std::min(a.frequency, 100u);

                const unsigned int scoreB =
                    b.materialFrequency * 10u +
                    std::min(b.frequency, 100u);

                return scoreA > scoreB;
            });

        const std::size_t maxRankedPaths =
            deep ? 128u : 48u;

        unsigned int rank = 1;

        for (std::size_t si = 0;
             si < stats.size() &&
             si < maxRankedPaths;
             ++si)
        {
            const auto& stat =
                stats[si];

            const unsigned int score =
                stat.materialFrequency * 10u +
                std::min(stat.frequency, 100u);

            const char* roleHint =
                stat.materialFrequency >= 20
                ? "COMMON_MATERIAL_LAYER_SLOT"
                : stat.materialFrequency >= 8
                    ? "LIKELY_LAYER_SLOT"
                    : "SPECIALIZED_LAYER_SLOT";

            for (const auto& hit : layerHits)
            {
                if (hit.materialOffset != stat.materialOffset ||
                    hit.childOffset != stat.childOffset)
                {
                    continue;
                }

                rankedLayers
                    << rank
                    << ",RANKED_CAMO_LAYER,"
                    << hit.camoSlot
                    << ','
                    << hit.materialIndex
                    << ",0x"
                    << std::hex
                    << std::uppercase
                    << hit.materialAddress
                    << std::dec
                    << ','
                    << hit.materialOffset
                    << ',';

                if (hit.childOffset ==
                    static_cast<std::size_t>(-1))
                {
                    rankedLayers << -1;
                }
                else
                {
                    rankedLayers << hit.childOffset;
                }

                rankedLayers
                    << ','
                    << hit.imageIndex
                    << ",0x"
                    << std::hex
                    << std::uppercase
                    << hit.imageAddress
                    << std::dec
                    << ','
                    << stat.frequency
                    << ','
                    << stat.materialFrequency
                    << ','
                    << score
                    << ','
                    << roleHint
                    << ','
                    << "ranked by recurring Material/child offset; use top paths to identify color/normal/mask semantics"
                    << "\n";
            }

            ++rank;
        }

        rankedLayers.flush();
        materialTables.flush();

        // -----------------------------------------------------------------
        // [MATERIAL +0x30 TEXTURE TABLE DECODER]
        //
        // Previous scan repeatedly found strong 24-byte texture-table entries
        // beneath Material +0x30. Decode the table directly instead of doing
        // generic pointer chasing.
        // -----------------------------------------------------------------
        material30Entries
            << "label,camo_slot,material_index,material_address,"
               "table_pointer,entry_index,entry_address,"
               "q0,q1,q2,image_field_offset,image_index,image_address,"
               "image_q0,image_q1,image_q2,image_q3,image_q4,"
               "confidence,role_hint,notes\n";

        unsigned int material30Tables = 0;
        unsigned int material30ImageEntries = 0;

        if (materialPool &&
            materialPool->pool.unk &&
            materialPool->itemSize > 0 &&
            imagePool &&
            imagePool->pool.unk)
        {
            for (unsigned int ci = 0;
                 ci < camoAllocated;
                 ++ci)
            {
                const auto camoRecord =
                    camoBase +
                    static_cast<std::uintptr_t>(ci) *
                    camoPool->itemSize;

                unsigned char rec[32]{};

                if (!CopyFromProcess(
                        reinterpret_cast<const void*>(camoRecord),
                        rec,
                        sizeof(rec)))
                {
                    continue;
                }

                std::uint64_t definition = 0;
                std::memcpy(
                    &definition,
                    rec + 0x10,
                    sizeof(definition));

                if (!definition)
                    continue;

                std::vector<std::uint64_t> roots;
                roots.push_back(definition);

                std::uint64_t firstChild = 0;
                if (CopyFromProcess(
                        reinterpret_cast<const void*>(definition),
                        &firstChild,
                        sizeof(firstChild)) &&
                    firstChild)
                {
                    roots.push_back(firstChild);
                }

                std::vector<std::uint64_t> seenMaterials;

                for (const auto rootAddress : roots)
                {
                    const auto rootSpan =
                        SafeReadableSpan(rootAddress, 0x200);

                    if (rootSpan < 8)
                        continue;

                    std::vector<unsigned char> rootBytes(rootSpan);

                    if (!CopyFromProcess(
                            reinterpret_cast<const void*>(rootAddress),
                            rootBytes.data(),
                            rootBytes.size()))
                    {
                        continue;
                    }

                    for (std::size_t off = 0;
                         off + 8 <= rootBytes.size();
                         off += 8)
                    {
                        std::uint64_t materialAddress = 0;
                        std::memcpy(
                            &materialAddress,
                            rootBytes.data() + off,
                            sizeof(materialAddress));

                        unsigned int materialIndex = 0;

                        if (!InPool(
                                materialAddress,
                                *materialPool,
                                materialIndex))
                        {
                            continue;
                        }

                        if (std::find(
                                seenMaterials.begin(),
                                seenMaterials.end(),
                                materialAddress) !=
                            seenMaterials.end())
                        {
                            continue;
                        }

                        seenMaterials.push_back(materialAddress);

                        // Material +0x30 appears to point at a texture-entry table.
                        std::uint64_t tablePointer = 0;

                        if (!CopyFromProcess(
                                reinterpret_cast<const void*>(
                                    materialAddress + 0x30),
                                &tablePointer,
                                sizeof(tablePointer)) ||
                            !tablePointer)
                        {
                            continue;
                        }

                        const auto tableSpan =
                            SafeReadableSpan(
                                tablePointer,
                                deep ? 0x600u : 0x300u);

                        if (tableSpan < 24)
                            continue;

                        ++material30Tables;

                        const std::size_t maxEntries =
                            std::min<std::size_t>(
                                tableSpan / 24u,
                                deep ? 64u : 32u);

                        for (std::size_t ei = 0;
                             ei < maxEntries;
                             ++ei)
                        {
                            const auto entryAddress =
                                tablePointer + ei * 24u;

                            std::uint64_t q[3]{};

                            if (!CopyFromProcess(
                                    reinterpret_cast<const void*>(entryAddress),
                                    q,
                                    sizeof(q)))
                            {
                                continue;
                            }

                            // Test each qword as a possible Image* field.
                            for (unsigned int qIndex = 0;
                                 qIndex < 3;
                                 ++qIndex)
                            {
                                unsigned int imageIndex = 0;

                                if (!InPool(
                                        q[qIndex],
                                        *imagePool,
                                        imageIndex))
                                {
                                    continue;
                                }

                                std::uint64_t iq[5]{};

                                if (SafeReadableSpan(
                                        q[qIndex],
                                        sizeof(iq)) >=
                                    sizeof(iq))
                                {
                                    CopyFromProcess(
                                        reinterpret_cast<const void*>(
                                            q[qIndex]),
                                        iq,
                                        sizeof(iq));
                                }

                                const char* roleHint =
                                    qIndex == 0
                                    ? "ENTRY_Q0_IMAGE"
                                    : qIndex == 1
                                        ? "ENTRY_Q1_IMAGE"
                                        : "ENTRY_Q2_IMAGE";

                                material30Entries
                                    << "MATERIAL30_TEXTURE_ENTRY,"
                                    << ci
                                    << ','
                                    << materialIndex
                                    << ",0x"
                                    << std::hex
                                    << std::uppercase
                                    << materialAddress
                                    << ",0x"
                                    << tablePointer
                                    << std::dec
                                    << ','
                                    << ei
                                    << ",0x"
                                    << std::hex
                                    << std::uppercase
                                    << entryAddress
                                    << ",0x"
                                    << q[0]
                                    << ",0x"
                                    << q[1]
                                    << ",0x"
                                    << q[2]
                                    << std::dec
                                    << ','
                                    << (qIndex * 8u)
                                    << ','
                                    << imageIndex
                                    << ",0x"
                                    << std::hex
                                    << std::uppercase
                                    << q[qIndex]
                                    << ",0x"
                                    << iq[0]
                                    << ",0x"
                                    << iq[1]
                                    << ",0x"
                                    << iq[2]
                                    << ",0x"
                                    << iq[3]
                                    << ",0x"
                                    << iq[4]
                                    << std::dec
                                    << ",HIGH,"
                                    << roleHint
                                    << ','
                                    << "24-byte Material+0x30 table entry; compare entry index/qword position to map color/normal/mask/layer0/layer1"
                                    << "\n";

                                ++material30ImageEntries;
                            }
                        }
                    }
                }
            }
        }

        material30Entries.flush();

        // -----------------------------------------------------------------
        // [MATERIAL +0x30 Q0-ONLY TABLE DECODER]
        //
        // Build 154 showed Q0 is the stable GfxImage* field in the real
        // 24-byte table. Stop the table at the first sustained invalid run
        // instead of blindly reading 32 entries into adjacent memory.
        // Q1/Q2 are preserved as metadata for semantic-role research.
        // -----------------------------------------------------------------
        material30Q0
            << "label,camo_slot,material_index,material_address,"
               "table_pointer,entry_index,entry_address,"
               "image_index,image_address,q1_metadata,q2_metadata,"
               "q1_low32,q1_high32,q2_low32,q2_high32,"
               "valid_run_length,confidence,role_hint,notes\n";

        unsigned int q0Tables = 0;
        unsigned int q0Entries = 0;

        if (materialPool &&
            materialPool->pool.unk &&
            materialPool->itemSize > 0 &&
            imagePool &&
            imagePool->pool.unk)
        {
            for (unsigned int ci = 0;
                 ci < camoAllocated;
                 ++ci)
            {
                const auto camoRecord =
                    camoBase +
                    static_cast<std::uintptr_t>(ci) *
                    camoPool->itemSize;

                unsigned char rec[32]{};

                if (!CopyFromProcess(
                        reinterpret_cast<const void*>(camoRecord),
                        rec,
                        sizeof(rec)))
                {
                    continue;
                }

                std::uint64_t definition = 0;
                std::memcpy(&definition, rec + 0x10, sizeof(definition));

                if (!definition)
                    continue;

                std::vector<std::uint64_t> roots;
                roots.push_back(definition);

                std::uint64_t firstChild = 0;
                if (CopyFromProcess(
                        reinterpret_cast<const void*>(definition),
                        &firstChild,
                        sizeof(firstChild)) &&
                    firstChild)
                {
                    roots.push_back(firstChild);
                }

                std::vector<std::uint64_t> seenMaterials;

                for (const auto rootAddress : roots)
                {
                    const auto rootSpan =
                        SafeReadableSpan(rootAddress, 0x200);

                    if (rootSpan < 8)
                        continue;

                    std::vector<unsigned char> rootBytes(rootSpan);

                    if (!CopyFromProcess(
                            reinterpret_cast<const void*>(rootAddress),
                            rootBytes.data(),
                            rootBytes.size()))
                    {
                        continue;
                    }

                    for (std::size_t off = 0;
                         off + 8 <= rootBytes.size();
                         off += 8)
                    {
                        std::uint64_t materialAddress = 0;
                        std::memcpy(
                            &materialAddress,
                            rootBytes.data() + off,
                            sizeof(materialAddress));

                        unsigned int materialIndex = 0;

                        if (!InPool(
                                materialAddress,
                                *materialPool,
                                materialIndex))
                        {
                            continue;
                        }

                        if (std::find(
                                seenMaterials.begin(),
                                seenMaterials.end(),
                                materialAddress) !=
                            seenMaterials.end())
                        {
                            continue;
                        }

                        seenMaterials.push_back(materialAddress);

                        std::uint64_t tablePointer = 0;

                        if (!CopyFromProcess(
                                reinterpret_cast<const void*>(
                                    materialAddress + 0x30),
                                &tablePointer,
                                sizeof(tablePointer)) ||
                            !tablePointer)
                        {
                            continue;
                        }

                        const auto tableSpan =
                            SafeReadableSpan(
                                tablePointer,
                                deep ? 0x600u : 0x300u);

                        if (tableSpan < 24)
                            continue;

                        const std::size_t hardMax =
                            std::min<std::size_t>(
                                tableSpan / 24u,
                                deep ? 96u : 48u);

                        std::vector<std::array<std::uint64_t, 3>> entries;
                        unsigned int consecutiveInvalid = 0;

                        for (std::size_t ei = 0;
                             ei < hardMax;
                             ++ei)
                        {
                            std::array<std::uint64_t, 3> q{};

                            if (!CopyFromProcess(
                                    reinterpret_cast<const void*>(
                                        tablePointer + ei * 24u),
                                    q.data(),
                                    sizeof(q)))
                            {
                                break;
                            }

                            unsigned int imageIndex = 0;
                            const bool q0IsImage =
                                InPool(
                                    q[0],
                                    *imagePool,
                                    imageIndex);

                            if (q0IsImage)
                            {
                                entries.push_back(q);
                                consecutiveInvalid = 0;
                            }
                            else
                            {
                                ++consecutiveInvalid;

                                // Allow sparse holes, but stop once we've clearly
                                // crossed the table boundary.
                                if (consecutiveInvalid >= 3 &&
                                    entries.size() >= 2)
                                {
                                    break;
                                }

                                if (entries.empty() &&
                                    consecutiveInvalid >= 4)
                                {
                                    break;
                                }
                            }
                        }

                        if (entries.empty())
                            continue;

                        ++q0Tables;
                        const unsigned int runLength =
                            static_cast<unsigned int>(entries.size());

                        for (unsigned int ei = 0;
                             ei < runLength;
                             ++ei)
                        {
                            const auto& q = entries[ei];

                            unsigned int imageIndex = 0;

                            if (!InPool(
                                    q[0],
                                    *imagePool,
                                    imageIndex))
                            {
                                continue;
                            }

                            ++q0Entries;

                            const std::uint32_t q1Low =
                                static_cast<std::uint32_t>(q[1] & 0xFFFFFFFFull);
                            const std::uint32_t q1High =
                                static_cast<std::uint32_t>(q[1] >> 32);
                            const std::uint32_t q2Low =
                                static_cast<std::uint32_t>(q[2] & 0xFFFFFFFFull);
                            const std::uint32_t q2High =
                                static_cast<std::uint32_t>(q[2] >> 32);

                            const char* roleHint =
                                ei == 0
                                ? "PRIMARY_LAYER_OR_ALBEDO_CANDIDATE"
                                : ei == 1
                                    ? "SECONDARY_LAYER_CANDIDATE"
                                    : ei == 2
                                        ? "NORMAL_OR_MASK_CANDIDATE"
                                        : "ADDITIONAL_TEXTURE_ROLE";

                            material30Q0
                                << "MATERIAL30_Q0_ENTRY,"
                                << ci
                                << ','
                                << materialIndex
                                << ",0x"
                                << std::hex
                                << std::uppercase
                                << materialAddress
                                << ",0x"
                                << tablePointer
                                << std::dec
                                << ','
                                << ei
                                << ",0x"
                                << std::hex
                                << std::uppercase
                                << (tablePointer +
                                    static_cast<std::uint64_t>(ei) * 24ull)
                                << std::dec
                                << ','
                                << imageIndex
                                << ",0x"
                                << std::hex
                                << std::uppercase
                                << q[0]
                                << ",0x"
                                << q[1]
                                << ",0x"
                                << q[2]
                                << std::dec
                                << ','
                                << q1Low
                                << ','
                                << q1High
                                << ','
                                << q2Low
                                << ','
                                << q2High
                                << ','
                                << runLength
                                << ",HIGH,"
                                << roleHint
                                << ','
                                << "Q0 confirmed image pointer candidate; Q1/Q2 preserved as role/flags/hash metadata"
                                << "\n";
                        }
                    }
                }
            }
        }

        material30Q0.flush();

        // -----------------------------------------------------------------
        // [MATERIAL SEMANTIC CLUSTERING]
        //
        // Build 155 established Q0 as the strong image pointer field and Q1/Q2
        // as metadata. Cluster Q1/Q2 values by table entry index across every
        // valid Material+0x30 table. This is intended to reveal stable semantic
        // roles such as albedo/color, normal, mask, detail, etc.
        // -----------------------------------------------------------------
        semanticClusters
            << "label,entry_index,q1_low32,q1_high32,q2_low32,q2_high32,"
               "occurrences,distinct_materials,distinct_images,"
               "role_confidence,notes\n";

        struct SemanticBucket
        {
            unsigned int entryIndex = 0;
            std::uint32_t q1Low = 0;
            std::uint32_t q1High = 0;
            std::uint32_t q2Low = 0;
            std::uint32_t q2High = 0;
            unsigned int occurrences = 0;
            std::vector<unsigned int> materials;
            std::vector<unsigned int> images;
        };

        std::vector<SemanticBucket> semanticBuckets;

        if (materialPool &&
            materialPool->pool.unk &&
            imagePool &&
            imagePool->pool.unk)
        {
            for (unsigned int ci = 0;
                 ci < camoAllocated;
                 ++ci)
            {
                const auto camoRecord =
                    camoBase +
                    static_cast<std::uintptr_t>(ci) *
                    camoPool->itemSize;

                unsigned char rec[32]{};

                if (!CopyFromProcess(
                        reinterpret_cast<const void*>(camoRecord),
                        rec,
                        sizeof(rec)))
                {
                    continue;
                }

                std::uint64_t definition = 0;
                std::memcpy(&definition, rec + 0x10, sizeof(definition));

                if (!definition)
                    continue;

                std::vector<std::uint64_t> roots;
                roots.push_back(definition);

                std::uint64_t firstChild = 0;
                if (CopyFromProcess(
                        reinterpret_cast<const void*>(definition),
                        &firstChild,
                        sizeof(firstChild)) &&
                    firstChild)
                {
                    roots.push_back(firstChild);
                }

                std::vector<std::uint64_t> seenMaterials;

                for (const auto rootAddress : roots)
                {
                    const auto rootSpan =
                        SafeReadableSpan(rootAddress, 0x200);

                    if (rootSpan < 8)
                        continue;

                    std::vector<unsigned char> rootBytes(rootSpan);

                    if (!CopyFromProcess(
                            reinterpret_cast<const void*>(rootAddress),
                            rootBytes.data(),
                            rootBytes.size()))
                    {
                        continue;
                    }

                    for (std::size_t roff = 0;
                         roff + 8 <= rootBytes.size();
                         roff += 8)
                    {
                        std::uint64_t materialAddress = 0;
                        std::memcpy(
                            &materialAddress,
                            rootBytes.data() + roff,
                            sizeof(materialAddress));

                        unsigned int materialIndex = 0;

                        if (!InPool(
                                materialAddress,
                                *materialPool,
                                materialIndex))
                        {
                            continue;
                        }

                        if (std::find(
                                seenMaterials.begin(),
                                seenMaterials.end(),
                                materialAddress) !=
                            seenMaterials.end())
                        {
                            continue;
                        }

                        seenMaterials.push_back(materialAddress);

                        std::uint64_t tablePointer = 0;

                        if (!CopyFromProcess(
                                reinterpret_cast<const void*>(
                                    materialAddress + 0x30),
                                &tablePointer,
                                sizeof(tablePointer)) ||
                            !tablePointer)
                        {
                            continue;
                        }

                        const auto tableSpan =
                            SafeReadableSpan(tablePointer, 0x300);

                        if (tableSpan < 24)
                            continue;

                        unsigned int consecutiveInvalid = 0;

                        for (unsigned int ei = 0;
                             ei < 48;
                             ++ei)
                        {
                            std::uint64_t q[3]{};

                            if (!CopyFromProcess(
                                    reinterpret_cast<const void*>(
                                        tablePointer +
                                        static_cast<std::uint64_t>(ei) * 24ull),
                                    q,
                                    sizeof(q)))
                            {
                                break;
                            }

                            unsigned int imageIndex = 0;

                            if (!InPool(q[0], *imagePool, imageIndex))
                            {
                                ++consecutiveInvalid;

                                if (consecutiveInvalid >= 3 && ei >= 2)
                                    break;

                                continue;
                            }

                            consecutiveInvalid = 0;

                            const std::uint32_t q1Low =
                                static_cast<std::uint32_t>(q[1] & 0xFFFFFFFFull);
                            const std::uint32_t q1High =
                                static_cast<std::uint32_t>(q[1] >> 32);
                            const std::uint32_t q2Low =
                                static_cast<std::uint32_t>(q[2] & 0xFFFFFFFFull);
                            const std::uint32_t q2High =
                                static_cast<std::uint32_t>(q[2] >> 32);

                            auto it = std::find_if(
                                semanticBuckets.begin(),
                                semanticBuckets.end(),
                                [&](const SemanticBucket& b)
                                {
                                    return
                                        b.entryIndex == ei &&
                                        b.q1Low == q1Low &&
                                        b.q1High == q1High &&
                                        b.q2Low == q2Low &&
                                        b.q2High == q2High;
                                });

                            if (it == semanticBuckets.end())
                            {
                                semanticBuckets.push_back({
                                    ei, q1Low, q1High, q2Low, q2High,
                                    0u, {}, {}
                                });

                                it = semanticBuckets.end() - 1;
                            }

                            ++it->occurrences;

                            if (std::find(
                                    it->materials.begin(),
                                    it->materials.end(),
                                    materialIndex) ==
                                it->materials.end())
                            {
                                it->materials.push_back(materialIndex);
                            }

                            if (std::find(
                                    it->images.begin(),
                                    it->images.end(),
                                    imageIndex) ==
                                it->images.end())
                            {
                                it->images.push_back(imageIndex);
                            }
                        }
                    }
                }
            }
        }

        std::sort(
            semanticBuckets.begin(),
            semanticBuckets.end(),
            [](const SemanticBucket& a,
               const SemanticBucket& b)
            {
                if (a.entryIndex != b.entryIndex)
                    return a.entryIndex < b.entryIndex;

                return a.occurrences > b.occurrences;
            });

        for (const auto& b : semanticBuckets)
        {
            const char* confidence =
                b.materials.size() >= 20
                ? "HIGH"
                : b.materials.size() >= 8
                    ? "MEDIUM"
                    : "LOW";

            semanticClusters
                << "MATERIAL_SEMANTIC_CLUSTER,"
                << b.entryIndex
                << ','
                << b.q1Low
                << ','
                << b.q1High
                << ','
                << b.q2Low
                << ','
                << b.q2High
                << ','
                << b.occurrences
                << ','
                << b.materials.size()
                << ','
                << b.images.size()
                << ','
                << confidence
                << ','
                << "stable metadata cluster candidate for texture semantic/role"
                << "\n";
        }

        semanticClusters.flush();

        // -----------------------------------------------------------------
        // [GENERIC XASSETPOOL ALLOCATOR XREF SEARCH]
        //
        // Direct xrefs to runtime freeHead addresses were empty. Search for
        // executable references to the XAssetPool table entry itself and the
        // stable field offsets inside that entry, then label nearby code for
        // manual function inspection.
        // -----------------------------------------------------------------
        genericPoolXrefs
            << "label,section,instruction_address,target_address,"
               "target_label,bytes,confidence,notes\n";

        std::vector<std::pair<std::uintptr_t, const char*>>
            poolTargets;

        poolTargets.push_back({
            reinterpret_cast<std::uintptr_t>(camoPool),
            "WEAPONCAMO_XASSETPOOL_ENTRY"
        });

        poolTargets.push_back({
            reinterpret_cast<std::uintptr_t>(bindingPool),
            "CAMOBINDING_XASSETPOOL_ENTRY"
        });

        if (imagePool)
        {
            poolTargets.push_back({
                reinterpret_cast<std::uintptr_t>(imagePool),
                "IMAGE_XASSETPOOL_ENTRY"
            });
        }

        unsigned int genericPoolHits = 0;
        HMODULE poolScanExe = GetModuleHandleW(nullptr);

        if (poolScanExe)
        {
            const auto moduleBase =
                reinterpret_cast<std::uintptr_t>(poolScanExe);

            IMAGE_DOS_HEADER dos{};

            if (CopyFromProcess(
                    reinterpret_cast<const void*>(moduleBase),
                    &dos,
                    sizeof(dos)) &&
                dos.e_magic == IMAGE_DOS_SIGNATURE)
            {
                IMAGE_NT_HEADERS64 nt{};

                const auto ntAddress =
                    moduleBase +
                    static_cast<std::uintptr_t>(dos.e_lfanew);

                if (CopyFromProcess(
                        reinterpret_cast<const void*>(ntAddress),
                        &nt,
                        sizeof(nt)) &&
                    nt.Signature == IMAGE_NT_SIGNATURE)
                {
                    const auto sectionBase =
                        ntAddress +
                        sizeof(DWORD) +
                        sizeof(IMAGE_FILE_HEADER) +
                        nt.FileHeader.SizeOfOptionalHeader;

                    for (unsigned int si = 0;
                         si < nt.FileHeader.NumberOfSections;
                         ++si)
                    {
                        IMAGE_SECTION_HEADER sh{};

                        if (!CopyFromProcess(
                                reinterpret_cast<const void*>(
                                    sectionBase +
                                    static_cast<std::uintptr_t>(si) *
                                    sizeof(sh)),
                                &sh,
                                sizeof(sh)))
                        {
                            continue;
                        }

                        if (!(sh.Characteristics & IMAGE_SCN_MEM_EXECUTE) ||
                            !(sh.Characteristics & IMAGE_SCN_MEM_READ))
                        {
                            continue;
                        }

                        char sectionName[9]{};
                        std::memcpy(sectionName, sh.Name, 8);

                        const std::size_t sectionSize =
                            static_cast<std::size_t>(
                                std::max(
                                    sh.Misc.VirtualSize,
                                    sh.SizeOfRawData));

                        if (sectionSize < 8 ||
                            sectionSize > 512ull * 1024ull * 1024ull)
                        {
                            continue;
                        }

                        const auto sectionAddress =
                            moduleBase + sh.VirtualAddress;

                        std::vector<unsigned char> bytes(sectionSize);

                        if (!CopyFromProcess(
                                reinterpret_cast<const void*>(sectionAddress),
                                bytes.data(),
                                bytes.size()))
                        {
                            continue;
                        }

                        for (std::size_t off = 0;
                             off + 10 <= bytes.size();
                             ++off)
                        {
                            for (unsigned int len = 5;
                                 len <= 10;
                                 ++len)
                            {
                                for (unsigned int dispOff = 1;
                                     dispOff + 4 <= len;
                                     ++dispOff)
                                {
                                    std::int32_t disp = 0;

                                    std::memcpy(
                                        &disp,
                                        bytes.data() + off + dispOff,
                                        sizeof(disp));

                                    const auto target =
                                        static_cast<std::uintptr_t>(
                                            static_cast<std::intptr_t>(
                                                sectionAddress + off + len) +
                                            disp);

                                    for (const auto& candidate : poolTargets)
                                    {
                                        if (target != candidate.first)
                                            continue;

                                        std::ostringstream byteText;

                                        for (unsigned int bi = 0;
                                             bi < len;
                                             ++bi)
                                        {
                                            if (bi)
                                                byteText << ' ';

                                            byteText
                                                << std::hex
                                                << std::uppercase
                                                << std::setw(2)
                                                << std::setfill('0')
                                                << static_cast<unsigned int>(
                                                       bytes[off + bi]);
                                        }

                                        genericPoolXrefs
                                            << "GENERIC_POOL_XREF,"
                                            << sectionName
                                            << ",0x"
                                            << std::hex
                                            << std::uppercase
                                            << (sectionAddress + off)
                                            << ",0x"
                                            << target
                                            << std::dec
                                            << ','
                                            << candidate.second
                                            << ",\""
                                            << byteText.str()
                                            << "\",HIGH,"
                                            << "inspect containing function for generic XAssetPool allocation/add logic"
                                            << "\n";

                                        ++genericPoolHits;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        if (!genericPoolHits)
        {
            genericPoolXrefs
                << "GENERIC_POOL_XREF_NONE,none,0,0,none,\"\",NONE,"
                   "no direct RIP-relative XAssetPool-entry xref found; likely indexed through global pool table base"
                   "\n";
        }

        genericPoolXrefs.flush();

        // -----------------------------------------------------------------
        // [g_assetPool[] BASE / INDEXING XREF SEARCH]
        //
        // Direct per-entry xrefs were empty. Search for references to the base
        // of the global XAssetPool array and dump nearby instruction bytes.
        // -----------------------------------------------------------------
        assetPoolBaseXrefs
            << "label,section,instruction_address,target_address,"
               "bytes,confidence,notes\n";

        const auto assetPoolBaseAddress =
            reinterpret_cast<std::uintptr_t>(
                g_assetPool);

        unsigned int assetPoolBaseHits = 0;

        HMODULE poolBaseExe =
            GetModuleHandleW(nullptr);

        if (poolBaseExe &&
            assetPoolBaseAddress)
        {
            const auto moduleBase =
                reinterpret_cast<std::uintptr_t>(
                    poolBaseExe);

            IMAGE_DOS_HEADER dos{};

            if (CopyFromProcess(
                    reinterpret_cast<const void*>(moduleBase),
                    &dos,
                    sizeof(dos)) &&
                dos.e_magic == IMAGE_DOS_SIGNATURE)
            {
                IMAGE_NT_HEADERS64 nt{};

                const auto ntAddress =
                    moduleBase +
                    static_cast<std::uintptr_t>(
                        dos.e_lfanew);

                if (CopyFromProcess(
                        reinterpret_cast<const void*>(ntAddress),
                        &nt,
                        sizeof(nt)) &&
                    nt.Signature == IMAGE_NT_SIGNATURE)
                {
                    const auto shBase =
                        ntAddress +
                        sizeof(DWORD) +
                        sizeof(IMAGE_FILE_HEADER) +
                        nt.FileHeader.SizeOfOptionalHeader;

                    for (unsigned int si = 0;
                         si < nt.FileHeader.NumberOfSections;
                         ++si)
                    {
                        IMAGE_SECTION_HEADER sh{};

                        if (!CopyFromProcess(
                                reinterpret_cast<const void*>(
                                    shBase +
                                    static_cast<std::uintptr_t>(si) *
                                    sizeof(sh)),
                                &sh,
                                sizeof(sh)))
                        {
                            continue;
                        }

                        if (!(sh.Characteristics & IMAGE_SCN_MEM_EXECUTE) ||
                            !(sh.Characteristics & IMAGE_SCN_MEM_READ))
                        {
                            continue;
                        }

                        char sectionName[9]{};
                        std::memcpy(sectionName, sh.Name, 8);

                        const std::size_t sectionSize =
                            static_cast<std::size_t>(
                                std::max(
                                    sh.Misc.VirtualSize,
                                    sh.SizeOfRawData));

                        if (sectionSize < 8 ||
                            sectionSize > 512ull * 1024ull * 1024ull)
                        {
                            continue;
                        }

                        const auto sectionAddress =
                            moduleBase + sh.VirtualAddress;

                        std::vector<unsigned char> bytes(sectionSize);

                        if (!CopyFromProcess(
                                reinterpret_cast<const void*>(sectionAddress),
                                bytes.data(),
                                bytes.size()))
                        {
                            continue;
                        }

                        for (std::size_t off = 0;
                             off + 12 <= bytes.size();
                             ++off)
                        {
                            for (unsigned int len = 5;
                                 len <= 12;
                                 ++len)
                            {
                                for (unsigned int dispOff = 1;
                                     dispOff + 4 <= len;
                                     ++dispOff)
                                {
                                    std::int32_t disp = 0;

                                    std::memcpy(
                                        &disp,
                                        bytes.data() + off + dispOff,
                                        sizeof(disp));

                                    const auto target =
                                        static_cast<std::uintptr_t>(
                                            static_cast<std::intptr_t>(
                                                sectionAddress + off + len) +
                                            disp);

                                    if (target != assetPoolBaseAddress)
                                        continue;

                                    std::ostringstream byteText;

                                    const unsigned int dumpLen =
                                        std::min<unsigned int>(
                                            24u,
                                            static_cast<unsigned int>(
                                                bytes.size() - off));

                                    for (unsigned int bi = 0;
                                         bi < dumpLen;
                                         ++bi)
                                    {
                                        if (bi)
                                            byteText << ' ';

                                        byteText
                                            << std::hex
                                            << std::uppercase
                                            << std::setw(2)
                                            << std::setfill('0')
                                            << static_cast<unsigned int>(
                                                   bytes[off + bi]);
                                    }

                                    assetPoolBaseXrefs
                                        << "ASSETPOOL_BASE_XREF,"
                                        << sectionName
                                        << ",0x"
                                        << std::hex
                                        << std::uppercase
                                        << (sectionAddress + off)
                                        << ",0x"
                                        << assetPoolBaseAddress
                                        << std::dec
                                        << ",\""
                                        << byteText.str()
                                        << "\",HIGH,"
                                        << "candidate generic XAssetPool indexed access; inspect surrounding function for type*entrySize and allocator bookkeeping"
                                        << "\n";

                                    ++assetPoolBaseHits;
                                }
                            }
                        }
                    }
                }
            }
        }

        if (!assetPoolBaseHits)
        {
            assetPoolBaseXrefs
                << "ASSETPOOL_BASE_XREF_NONE,none,0,0,\"\",NONE,"
                   "no direct RIP-relative g_assetPool base reference found; next step would be xref to pointer/global holding the table"
                   "\n";
        }

        assetPoolBaseXrefs.flush();

        // -----------------------------------------------------------------
        // [BINDING FREE-LIST WALK]
        // -----------------------------------------------------------------
        bindingFreeWalk
            << "ordinal,address,next,slot_index,inside_pool,"
               "matches_itemAllocCount,state\n";

        unsigned int bindingFreeNodes = 0;
        long long firstBindingFreeIndex = -1;

        if (bindingPool &&
            bindingPool->freeHead &&
            bindingPool->itemSize > 0)
        {
            std::vector<std::uintptr_t> seen;

            AssetLink* node =
                bindingPool->freeHead;

            for (unsigned int ordinal = 0;
                 node &&
                 ordinal < std::min<unsigned int>(
                     bindingCapacity + 8u,
                     4096u);
                 ++ordinal)
            {
                const auto address =
                    reinterpret_cast<std::uintptr_t>(node);

                if (std::find(
                        seen.begin(),
                        seen.end(),
                        address) !=
                    seen.end())
                {
                    bindingFreeWalk
                        << ordinal
                        << ",0x"
                        << std::hex
                        << std::uppercase
                        << address
                        << ",0x0"
                        << std::dec
                        << ",-1,0,0,LOOP\n";
                    break;
                }

                seen.push_back(address);

                long long slotIndex = -1;
                bool insidePool = false;

                if (address >= bindingBase)
                {
                    const auto delta =
                        address - bindingBase;

                    if ((delta %
                         bindingPool->itemSize) == 0)
                    {
                        const auto idx =
                            delta / bindingPool->itemSize;

                        if (idx < bindingCapacity)
                        {
                            insidePool = true;
                            slotIndex =
                                static_cast<long long>(idx);

                            if (firstBindingFreeIndex < 0)
                                firstBindingFreeIndex = slotIndex;
                        }
                    }
                }

                AssetLink link{};

                if (!CopyFromProcess(
                        node,
                        &link,
                        sizeof(link)))
                {
                    bindingFreeWalk
                        << ordinal
                        << ",0x"
                        << std::hex
                        << std::uppercase
                        << address
                        << ",0x0"
                        << std::dec
                        << ','
                        << slotIndex
                        << ','
                        << (insidePool ? 1 : 0)
                        << ','
                        << (slotIndex ==
                            static_cast<long long>(bindingAllocated)
                            ? 1 : 0)
                        << ",UNREADABLE\n";
                    break;
                }

                bindingFreeWalk
                    << ordinal
                    << ",0x"
                    << std::hex
                    << std::uppercase
                    << address
                    << ",0x"
                    << reinterpret_cast<std::uintptr_t>(
                           link.next)
                    << std::dec
                    << ','
                    << slotIndex
                    << ','
                    << (insidePool ? 1 : 0)
                    << ','
                    << (slotIndex ==
                        static_cast<long long>(bindingAllocated)
                        ? 1 : 0)
                    << ",OK\n";

                ++bindingFreeNodes;
                node = link.next;
            }
        }

        bindingFreeWalk.flush();

        // -----------------------------------------------------------------
        // [g_assetPool INDIRECT HOLDER / POINTER SEARCH]
        //
        // Search writable module data for qwords equal to the g_assetPool base,
        // then scan executable code for references to those holder addresses.
        // -----------------------------------------------------------------
        assetPoolIndirect
            << "label,holder_address,holder_section,code_section,"
               "instruction_address,bytes,confidence,notes\n";

        const auto poolBase =
            reinterpret_cast<std::uintptr_t>(g_assetPool);

        std::vector<std::pair<std::uintptr_t, std::string>>
            poolHolders;

        HMODULE indirectExe =
            GetModuleHandleW(nullptr);

        if (indirectExe && poolBase)
        {
            const auto moduleBase =
                reinterpret_cast<std::uintptr_t>(indirectExe);

            IMAGE_DOS_HEADER dos{};

            if (CopyFromProcess(
                    reinterpret_cast<const void*>(moduleBase),
                    &dos,
                    sizeof(dos)) &&
                dos.e_magic == IMAGE_DOS_SIGNATURE)
            {
                IMAGE_NT_HEADERS64 nt{};

                const auto ntAddress =
                    moduleBase +
                    static_cast<std::uintptr_t>(dos.e_lfanew);

                if (CopyFromProcess(
                        reinterpret_cast<const void*>(ntAddress),
                        &nt,
                        sizeof(nt)) &&
                    nt.Signature == IMAGE_NT_SIGNATURE)
                {
                    const auto shBase =
                        ntAddress +
                        sizeof(DWORD) +
                        sizeof(IMAGE_FILE_HEADER) +
                        nt.FileHeader.SizeOfOptionalHeader;

                    // Pass 1: writable sections containing poolBase qword.
                    for (unsigned int si = 0;
                         si < nt.FileHeader.NumberOfSections;
                         ++si)
                    {
                        IMAGE_SECTION_HEADER sh{};

                        if (!CopyFromProcess(
                                reinterpret_cast<const void*>(
                                    shBase +
                                    static_cast<std::uintptr_t>(si) *
                                    sizeof(sh)),
                                &sh,
                                sizeof(sh)))
                        {
                            continue;
                        }

                        if (!(sh.Characteristics & IMAGE_SCN_MEM_READ) ||
                            !(sh.Characteristics & IMAGE_SCN_MEM_WRITE) ||
                            (sh.Characteristics & IMAGE_SCN_MEM_EXECUTE))
                        {
                            continue;
                        }

                        char sectionName[9]{};
                        std::memcpy(sectionName, sh.Name, 8);

                        const std::size_t sectionSize =
                            static_cast<std::size_t>(
                                std::max(
                                    sh.Misc.VirtualSize,
                                    sh.SizeOfRawData));

                        if (sectionSize < 8 ||
                            sectionSize > 512ull * 1024ull * 1024ull)
                        {
                            continue;
                        }

                        const auto sectionAddress =
                            moduleBase + sh.VirtualAddress;

                        std::vector<unsigned char> bytes(sectionSize);

                        if (!CopyFromProcess(
                                reinterpret_cast<const void*>(sectionAddress),
                                bytes.data(),
                                bytes.size()))
                        {
                            continue;
                        }

                        for (std::size_t off = 0;
                             off + 8 <= bytes.size();
                             off += 8)
                        {
                            std::uint64_t value = 0;
                            std::memcpy(
                                &value,
                                bytes.data() + off,
                                sizeof(value));

                            if (value == poolBase)
                            {
                                poolHolders.push_back({
                                    sectionAddress + off,
                                    sectionName
                                });
                            }
                        }
                    }

                    // Pass 2: xrefs to each holder.
                    for (unsigned int si = 0;
                         si < nt.FileHeader.NumberOfSections;
                         ++si)
                    {
                        IMAGE_SECTION_HEADER sh{};

                        if (!CopyFromProcess(
                                reinterpret_cast<const void*>(
                                    shBase +
                                    static_cast<std::uintptr_t>(si) *
                                    sizeof(sh)),
                                &sh,
                                sizeof(sh)))
                        {
                            continue;
                        }

                        if (!(sh.Characteristics & IMAGE_SCN_MEM_EXECUTE) ||
                            !(sh.Characteristics & IMAGE_SCN_MEM_READ))
                        {
                            continue;
                        }

                        char sectionName[9]{};
                        std::memcpy(sectionName, sh.Name, 8);

                        const std::size_t sectionSize =
                            static_cast<std::size_t>(
                                std::max(
                                    sh.Misc.VirtualSize,
                                    sh.SizeOfRawData));

                        if (sectionSize < 8 ||
                            sectionSize > 512ull * 1024ull * 1024ull)
                        {
                            continue;
                        }

                        const auto sectionAddress =
                            moduleBase + sh.VirtualAddress;

                        std::vector<unsigned char> bytes(sectionSize);

                        if (!CopyFromProcess(
                                reinterpret_cast<const void*>(sectionAddress),
                                bytes.data(),
                                bytes.size()))
                        {
                            continue;
                        }

                        for (std::size_t off = 0;
                             off + 12 <= bytes.size();
                             ++off)
                        {
                            for (unsigned int len = 5;
                                 len <= 12;
                                 ++len)
                            {
                                for (unsigned int dispOff = 1;
                                     dispOff + 4 <= len;
                                     ++dispOff)
                                {
                                    std::int32_t disp = 0;

                                    std::memcpy(
                                        &disp,
                                        bytes.data() + off + dispOff,
                                        sizeof(disp));

                                    const auto target =
                                        static_cast<std::uintptr_t>(
                                            static_cast<std::intptr_t>(
                                                sectionAddress + off + len) +
                                            disp);

                                    for (const auto& holder : poolHolders)
                                    {
                                        if (target != holder.first)
                                            continue;

                                        std::ostringstream byteText;

                                        const unsigned int dumpLen =
                                            std::min<unsigned int>(
                                                24u,
                                                static_cast<unsigned int>(
                                                    bytes.size() - off));

                                        for (unsigned int bi = 0;
                                             bi < dumpLen;
                                             ++bi)
                                        {
                                            if (bi)
                                                byteText << ' ';

                                            byteText
                                                << std::hex
                                                << std::uppercase
                                                << std::setw(2)
                                                << std::setfill('0')
                                                << static_cast<unsigned int>(
                                                       bytes[off + bi]);
                                        }

                                        assetPoolIndirect
                                            << "ASSETPOOL_INDIRECT_XREF,0x"
                                            << std::hex
                                            << std::uppercase
                                            << holder.first
                                            << ','
                                            << holder.second
                                            << ','
                                            << sectionName
                                            << ",0x"
                                            << (sectionAddress + off)
                                            << std::dec
                                            << ",\""
                                            << byteText.str()
                                            << "\",HIGH,"
                                            << "code references a writable global holding g_assetPool base; inspect containing function for indexed XAssetType access"
                                            << "\n";
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        if (poolHolders.empty())
        {
            assetPoolIndirect
                << "ASSETPOOL_HOLDER_NONE,0,none,none,0,\"\",NONE,"
                   "no writable module qword directly held g_assetPool base"
                   "\n";
        }

        assetPoolIndirect.flush();

        rankedSummary
            << "[RANKED CAMO LAYER + GENERIC POOL ALLOCATOR PASS]\n"
            << "mode=" << (deep ? "DEEP" : "FAST") << "\n"
            << "deduplicated_layer_hits=" << layerHits.size() << "\n"
            << "ranked_path_count=" << std::min(stats.size(), maxRankedPaths) << "\n"
            << "generic_pool_xrefs=" << genericPoolHits << "\n"
            << "\n"
            << "[NEXT TEST]\n"
            << "ONE normal /scan camo on ONE MP camo is enough.\n"
            << "Send _57, _58, _74, _93 plus the full camo_scan group.\n"
            << "\n"
            << "[INTERPRETATION]\n"
            << "Top recurring paths in _57 are the best candidates for stable shader layer slots.\n"
            << "_58 flags child tables containing multiple GfxImage pointers.\n"
            << "_74 looks for code touching the XAssetPool entries themselves rather than transient freeHead addresses.\n";

        rankedSummary.flush();

        phaseSummary
            << "[MATERIAL +0x30 / g_assetPool BASE PASS]\n"
            << "mode=" << (deep ? "DEEP" : "FAST") << "\n"
            << "material30_tables=" << material30Tables << "\n"
            << "material30_image_entries=" << material30ImageEntries << "\n"
            << "assetPool_base_xrefs=" << assetPoolBaseHits << "\n"
            << "\n"
            << "[NEXT TEST]\n"
            << "ONE normal /scan camo on ONE MP camo is enough.\n"
            << "Send _59, _75, _94 plus the rest of the camo_scan group.\n"
            << "\n"
            << "[WHAT WE ARE TRYING TO CONFIRM]\n"
            << "1. Which qword within each 24-byte Material+0x30 entry is the GfxImage pointer.\n"
            << "2. Whether entry index maps consistently to color/normal/mask/layer0/layer1.\n"
            << "3. Which function indexes g_assetPool[] and performs generic asset allocation/addition.\n";

        phaseSummary.flush();

        finalFocusedSummary
            << "[Q0 TABLE / BINDING FREELIST / INDIRECT POOL PASS]\n"
            << "mode=" << (deep ? "DEEP" : "FAST") << "\n"
            << "q0_tables=" << q0Tables << "\n"
            << "q0_entries=" << q0Entries << "\n"
            << "binding_freelist_nodes=" << bindingFreeNodes << "\n"
            << "binding_first_free_index=" << firstBindingFreeIndex << "\n"
            << "binding_itemAllocCount=" << bindingAllocated << "\n"
            << "assetPool_holder_count=" << poolHolders.size() << "\n"
            << "\n"
            << "[NEXT TEST]\n"
            << "ONE normal /scan camo on ONE MP camo is enough.\n"
            << "Send _60, _76, _77, _95 plus the full camo_scan group.\n"
            << "\n"
            << "[KEY QUESTIONS]\n"
            << "1. Do Q1/Q2 metadata values cluster by entry index/role?\n"
            << "2. What is the real first binding free-list index?\n"
            << "3. Is there a writable holder/global for g_assetPool that executable code references?\n";

        finalFocusedSummary.flush();

        // -----------------------------------------------------------------
        // [READ-ONLY SYNTHETIC ADDITIVE PREVIEW]
        //
        // Construct a validation report for what a new WeaponCamo would need
        // WITHOUT modifying game memory. This separates asset feasibility from
        // menu enumeration feasibility.
        // -----------------------------------------------------------------
        const auto nextCamoAddressPreview =
            camoBase +
            static_cast<std::uintptr_t>(camoAllocated) *
            camoPool->itemSize;

        const auto bindingFreeAddressPreview =
            reinterpret_cast<std::uintptr_t>(bindingPool->freeHead);

        long long bindingFreeIndexPreview = -1;

        if (bindingFreeAddressPreview >= bindingBase &&
            bindingPool->itemSize > 0)
        {
            const auto delta =
                bindingFreeAddressPreview - bindingBase;

            if ((delta % bindingPool->itemSize) == 0)
            {
                const auto idx =
                    delta / bindingPool->itemSize;

                if (idx < bindingCapacity)
                    bindingFreeIndexPreview =
                        static_cast<long long>(idx);
            }
        }

        syntheticPreview
            << "[SYNTHETIC ADDITIVE CAMO PREVIEW - READ ONLY]\n"
            << "weaponCamo.nextIndex=" << camoAllocated << "\n"
            << "weaponCamo.nextAddress=0x"
            << std::hex << std::uppercase
            << nextCamoAddressPreview << std::dec << "\n"
            << "weaponCamo.freeHead=0x"
            << std::hex << std::uppercase
            << reinterpret_cast<std::uintptr_t>(camoPool->freeHead)
            << std::dec << "\n"
            << "weaponCamo.freeHeadMatchesNext="
            << (reinterpret_cast<std::uintptr_t>(camoPool->freeHead) ==
                nextCamoAddressPreview ? 1 : 0)
            << "\n"
            << "binding.freeHead=0x"
            << std::hex << std::uppercase
            << bindingFreeAddressPreview
            << std::dec << "\n"
            << "binding.freeIndex="
            << bindingFreeIndexPreview << "\n"
            << "material.semanticClusters="
            << semanticBuckets.size() << "\n"
            << "\n"
            << "[WHAT A SAFE ADDITIVE INSERTION MUST DO]\n"
            << "1. Allocate WeaponCamo from freeHead.\n"
            << "2. Initialize/clone definition + material references.\n"
            << "3. Allocate binding from binding freeHead dynamically.\n"
            << "4. Register/enroll both assets through engine bookkeeping.\n"
            << "5. Add the new camo to whatever runtime/UI enumeration source the menu consumes.\n"
            << "\n"
            << "[IMPORTANT]\n"
            << "Asset allocation and menu visibility are treated as separate systems.\n";

        syntheticPreview.flush();

        // -----------------------------------------------------------------
        // [MENU ENUMERATION CANDIDATES]
        //
        // The camo menu may NOT enumerate WeaponCamo directly. Search writable
        // memory for compact arrays containing many valid camo indices (0..57)
        // and/or pointers into the allocated WeaponCamo pool, but rank them by
        // exact uniqueness/coverage rather than generic small-byte runs.
        // -----------------------------------------------------------------
        menuCandidates
            << "label,address,element_width,length,distinct_values,"
               "min_value,max_value,coverage_percent,confidence,notes\n";

        unsigned int menuIndexCandidates = 0;
        unsigned int menuPointerCandidates = 0;

        SYSTEM_INFO menuSys{};
        GetSystemInfo(&menuSys);

        std::uintptr_t menuCursor =
            reinterpret_cast<std::uintptr_t>(
                menuSys.lpMinimumApplicationAddress);

        const auto menuMax =
            reinterpret_cast<std::uintptr_t>(
                menuSys.lpMaximumApplicationAddress);

        std::uint64_t menuBytesScanned = 0;
        const std::uint64_t menuBudget =
            deep
            ? 256ull * 1024ull * 1024ull
            : 64ull * 1024ull * 1024ull;

        while (menuCursor < menuMax &&
               menuBytesScanned < menuBudget)
        {
            MEMORY_BASIC_INFORMATION mbi{};

            if (!VirtualQuery(
                    reinterpret_cast<LPCVOID>(menuCursor),
                    &mbi,
                    sizeof(mbi)))
            {
                break;
            }

            const auto regionBase =
                reinterpret_cast<std::uintptr_t>(
                    mbi.BaseAddress);

            const auto regionSize =
                static_cast<std::uint64_t>(
                    mbi.RegionSize);

            const bool readableWritable =
                mbi.State == MEM_COMMIT &&
                !(mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)) &&
                (mbi.Protect &
                 (PAGE_READWRITE |
                  PAGE_WRITECOPY |
                  PAGE_EXECUTE_READWRITE |
                  PAGE_EXECUTE_WRITECOPY));

            if (readableWritable &&
                regionSize >= 0x100 &&
                regionSize <= 8ull * 1024ull * 1024ull)
            {
                std::vector<unsigned char> bytes(
                    static_cast<std::size_t>(regionSize));

                if (CopyFromProcess(
                        reinterpret_cast<const void*>(regionBase),
                        bytes.data(),
                        bytes.size()))
                {
                    menuBytesScanned += bytes.size();

                    // 32-bit index arrays, much less noisy than raw byte arrays.
                    for (std::size_t off = 0;
                         off + 16 * 4 <= bytes.size();
                         off += 4)
                    {
                        std::vector<unsigned int> vals;
                        vals.reserve(64);

                        for (unsigned int i = 0;
                             i < 64 &&
                             off + (i + 1) * 4 <= bytes.size();
                             ++i)
                        {
                            std::uint32_t v = 0;
                            std::memcpy(
                                &v,
                                bytes.data() + off + i * 4,
                                sizeof(v));

                            if (v >= camoAllocated)
                                break;

                            vals.push_back(v);
                        }

                        if (vals.size() < 8)
                            continue;

                        auto distinct = vals;
                        std::sort(distinct.begin(), distinct.end());
                        distinct.erase(
                            std::unique(distinct.begin(), distinct.end()),
                            distinct.end());

                        if (distinct.size() < 6)
                            continue;

                        const auto minmax =
                            std::minmax_element(vals.begin(), vals.end());

                        const double coverage =
                            camoAllocated
                            ? (100.0 *
                               static_cast<double>(distinct.size()) /
                               static_cast<double>(camoAllocated))
                            : 0.0;

                        const char* confidence =
                            coverage >= 50.0
                            ? "HIGH"
                            : coverage >= 25.0
                                ? "MEDIUM"
                                : "LOW";

                        menuCandidates
                            << "CAMO_MENU_INDEX_ARRAY32,0x"
                            << std::hex << std::uppercase
                            << (regionBase + off)
                            << std::dec
                            << ",32,"
                            << vals.size()
                            << ','
                            << distinct.size()
                            << ','
                            << *minmax.first
                            << ','
                            << *minmax.second
                            << ','
                            << coverage
                            << ','
                            << confidence
                            << ','
                            << "candidate curated features/camo/menu list; compare against category sizes before trusting"
                            << "\n";

                        ++menuIndexCandidates;

                        off += vals.size() * 4 - 4;
                    }

                    // Camo* pointer arrays.
                    for (std::size_t off = 0;
                         off + 8 * 8 <= bytes.size();
                         off += 8)
                    {
                        std::vector<unsigned int> indices;

                        for (unsigned int i = 0;
                             i < 64 &&
                             off + (i + 1) * 8 <= bytes.size();
                             ++i)
                        {
                            std::uint64_t p = 0;
                            std::memcpy(
                                &p,
                                bytes.data() + off + i * 8,
                                sizeof(p));

                            unsigned int index = 0;

                            if (!InPool(p, *camoPool, index) ||
                                index >= camoAllocated)
                            {
                                break;
                            }

                            indices.push_back(index);
                        }

                        if (indices.size() < 6)
                            continue;

                        auto distinct = indices;
                        std::sort(distinct.begin(), distinct.end());
                        distinct.erase(
                            std::unique(distinct.begin(), distinct.end()),
                            distinct.end());

                        const double coverage =
                            camoAllocated
                            ? (100.0 *
                               static_cast<double>(distinct.size()) /
                               static_cast<double>(camoAllocated))
                            : 0.0;

                        menuCandidates
                            << "CAMO_MENU_POINTER_ARRAY,0x"
                            << std::hex << std::uppercase
                            << (regionBase + off)
                            << std::dec
                            << ",64,"
                            << indices.size()
                            << ','
                            << distinct.size()
                            << ",0,"
                            << (camoAllocated ? camoAllocated - 1 : 0)
                            << ','
                            << coverage
                            << ','
                            << (coverage >= 25.0 ? "HIGH" : "MEDIUM")
                            << ','
                            << "candidate runtime menu/enrollment list of WeaponCamo pointers"
                            << "\n";

                        ++menuPointerCandidates;

                        off += indices.size() * 8 - 8;
                    }
                }
            }

            if (regionSize == 0 ||
                regionBase + regionSize <= menuCursor)
            {
                break;
            }

            menuCursor =
                regionBase +
                static_cast<std::uintptr_t>(regionSize);
        }

        if (!menuIndexCandidates &&
            !menuPointerCandidates)
        {
            menuCandidates
                << "CAMO_MENU_CANDIDATE_NONE,0,0,0,0,0,0,0,NONE,"
                   "no compact runtime list found in bounded writable scan\n";
        }

        menuCandidates.flush();

        // -----------------------------------------------------------------
        // [RANKED / DEDUPED MENU LISTS]
        //
        // The previous pass proved there are many candidate 32-bit camo-index
        // arrays. This pass records the actual sequences, deduplicates identical
        // lists, ranks by coverage/length, snapshots nearby qwords, and then
        // searches executable code for direct references to the best list or
        // containing-structure addresses.
        // -----------------------------------------------------------------
        rankedMenuLists
            << "rank,address,length,distinct,coverage_percent,min_value,max_value,"
               "sequence_hash,sequence,near_qword_m20,near_qword_m18,near_qword_m10,"
               "near_qword_m08,near_qword_p00,near_qword_p08,near_qword_p10,"
               "near_qword_p18,confidence,notes\n";

        struct MenuListCandidate
        {
            std::uintptr_t address = 0;
            std::vector<std::uint32_t> values;
            std::vector<std::uint32_t> distinct;
            double coverage = 0.0;
            std::uint64_t hash = 0;
            std::uint64_t nearQ[8]{};
        };

        std::vector<MenuListCandidate> rankedCandidates;
        std::vector<std::uint64_t> seenHashes;

        auto hashSequence =
            [](const std::vector<std::uint32_t>& values)
            {
                std::uint64_t h = 14695981039346656037ull;

                for (const auto v : values)
                {
                    const unsigned char* p =
                        reinterpret_cast<const unsigned char*>(&v);

                    for (std::size_t i = 0; i < sizeof(v); ++i)
                    {
                        h ^= p[i];
                        h *= 1099511628211ull;
                    }
                }

                h ^= static_cast<std::uint64_t>(values.size());
                h *= 1099511628211ull;
                return h;
            };

        SYSTEM_INFO rankSys{};
        GetSystemInfo(&rankSys);

        std::uintptr_t rankCursor =
            reinterpret_cast<std::uintptr_t>(
                rankSys.lpMinimumApplicationAddress);

        const auto rankMax =
            reinterpret_cast<std::uintptr_t>(
                rankSys.lpMaximumApplicationAddress);

        std::uint64_t rankBytesScanned = 0;
        const std::uint64_t rankBudget =
            deep
            ? 256ull * 1024ull * 1024ull
            : 64ull * 1024ull * 1024ull;

        while (rankCursor < rankMax &&
               rankBytesScanned < rankBudget)
        {
            MEMORY_BASIC_INFORMATION mbi{};

            if (!VirtualQuery(
                    reinterpret_cast<LPCVOID>(rankCursor),
                    &mbi,
                    sizeof(mbi)))
            {
                break;
            }

            const auto regionBase =
                reinterpret_cast<std::uintptr_t>(mbi.BaseAddress);

            const auto regionSize =
                static_cast<std::uint64_t>(mbi.RegionSize);

            const bool rw =
                mbi.State == MEM_COMMIT &&
                !(mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)) &&
                (mbi.Protect &
                 (PAGE_READWRITE |
                  PAGE_WRITECOPY |
                  PAGE_EXECUTE_READWRITE |
                  PAGE_EXECUTE_WRITECOPY));

            if (rw &&
                regionSize >= 0x100 &&
                regionSize <= 8ull * 1024ull * 1024ull)
            {
                std::vector<unsigned char> bytes(
                    static_cast<std::size_t>(regionSize));

                if (CopyFromProcess(
                        reinterpret_cast<const void*>(regionBase),
                        bytes.data(),
                        bytes.size()))
                {
                    rankBytesScanned += bytes.size();

                    for (std::size_t off = 0;
                         off + 8 * 4 <= bytes.size();
                         off += 4)
                    {
                        std::vector<std::uint32_t> values;
                        values.reserve(64);

                        for (unsigned int i = 0;
                             i < 64 &&
                             off + (i + 1) * 4 <= bytes.size();
                             ++i)
                        {
                            std::uint32_t v = 0;
                            std::memcpy(
                                &v,
                                bytes.data() + off + i * 4,
                                sizeof(v));

                            if (v >= camoAllocated)
                                break;

                            values.push_back(v);
                        }

                        if (values.size() < 8)
                            continue;

                        auto distinct = values;
                        std::sort(distinct.begin(), distinct.end());
                        distinct.erase(
                            std::unique(distinct.begin(), distinct.end()),
                            distinct.end());

                        if (distinct.size() < 6)
                            continue;

                        const double coverage =
                            camoAllocated
                            ? 100.0 *
                              static_cast<double>(distinct.size()) /
                              static_cast<double>(camoAllocated)
                            : 0.0;

                        if (coverage < 15.0)
                            continue;

                        const auto h =
                            hashSequence(values);

                        if (std::find(
                                seenHashes.begin(),
                                seenHashes.end(),
                                h) != seenHashes.end())
                        {
                            continue;
                        }

                        seenHashes.push_back(h);

                        MenuListCandidate c{};
                        c.address = regionBase + off;
                        c.values = values;
                        c.distinct = distinct;
                        c.coverage = coverage;
                        c.hash = h;

                        // Snapshot 0x20 bytes before and after list start.
                        const std::intptr_t offsets[8] =
                        {
                            -0x20, -0x18, -0x10, -0x08,
                             0x00,  0x08,  0x10,  0x18
                        };

                        for (unsigned int qi = 0; qi < 8; ++qi)
                        {
                            const auto addr =
                                static_cast<std::uintptr_t>(
                                    static_cast<std::intptr_t>(c.address) +
                                    offsets[qi]);

                            CopyFromProcess(
                                reinterpret_cast<const void*>(addr),
                                &c.nearQ[qi],
                                sizeof(c.nearQ[qi]));
                        }

                        rankedCandidates.push_back(
                            std::move(c));

                        off += values.size() * 4 - 4;
                    }
                }
            }

            if (regionSize == 0 ||
                regionBase + regionSize <= rankCursor)
            {
                break;
            }

            rankCursor =
                regionBase +
                static_cast<std::uintptr_t>(regionSize);
        }

        std::sort(
            rankedCandidates.begin(),
            rankedCandidates.end(),
            [](const MenuListCandidate& a,
               const MenuListCandidate& b)
            {
                const double scoreA =
                    a.coverage * 10.0 +
                    static_cast<double>(a.values.size());

                const double scoreB =
                    b.coverage * 10.0 +
                    static_cast<double>(b.values.size());

                return scoreA > scoreB;
            });

        const std::size_t maxMenuRank =
            deep ? 128u : 40u;

        const std::size_t rankedCount =
            std::min(
                rankedCandidates.size(),
                maxMenuRank);

        for (std::size_t i = 0;
             i < rankedCount;
             ++i)
        {
            const auto& c =
                rankedCandidates[i];

            std::ostringstream sequence;

            for (std::size_t vi = 0;
                 vi < c.values.size();
                 ++vi)
            {
                if (vi)
                    sequence << ' ';

                sequence << c.values[vi];
            }

            const auto minmax =
                std::minmax_element(
                    c.values.begin(),
                    c.values.end());

            const char* confidence =
                c.coverage >= 50.0
                ? "HIGH"
                : c.coverage >= 30.0
                    ? "MEDIUM"
                    : "LOW";

            rankedMenuLists
                << (i + 1)
                << ",0x"
                << std::hex
                << std::uppercase
                << c.address
                << std::dec
                << ','
                << c.values.size()
                << ','
                << c.distinct.size()
                << ','
                << c.coverage
                << ','
                << *minmax.first
                << ','
                << *minmax.second
                << ",0x"
                << std::hex
                << std::uppercase
                << c.hash
                << std::dec
                << ",\""
                << sequence.str()
                << "\"";

            for (const auto q : c.nearQ)
            {
                rankedMenuLists
                    << ",0x"
                    << std::hex
                    << std::uppercase
                    << q
                    << std::dec;
            }

            rankedMenuLists
                << ','
                << confidence
                << ','
                << "deduped candidate; surrounding qwords may expose count/category/owner pointer"
                << "\n";
        }

        rankedMenuLists.flush();

        // -----------------------------------------------------------------
        // [MENU LIST / STRUCTURE XREFS]
        // Search executable code for direct references to top list addresses
        // and the common likely structure starts immediately before them.
        // -----------------------------------------------------------------
        menuStructureXrefs
            << "label,rank,list_address,target_address,target_kind,"
               "section,instruction_address,bytes,confidence,notes\n";

        std::vector<std::pair<std::uintptr_t, std::pair<unsigned int, const char*>>>
            menuTargets;

        for (std::size_t i = 0;
             i < rankedCount &&
             i < 16;
             ++i)
        {
            const auto addr =
                rankedCandidates[i].address;

            menuTargets.push_back({
                addr,
                {
                    static_cast<unsigned int>(i + 1),
                    "LIST_START"
                }
            });

            if (addr >= 0x20)
            {
                menuTargets.push_back({
                    addr - 0x20,
                    {
                        static_cast<unsigned int>(i + 1),
                        "STRUCT_MINUS_0x20"
                    }
                });
            }
        }

        unsigned int menuXrefHits = 0;
        HMODULE menuExe =
            GetModuleHandleW(nullptr);

        if (menuExe && !menuTargets.empty())
        {
            const auto moduleBase =
                reinterpret_cast<std::uintptr_t>(menuExe);

            IMAGE_DOS_HEADER dos{};

            if (CopyFromProcess(
                    reinterpret_cast<const void*>(moduleBase),
                    &dos,
                    sizeof(dos)) &&
                dos.e_magic == IMAGE_DOS_SIGNATURE)
            {
                IMAGE_NT_HEADERS64 nt{};

                const auto ntAddress =
                    moduleBase +
                    static_cast<std::uintptr_t>(dos.e_lfanew);

                if (CopyFromProcess(
                        reinterpret_cast<const void*>(ntAddress),
                        &nt,
                        sizeof(nt)) &&
                    nt.Signature == IMAGE_NT_SIGNATURE)
                {
                    const auto shBase =
                        ntAddress +
                        sizeof(DWORD) +
                        sizeof(IMAGE_FILE_HEADER) +
                        nt.FileHeader.SizeOfOptionalHeader;

                    for (unsigned int si = 0;
                         si < nt.FileHeader.NumberOfSections;
                         ++si)
                    {
                        IMAGE_SECTION_HEADER sh{};

                        if (!CopyFromProcess(
                                reinterpret_cast<const void*>(
                                    shBase +
                                    static_cast<std::uintptr_t>(si) *
                                    sizeof(sh)),
                                &sh,
                                sizeof(sh)))
                        {
                            continue;
                        }

                        if (!(sh.Characteristics & IMAGE_SCN_MEM_EXECUTE) ||
                            !(sh.Characteristics & IMAGE_SCN_MEM_READ))
                        {
                            continue;
                        }

                        char sectionName[9]{};
                        std::memcpy(sectionName, sh.Name, 8);

                        const std::size_t sectionSize =
                            static_cast<std::size_t>(
                                std::max(
                                    sh.Misc.VirtualSize,
                                    sh.SizeOfRawData));

                        if (sectionSize < 8 ||
                            sectionSize > 512ull * 1024ull * 1024ull)
                        {
                            continue;
                        }

                        const auto sectionAddress =
                            moduleBase + sh.VirtualAddress;

                        std::vector<unsigned char> bytes(sectionSize);

                        if (!CopyFromProcess(
                                reinterpret_cast<const void*>(sectionAddress),
                                bytes.data(),
                                bytes.size()))
                        {
                            continue;
                        }

                        for (std::size_t off = 0;
                             off + 12 <= bytes.size();
                             ++off)
                        {
                            for (unsigned int len = 5;
                                 len <= 12;
                                 ++len)
                            {
                                for (unsigned int dispOff = 1;
                                     dispOff + 4 <= len;
                                     ++dispOff)
                                {
                                    std::int32_t disp = 0;

                                    std::memcpy(
                                        &disp,
                                        bytes.data() + off + dispOff,
                                        sizeof(disp));

                                    const auto target =
                                        static_cast<std::uintptr_t>(
                                            static_cast<std::intptr_t>(
                                                sectionAddress + off + len) +
                                            disp);

                                    for (const auto& mt : menuTargets)
                                    {
                                        if (target != mt.first)
                                            continue;

                                        std::ostringstream byteText;

                                        const unsigned int dumpLen =
                                            std::min<unsigned int>(
                                                24u,
                                                static_cast<unsigned int>(
                                                    bytes.size() - off));

                                        for (unsigned int bi = 0;
                                             bi < dumpLen;
                                             ++bi)
                                        {
                                            if (bi)
                                                byteText << ' ';

                                            byteText
                                                << std::hex
                                                << std::uppercase
                                                << std::setw(2)
                                                << std::setfill('0')
                                                << static_cast<unsigned int>(
                                                       bytes[off + bi]);
                                        }

                                        menuStructureXrefs
                                            << "MENU_STRUCTURE_XREF,"
                                            << mt.second.first
                                            << ",0x"
                                            << std::hex
                                            << std::uppercase
                                            << rankedCandidates[
                                                   mt.second.first - 1].address
                                            << ",0x"
                                            << target
                                            << std::dec
                                            << ','
                                            << mt.second.second
                                            << ','
                                            << sectionName
                                            << ",0x"
                                            << std::hex
                                            << std::uppercase
                                            << (sectionAddress + off)
                                            << std::dec
                                            << ",\""
                                            << byteText.str()
                                            << "\",HIGH,"
                                            << "code references ranked menu list/nearby structure"
                                            << "\n";

                                        ++menuXrefHits;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        if (!menuXrefHits)
        {
            menuStructureXrefs
                << "MENU_STRUCTURE_XREF_NONE,0,0,0,none,none,0,\"\",NONE,"
                   "no direct code xref to top runtime lists; may be heap objects reached indirectly"
                   "\n";
        }

        menuStructureXrefs.flush();

        menuSummary
            << "[MENU VS ASSET RESEARCH]\n"
            << "weaponCamoAssets=" << camoAllocated << "/" << camoCapacity << "\n"
            << "bindingFirstFree=" << bindingFreeIndexPreview << "\n"
            << "semanticClusters=" << semanticBuckets.size() << "\n"
            << "menuIndexCandidates=" << menuIndexCandidates << "\n"
            << "menuPointerCandidates=" << menuPointerCandidates << "\n"
            << "menuBytesScanned=" << menuBytesScanned << "\n"
            << "\n"
            << "[INTERPRETATION]\n"
            << "The menu is NOT assumed to enumerate WeaponCamo directly.\n"
            << "A valid additive asset can exist without appearing in UI if a separate category/list/unlock table excludes it.\n"
            << "Likewise, visible empty tiles do not prove there are unused WeaponCamo asset records.\n"
            << "\n"
            << "[NEXT TEST]\n"
            << "ONE /scan camo on ONE MP camo is enough.\n"
            << "Send _61, _78, _85, _96 plus the full group.\n";

        menuSummary.flush();

        // -----------------------------------------------------------------
        // [GENERIC XASSETPOOL REGISTRATION-FUNCTION DISCOVERY]
        //
        // Direct xrefs to the WeaponCamo pool/freeHead were empty. Instead,
        // search executable code for functions/windows that access MULTIPLE
        // XAssetPool field offsets needed by allocation/registration.
        //
        // This is intentionally read-only and heuristic. We do not execute or
        // patch any candidate.
        // -----------------------------------------------------------------
        registrationFieldCandidates
            << "rank,window_start,window_end,section,"
               "pool_field_hits,item_size_hits,item_count_hits,"
               "item_alloc_count_hits,free_head_hits,"
               "unique_field_count,total_hits,score,confidence,notes\n";

        // Derive real field offsets from the live structure layout used by
        // this project rather than hard-coding guesses.
        const std::uintptr_t poolStructBase =
            reinterpret_cast<std::uintptr_t>(camoPool);

        const unsigned int offPool =
            static_cast<unsigned int>(
                reinterpret_cast<std::uintptr_t>(&camoPool->pool) -
                poolStructBase);

        const unsigned int offItemSize =
            static_cast<unsigned int>(
                reinterpret_cast<std::uintptr_t>(&camoPool->itemSize) -
                poolStructBase);

        const unsigned int offItemCount =
            static_cast<unsigned int>(
                reinterpret_cast<std::uintptr_t>(&camoPool->itemCount) -
                poolStructBase);

        const unsigned int offItemAllocCount =
            static_cast<unsigned int>(
                reinterpret_cast<std::uintptr_t>(&camoPool->itemAllocCount) -
                poolStructBase);

        const unsigned int offFreeHead =
            static_cast<unsigned int>(
                reinterpret_cast<std::uintptr_t>(&camoPool->freeHead) -
                poolStructBase);

        struct RegistrationWindow
        {
            std::uintptr_t start = 0;
            std::uintptr_t end = 0;
            std::string section;
            unsigned int poolHits = 0;
            unsigned int itemSizeHits = 0;
            unsigned int itemCountHits = 0;
            unsigned int allocHits = 0;
            unsigned int freeHeadHits = 0;
            unsigned int uniqueFields = 0;
            unsigned int totalHits = 0;
            unsigned int score = 0;
            std::vector<unsigned char> bytes;
        };

        std::vector<RegistrationWindow> registrationCandidates;

        auto countDispHits =
            [](const std::vector<unsigned char>& bytes,
               unsigned int displacement)
            {
                unsigned int hits = 0;

                const unsigned char d8 =
                    static_cast<unsigned char>(
                        displacement & 0xFFu);

                // Small structure fields often compile as disp8.
                if (displacement <= 0x7Fu)
                {
                    for (std::size_t i = 0; i < bytes.size(); ++i)
                    {
                        if (bytes[i] == d8)
                            ++hits;
                    }
                }

                // Also check disp32 little-endian form.
                if (bytes.size() >= 4)
                {
                    for (std::size_t i = 0;
                         i + 4 <= bytes.size();
                         ++i)
                    {
                        std::uint32_t v = 0;
                        std::memcpy(
                            &v,
                            bytes.data() + i,
                            sizeof(v));

                        if (v == displacement)
                            ++hits;
                    }
                }

                return hits;
            };

        HMODULE regExe =
            GetModuleHandleW(nullptr);

        if (regExe)
        {
            const auto moduleBase =
                reinterpret_cast<std::uintptr_t>(regExe);

            IMAGE_DOS_HEADER dos{};

            if (CopyFromProcess(
                    reinterpret_cast<const void*>(moduleBase),
                    &dos,
                    sizeof(dos)) &&
                dos.e_magic == IMAGE_DOS_SIGNATURE)
            {
                IMAGE_NT_HEADERS64 nt{};

                const auto ntAddress =
                    moduleBase +
                    static_cast<std::uintptr_t>(dos.e_lfanew);

                if (CopyFromProcess(
                        reinterpret_cast<const void*>(ntAddress),
                        &nt,
                        sizeof(nt)) &&
                    nt.Signature == IMAGE_NT_SIGNATURE)
                {
                    const auto shBase =
                        ntAddress +
                        sizeof(DWORD) +
                        sizeof(IMAGE_FILE_HEADER) +
                        nt.FileHeader.SizeOfOptionalHeader;

                    for (unsigned int si = 0;
                         si < nt.FileHeader.NumberOfSections;
                         ++si)
                    {
                        IMAGE_SECTION_HEADER sh{};

                        if (!CopyFromProcess(
                                reinterpret_cast<const void*>(
                                    shBase +
                                    static_cast<std::uintptr_t>(si) *
                                    sizeof(sh)),
                                &sh,
                                sizeof(sh)))
                        {
                            continue;
                        }

                        if (!(sh.Characteristics & IMAGE_SCN_MEM_EXECUTE) ||
                            !(sh.Characteristics & IMAGE_SCN_MEM_READ))
                        {
                            continue;
                        }

                        char sectionName[9]{};
                        std::memcpy(sectionName, sh.Name, 8);

                        const std::size_t sectionSize =
                            static_cast<std::size_t>(
                                std::max(
                                    sh.Misc.VirtualSize,
                                    sh.SizeOfRawData));

                        if (sectionSize < 0x100 ||
                            sectionSize > 512ull * 1024ull * 1024ull)
                        {
                            continue;
                        }

                        const auto sectionAddress =
                            moduleBase + sh.VirtualAddress;

                        std::vector<unsigned char> sectionBytes(sectionSize);

                        if (!CopyFromProcess(
                                reinterpret_cast<const void*>(sectionAddress),
                                sectionBytes.data(),
                                sectionBytes.size()))
                        {
                            continue;
                        }

                        // Use 0x100-byte windows stepped by 0x40. This is small
                        // enough to rank likely allocator helpers without needing
                        // a full disassembler/function-boundary database.
                        constexpr std::size_t kWindow = 0x100;
                        constexpr std::size_t kStep = 0x40;

                        for (std::size_t off = 0;
                             off + kWindow <= sectionBytes.size();
                             off += kStep)
                        {
                            std::vector<unsigned char> window(
                                sectionBytes.begin() + off,
                                sectionBytes.begin() + off + kWindow);

                            const unsigned int poolHits =
                                countDispHits(window, offPool);

                            const unsigned int itemSizeHits =
                                countDispHits(window, offItemSize);

                            const unsigned int itemCountHits =
                                countDispHits(window, offItemCount);

                            const unsigned int allocHits =
                                countDispHits(window, offItemAllocCount);

                            const unsigned int freeHeadHits =
                                countDispHits(window, offFreeHead);

                            unsigned int unique = 0;
                            unique += poolHits ? 1u : 0u;
                            unique += itemSizeHits ? 1u : 0u;
                            unique += itemCountHits ? 1u : 0u;
                            unique += allocHits ? 1u : 0u;
                            unique += freeHeadHits ? 1u : 0u;

                            const unsigned int total =
                                poolHits +
                                itemSizeHits +
                                itemCountHits +
                                allocHits +
                                freeHeadHits;

                            // We care most about itemAllocCount + freeHead in
                            // the same local region, with itemSize/count as
                            // additional evidence.
                            unsigned int score =
                                unique * 20u +
                                total * 2u +
                                (allocHits ? 25u : 0u) +
                                (freeHeadHits ? 25u : 0u) +
                                ((allocHits && freeHeadHits) ? 40u : 0u);

                            if (unique < 3 ||
                                score < 90)
                            {
                                continue;
                            }

                            registrationCandidates.push_back({
                                sectionAddress + off,
                                sectionAddress + off + kWindow,
                                sectionName,
                                poolHits,
                                itemSizeHits,
                                itemCountHits,
                                allocHits,
                                freeHeadHits,
                                unique,
                                total,
                                score,
                                std::move(window)
                            });
                        }
                    }
                }
            }
        }

        // Deduplicate heavily overlapping windows by keeping the highest score
        // in each 0x100-byte neighborhood.
        std::sort(
            registrationCandidates.begin(),
            registrationCandidates.end(),
            [](const RegistrationWindow& a,
               const RegistrationWindow& b)
            {
                if (a.score != b.score)
                    return a.score > b.score;

                return a.start < b.start;
            });

        std::vector<RegistrationWindow> dedupedRegistration;

        for (const auto& c : registrationCandidates)
        {
            bool overlaps = false;

            for (const auto& kept : dedupedRegistration)
            {
                const auto distance =
                    c.start > kept.start
                    ? c.start - kept.start
                    : kept.start - c.start;

                if (distance < 0x100)
                {
                    overlaps = true;
                    break;
                }
            }

            if (!overlaps)
            {
                dedupedRegistration.push_back(c);

                if (dedupedRegistration.size() >=
                    (deep ? 128u : 48u))
                {
                    break;
                }
            }
        }

        unsigned int regRank = 1;

        for (const auto& c : dedupedRegistration)
        {
            const char* confidence =
                c.uniqueFields >= 5 &&
                c.allocHits &&
                c.freeHeadHits
                ? "HIGH"
                : c.uniqueFields >= 4
                    ? "MEDIUM"
                    : "LOW";

            registrationFieldCandidates
                << regRank
                << ",0x"
                << std::hex
                << std::uppercase
                << c.start
                << ",0x"
                << c.end
                << std::dec
                << ','
                << c.section
                << ','
                << c.poolHits
                << ','
                << c.itemSizeHits
                << ','
                << c.itemCountHits
                << ','
                << c.allocHits
                << ','
                << c.freeHeadHits
                << ','
                << c.uniqueFields
                << ','
                << c.totalHits
                << ','
                << c.score
                << ','
                << confidence
                << ','
                << "ranked by XAssetPool field-offset co-occurrence; inspect for allocator/add/register bookkeeping"
                << "\n";

            registrationWindows
                << "[RANK "
                << regRank
                << "] section="
                << c.section
                << " start=0x"
                << std::hex
                << std::uppercase
                << c.start
                << " score="
                << std::dec
                << c.score
                << " uniqueFields="
                << c.uniqueFields
                << "\n";

            registrationWindows
                << "offsets: pool=0x"
                << std::hex
                << offPool
                << " itemSize=0x"
                << offItemSize
                << " itemCount=0x"
                << offItemCount
                << " itemAllocCount=0x"
                << offItemAllocCount
                << " freeHead=0x"
                << offFreeHead
                << std::dec
                << "\nbytes:\n";

            for (std::size_t i = 0;
                 i < c.bytes.size();
                 ++i)
            {
                if ((i % 16) == 0)
                {
                    registrationWindows
                        << "  +0x"
                        << std::hex
                        << std::uppercase
                        << i
                        << ": ";
                }

                registrationWindows
                    << std::hex
                    << std::uppercase
                    << std::setw(2)
                    << std::setfill('0')
                    << static_cast<unsigned int>(c.bytes[i])
                    << ' ';

                if ((i % 16) == 15)
                    registrationWindows << "\n";
            }

            registrationWindows
                << std::dec
                << "\n";

            ++regRank;
        }

        if (dedupedRegistration.empty())
        {
            registrationFieldCandidates
                << "0,0,0,none,0,0,0,0,0,0,0,0,NONE,"
                   "no strong XAssetPool field-cooccurrence window found\n";

            registrationWindows
                << "No strong registration candidate windows found.\n";
        }

        registrationFieldCandidates.flush();
        registrationWindows.flush();

        // -----------------------------------------------------------------
        // [FIRST ADDITIVE PROTOTYPE READINESS GATE]
        //
        // This does not create anything. It makes the decision explicit so we
        // know exactly when it is reasonable to attempt a non-replacement camo.
        // -----------------------------------------------------------------
        const auto prototypeNextCamo =
            camoBase +
            static_cast<std::uintptr_t>(camoAllocated) *
            camoPool->itemSize;

        const bool gateCamoAllocator =
            camoAllocated < camoCapacity &&
            reinterpret_cast<std::uintptr_t>(
                camoPool->freeHead) ==
            prototypeNextCamo;

        const auto prototypeBindingHead =
            reinterpret_cast<std::uintptr_t>(
                bindingPool->freeHead);

        bool gateBindingAllocator = false;
        long long prototypeBindingIndex = -1;

        if (prototypeBindingHead >= bindingBase &&
            bindingPool->itemSize > 0)
        {
            const auto delta =
                prototypeBindingHead - bindingBase;

            if ((delta % bindingPool->itemSize) == 0)
            {
                const auto idx =
                    delta / bindingPool->itemSize;

                if (idx < bindingCapacity)
                {
                    gateBindingAllocator = true;
                    prototypeBindingIndex =
                        static_cast<long long>(idx);
                }
            }
        }

        const bool gateMaterialLayout =
            !semanticBuckets.empty();

        const bool gateMenuEvidence =
            rankedCount > 0;

        // Registration remains the hard blocker until we have either:
        //  - a resolved engine add/register path, or
        //  - a completely validated manual allocator/bookkeeping model.
        const bool gateRegistration =
            false;

        const bool readyForPrototype =
            gateCamoAllocator &&
            gateBindingAllocator &&
            gateMaterialLayout &&
            gateRegistration;

        prototypeReadiness
            << "[FIRST NON-REPLACEMENT CAMO PROTOTYPE READINESS]\n"
            << "WeaponCamo allocator=" << (gateCamoAllocator ? "PASS" : "FAIL") << "\n"
            << "Binding allocator=" << (gateBindingAllocator ? "PASS" : "FAIL") << "\n"
            << "Binding free index=" << prototypeBindingIndex << "\n"
            << "Material/texture semantic layout=" << (gateMaterialLayout ? "PASS" : "FAIL") << "\n"
            << "Menu enumeration evidence=" << (gateMenuEvidence ? "PASS" : "FAIL") << "\n"
            << "Engine registration/add-asset path=" << (gateRegistration ? "PASS" : "BLOCKED") << "\n"
            << "\n"
            << "READY_FOR_FIRST_NON_REPLACEMENT_PROTOTYPE="
            << (readyForPrototype ? "YES" : "NO")
            << "\n\n"
            << "[WHY]\n";

        if (!gateRegistration)
        {
            prototypeReadiness
                << "The remaining hard blocker is safe asset registration/bookkeeping.\n"
                << "Do not write slot " << camoAllocated
                << " yet. The asset-side structure is close, but we still need the engine registration path or an equivalently validated manual allocator sequence.\n";
        }

        if (gateMenuEvidence)
        {
            prototypeReadiness
                << "Menu evidence exists, but menu enrollment is not required for the FIRST prototype: we can initially equip the additive camo programmatically once asset registration is safe.\n";
        }

        prototypeReadiness
            << "\n[WHEN TO PROTOTYPE]\n"
            << "Prototype becomes ready when registration/add-asset bookkeeping is resolved. At that point the first test should allocate a new WeaponCamo + Binding and equip it directly without touching the stock camo texture.\n";

        prototypeReadiness.flush();

        // -----------------------------------------------------------------
        // [PROTOTYPE READINESS V2]
        //
        // The registration scanner cannot prove a function is correct by
        // itself, but a HIGH candidate containing all five XAssetPool fields
        // is enough to move from broad research to targeted manual/IDA/runtime
        // validation of one candidate function.
        // -----------------------------------------------------------------
        bool hasHighRegistrationCandidate = false;
        unsigned int bestRegistrationScore = 0;
        std::uintptr_t bestRegistrationAddress = 0;

        for (const auto& c : dedupedRegistration)
        {
            bestRegistrationScore =
                std::max(
                    bestRegistrationScore,
                    c.score);

            if (c.uniqueFields >= 5 &&
                c.allocHits &&
                c.freeHeadHits)
            {
                hasHighRegistrationCandidate = true;

                if (!bestRegistrationAddress)
                    bestRegistrationAddress = c.start;
            }
        }

        prototypeGateV2
            << "[FIRST NON-REPLACEMENT CAMO PROTOTYPE - GATE V2]\n"
            << "WeaponCamo allocator="
            << (gateCamoAllocator ? "PASS" : "FAIL")
            << "\n"
            << "Binding allocator="
            << (gateBindingAllocator ? "PASS" : "FAIL")
            << "\n"
            << "Material/texture layout="
            << (gateMaterialLayout ? "PASS" : "FAIL")
            << "\n"
            << "Menu evidence="
            << (gateMenuEvidence ? "PASS" : "FAIL")
            << "\n"
            << "Registration candidates="
            << dedupedRegistration.size()
            << "\n"
            << "High registration candidate="
            << (hasHighRegistrationCandidate ? "YES" : "NO")
            << "\n"
            << "Best registration score="
            << bestRegistrationScore
            << "\n"
            << "Best registration window=0x"
            << std::hex
            << std::uppercase
            << bestRegistrationAddress
            << std::dec
            << "\n\n";

        if (hasHighRegistrationCandidate)
        {
            prototypeGateV2
                << "STATUS=TARGETED_REGISTRATION_VALIDATION_READY\n"
                << "Meaning: broad scanner research is done. Next step is inspect/validate the top candidate function before any asset write.\n";
        }
        else
        {
            prototypeGateV2
                << "STATUS=REGISTRATION_PATH_STILL_UNRESOLVED\n"
                << "Meaning: do not attempt slot58 writes yet.\n";
        }

        prototypeGateV2
            << "\n"
            << "READY_FOR_FIRST_NON_REPLACEMENT_PROTOTYPE=NO\n"
            << "This flips to YES only after one registration candidate is validated as the real engine add/register path.\n";

        prototypeGateV2.flush();

        // -----------------------------------------------------------------
        // [DECODED X64 REGISTRATION CANDIDATE PASS]
        //
        // Build 158 over-counted raw bytes. This pass parses a conservative
        // subset of real x64 instructions with ModRM/SIB/displacements and
        // only counts XAssetPool field offsets when they occur as memory
        // operands. It also distinguishes likely reads from writes.
        // -----------------------------------------------------------------
        decodedRegistration
            << "rank,function_window_start,function_window_end,section,"
               "decoded_instructions,valid_ratio,"
               "pool_reads,pool_writes,itemsize_reads,itemsize_writes,"
               "itemcount_reads,itemcount_writes,"
               "alloccount_reads,alloccount_writes,"
               "freehead_reads,freehead_writes,"
               "unique_fields,total_field_accesses,score,confidence,notes\n";

        struct DecodedMemOp
        {
            bool valid = false;
            bool hasMemory = false;
            bool writesMemory = false;
            bool readsMemory = false;
            std::int64_t displacement = 0;
            std::size_t length = 0;
        };

        auto decodeOne =
            [](const unsigned char* p,
               std::size_t remaining) -> DecodedMemOp
            {
                DecodedMemOp result{};

                if (!p || remaining == 0)
                    return result;

                std::size_t i = 0;

                // Prefixes: REX + common legacy prefixes.
                while (i < remaining)
                {
                    const unsigned char b = p[i];

                    if ((b >= 0x40 && b <= 0x4F) ||
                        b == 0x66 ||
                        b == 0x67 ||
                        b == 0xF2 ||
                        b == 0xF3 ||
                        b == 0x2E ||
                        b == 0x36 ||
                        b == 0x3E ||
                        b == 0x26 ||
                        b == 0x64 ||
                        b == 0x65)
                    {
                        ++i;
                        continue;
                    }

                    break;
                }

                if (i >= remaining)
                    return result;

                const unsigned char op1 = p[i++];

                // Obvious single-byte control/data instructions.
                if (op1 == 0x90 ||              // nop
                    op1 == 0xC3 ||              // ret
                    op1 == 0xCC ||              // int3
                    (op1 >= 0x50 && op1 <= 0x5F)) // push/pop reg
                {
                    result.valid = true;
                    result.length = i;
                    return result;
                }

                if (op1 == 0xE8 || op1 == 0xE9)
                {
                    if (i + 4 > remaining)
                        return result;

                    result.valid = true;
                    result.length = i + 4;
                    return result;
                }

                if (op1 == 0xEB ||
                    (op1 >= 0x70 && op1 <= 0x7F))
                {
                    if (i + 1 > remaining)
                        return result;

                    result.valid = true;
                    result.length = i + 1;
                    return result;
                }

                bool twoByte = false;
                unsigned char op2 = 0;

                if (op1 == 0x0F)
                {
                    if (i >= remaining)
                        return result;

                    twoByte = true;
                    op2 = p[i++];

                    if (op2 >= 0x80 && op2 <= 0x8F)
                    {
                        if (i + 4 > remaining)
                            return result;

                        result.valid = true;
                        result.length = i + 4;
                        return result;
                    }
                }

                // Conservative opcode whitelist that uses ModRM.
                bool hasModRM = false;
                bool memWrite = false;
                bool memRead = false;
                std::size_t immBytes = 0;

                if (!twoByte)
                {
                    switch (op1)
                    {
                        case 0x8B: // mov r, r/m
                        case 0x8A:
                        case 0x8D: // lea
                        case 0x03:
                        case 0x0B:
                        case 0x13:
                        case 0x1B:
                        case 0x23:
                        case 0x2B:
                        case 0x33:
                        case 0x3B:
                        case 0x63:
                            hasModRM = true;
                            memRead = true;
                            break;

                        case 0x89: // mov r/m, r
                        case 0x88:
                        case 0x01:
                        case 0x09:
                        case 0x11:
                        case 0x19:
                        case 0x21:
                        case 0x29:
                        case 0x31:
                            hasModRM = true;
                            memWrite = true;
                            memRead = true;
                            break;

                        case 0x80:
                            hasModRM = true;
                            memRead = true;
                            memWrite = true;
                            immBytes = 1;
                            break;

                        case 0x81:
                            hasModRM = true;
                            memRead = true;
                            memWrite = true;
                            immBytes = 4;
                            break;

                        case 0x83:
                            hasModRM = true;
                            memRead = true;
                            memWrite = true;
                            immBytes = 1;
                            break;

                        case 0xC6:
                            hasModRM = true;
                            memWrite = true;
                            immBytes = 1;
                            break;

                        case 0xC7:
                            hasModRM = true;
                            memWrite = true;
                            immBytes = 4;
                            break;

                        case 0xFF:
                        case 0xF7:
                            hasModRM = true;
                            memRead = true;
                            memWrite = true;
                            break;

                        default:
                            break;
                    }
                }
                else
                {
                    switch (op2)
                    {
                        case 0xB6:
                        case 0xB7:
                        case 0xBE:
                        case 0xBF:
                        case 0xAF:
                            hasModRM = true;
                            memRead = true;
                            break;

                        case 0x10:
                        case 0x28:
                        case 0x6F:
                            hasModRM = true;
                            memRead = true;
                            break;

                        case 0x11:
                        case 0x29:
                        case 0x7F:
                            hasModRM = true;
                            memWrite = true;
                            break;

                        default:
                            break;
                    }
                }

                if (!hasModRM)
                    return result;

                if (i >= remaining)
                    return result;

                const unsigned char modrm = p[i++];
                const unsigned int mod = (modrm >> 6) & 0x3;
                const unsigned int rm = modrm & 0x7;

                // Register-only instruction.
                if (mod == 3)
                {
                    if (i + immBytes > remaining)
                        return result;

                    result.valid = true;
                    result.length = i + immBytes;
                    return result;
                }

                bool hasSib = (rm == 4);
                unsigned int sibBase = 0;

                if (hasSib)
                {
                    if (i >= remaining)
                        return result;

                    const unsigned char sib = p[i++];
                    sibBase = sib & 0x7;
                }

                std::size_t dispBytes = 0;

                if (mod == 0)
                {
                    if ((!hasSib && rm == 5) ||
                        (hasSib && sibBase == 5))
                    {
                        dispBytes = 4;
                    }
                }
                else if (mod == 1)
                {
                    dispBytes = 1;
                }
                else if (mod == 2)
                {
                    dispBytes = 4;
                }

                std::int64_t disp = 0;

                if (dispBytes == 1)
                {
                    if (i + 1 > remaining)
                        return result;

                    std::int8_t d8 = 0;
                    std::memcpy(&d8, p + i, 1);
                    disp = d8;
                    i += 1;
                }
                else if (dispBytes == 4)
                {
                    if (i + 4 > remaining)
                        return result;

                    std::int32_t d32 = 0;
                    std::memcpy(&d32, p + i, 4);
                    disp = d32;
                    i += 4;
                }

                if (i + immBytes > remaining)
                    return result;

                i += immBytes;

                result.valid = true;
                result.hasMemory = true;
                result.writesMemory = memWrite;
                result.readsMemory = memRead;
                result.displacement = disp;
                result.length = i;
                return result;
            };

        struct FieldAccessStats
        {
            unsigned int reads = 0;
            unsigned int writes = 0;
        };

        struct DecodedRegCandidate
        {
            std::uintptr_t start = 0;
            std::uintptr_t end = 0;
            std::string section;
            unsigned int decoded = 0;
            unsigned int attempted = 0;
            FieldAccessStats pool;
            FieldAccessStats itemSize;
            FieldAccessStats itemCount;
            FieldAccessStats allocCount;
            FieldAccessStats freeHead;
            unsigned int uniqueFields = 0;
            unsigned int totalAccesses = 0;
            unsigned int score = 0;
            std::vector<unsigned char> bytes;
        };

        std::vector<DecodedRegCandidate> decodedCandidates;

        auto addFieldAccess =
            [&](DecodedRegCandidate& c,
                std::int64_t disp,
                bool read,
                bool write)
            {
                auto update =
                    [&](FieldAccessStats& f)
                    {
                        if (read) ++f.reads;
                        if (write) ++f.writes;
                    };

                if (disp == static_cast<std::int64_t>(offPool))
                    update(c.pool);
                else if (disp == static_cast<std::int64_t>(offItemSize))
                    update(c.itemSize);
                else if (disp == static_cast<std::int64_t>(offItemCount))
                    update(c.itemCount);
                else if (disp == static_cast<std::int64_t>(offItemAllocCount))
                    update(c.allocCount);
                else if (disp == static_cast<std::int64_t>(offFreeHead))
                    update(c.freeHead);
            };

        HMODULE decodedExe =
            GetModuleHandleW(nullptr);

        if (decodedExe)
        {
            const auto moduleBase =
                reinterpret_cast<std::uintptr_t>(decodedExe);

            IMAGE_DOS_HEADER dos{};

            if (CopyFromProcess(
                    reinterpret_cast<const void*>(moduleBase),
                    &dos,
                    sizeof(dos)) &&
                dos.e_magic == IMAGE_DOS_SIGNATURE)
            {
                IMAGE_NT_HEADERS64 nt{};

                const auto ntAddress =
                    moduleBase +
                    static_cast<std::uintptr_t>(dos.e_lfanew);

                if (CopyFromProcess(
                        reinterpret_cast<const void*>(ntAddress),
                        &nt,
                        sizeof(nt)) &&
                    nt.Signature == IMAGE_NT_SIGNATURE)
                {
                    const auto shBase =
                        ntAddress +
                        sizeof(DWORD) +
                        sizeof(IMAGE_FILE_HEADER) +
                        nt.FileHeader.SizeOfOptionalHeader;

                    for (unsigned int si = 0;
                         si < nt.FileHeader.NumberOfSections;
                         ++si)
                    {
                        IMAGE_SECTION_HEADER sh{};

                        if (!CopyFromProcess(
                                reinterpret_cast<const void*>(
                                    shBase +
                                    static_cast<std::uintptr_t>(si) *
                                    sizeof(sh)),
                                &sh,
                                sizeof(sh)))
                        {
                            continue;
                        }

                        if (!(sh.Characteristics & IMAGE_SCN_MEM_EXECUTE) ||
                            !(sh.Characteristics & IMAGE_SCN_MEM_READ))
                        {
                            continue;
                        }

                        char sectionName[9]{};
                        std::memcpy(sectionName, sh.Name, 8);

                        const std::size_t sectionSize =
                            static_cast<std::size_t>(
                                std::max(
                                    sh.Misc.VirtualSize,
                                    sh.SizeOfRawData));

                        if (sectionSize < 0x200 ||
                            sectionSize > 512ull * 1024ull * 1024ull)
                        {
                            continue;
                        }

                        const auto sectionAddress =
                            moduleBase + sh.VirtualAddress;

                        std::vector<unsigned char> bytes(sectionSize);

                        if (!CopyFromProcess(
                                reinterpret_cast<const void*>(sectionAddress),
                                bytes.data(),
                                bytes.size()))
                        {
                            continue;
                        }

                        constexpr std::size_t kWindow = 0x180;
                        constexpr std::size_t kStep = 0x80;

                        for (std::size_t off = 0;
                             off + kWindow <= bytes.size();
                             off += kStep)
                        {
                            DecodedRegCandidate c{};
                            c.start = sectionAddress + off;
                            c.end = c.start + kWindow;
                            c.section = sectionName;
                            c.bytes.assign(
                                bytes.begin() + off,
                                bytes.begin() + off + kWindow);

                            std::size_t ip = 0;

                            while (ip < c.bytes.size())
                            {
                                ++c.attempted;

                                const auto decoded =
                                    decodeOne(
                                        c.bytes.data() + ip,
                                        c.bytes.size() - ip);

                                if (!decoded.valid ||
                                    decoded.length == 0 ||
                                    decoded.length > 15)
                                {
                                    // Advance one byte to resynchronize, but
                                    // this lowers valid_ratio substantially for
                                    // data/pointer tables.
                                    ++ip;
                                    continue;
                                }

                                ++c.decoded;

                                if (decoded.hasMemory)
                                {
                                    addFieldAccess(
                                        c,
                                        decoded.displacement,
                                        decoded.readsMemory,
                                        decoded.writesMemory);
                                }

                                ip += decoded.length;
                            }

                            const double validRatio =
                                c.attempted
                                ? static_cast<double>(c.decoded) /
                                  static_cast<double>(c.attempted)
                                : 0.0;

                            if (validRatio < 0.35)
                                continue;

                            const FieldAccessStats fields[] =
                            {
                                c.pool,
                                c.itemSize,
                                c.itemCount,
                                c.allocCount,
                                c.freeHead
                            };

                            for (const auto& f : fields)
                            {
                                if (f.reads || f.writes)
                                    ++c.uniqueFields;

                                c.totalAccesses +=
                                    f.reads + f.writes;
                            }

                            const bool allocatorSignature =
                                (c.freeHead.reads > 0) &&
                                (c.freeHead.writes > 0) &&
                                (c.allocCount.writes > 0);

                            c.score =
                                c.uniqueFields * 30u +
                                c.totalAccesses * 3u +
                                c.freeHead.reads * 10u +
                                c.freeHead.writes * 35u +
                                c.allocCount.reads * 8u +
                                c.allocCount.writes * 35u +
                                (allocatorSignature ? 100u : 0u);

                            if (c.uniqueFields < 2 ||
                                c.score < 80)
                            {
                                continue;
                            }

                            decodedCandidates.push_back(
                                std::move(c));
                        }
                    }
                }
            }
        }

        std::sort(
            decodedCandidates.begin(),
            decodedCandidates.end(),
            [](const DecodedRegCandidate& a,
               const DecodedRegCandidate& b)
            {
                if (a.score != b.score)
                    return a.score > b.score;

                return a.start < b.start;
            });

        std::vector<DecodedRegCandidate> decodedDeduped;

        for (const auto& c : decodedCandidates)
        {
            bool overlap = false;

            for (const auto& kept : decodedDeduped)
            {
                const auto dist =
                    c.start > kept.start
                    ? c.start - kept.start
                    : kept.start - c.start;

                if (dist < 0x180)
                {
                    overlap = true;
                    break;
                }
            }

            if (!overlap)
            {
                decodedDeduped.push_back(c);

                if (decodedDeduped.size() >=
                    (deep ? 64u : 24u))
                {
                    break;
                }
            }
        }

        unsigned int decodedRank = 1;

        for (const auto& c : decodedDeduped)
        {
            const double validRatio =
                c.attempted
                ? static_cast<double>(c.decoded) /
                  static_cast<double>(c.attempted)
                : 0.0;

            const bool allocatorSignature =
                c.freeHead.reads > 0 &&
                c.freeHead.writes > 0 &&
                c.allocCount.writes > 0;

            const char* confidence =
                allocatorSignature &&
                c.uniqueFields >= 3 &&
                validRatio >= 0.55
                ? "HIGH"
                : c.uniqueFields >= 3
                    ? "MEDIUM"
                    : "LOW";

            decodedRegistration
                << decodedRank
                << ",0x"
                << std::hex
                << std::uppercase
                << c.start
                << ",0x"
                << c.end
                << std::dec
                << ','
                << c.section
                << ','
                << c.decoded
                << ','
                << validRatio
                << ','
                << c.pool.reads
                << ','
                << c.pool.writes
                << ','
                << c.itemSize.reads
                << ','
                << c.itemSize.writes
                << ','
                << c.itemCount.reads
                << ','
                << c.itemCount.writes
                << ','
                << c.allocCount.reads
                << ','
                << c.allocCount.writes
                << ','
                << c.freeHead.reads
                << ','
                << c.freeHead.writes
                << ','
                << c.uniqueFields
                << ','
                << c.totalAccesses
                << ','
                << c.score
                << ','
                << confidence
                << ','
                << (allocatorSignature
                    ? "allocator-like read/write signature: freeHead read+write and itemAllocCount write"
                    : "field-access candidate; needs targeted validation")
                << "\n";

            decodedWindows
                << "[RANK "
                << decodedRank
                << "] start=0x"
                << std::hex
                << std::uppercase
                << c.start
                << " end=0x"
                << c.end
                << std::dec
                << " score="
                << c.score
                << " validRatio="
                << validRatio
                << "\n"
                << "pool R/W="
                << c.pool.reads << '/' << c.pool.writes
                << " itemSize R/W="
                << c.itemSize.reads << '/' << c.itemSize.writes
                << " itemCount R/W="
                << c.itemCount.reads << '/' << c.itemCount.writes
                << " allocCount R/W="
                << c.allocCount.reads << '/' << c.allocCount.writes
                << " freeHead R/W="
                << c.freeHead.reads << '/' << c.freeHead.writes
                << "\nbytes:\n";

            for (std::size_t i = 0;
                 i < c.bytes.size();
                 ++i)
            {
                if ((i % 16) == 0)
                {
                    decodedWindows
                        << "  +0x"
                        << std::hex
                        << std::uppercase
                        << i
                        << ": ";
                }

                decodedWindows
                    << std::hex
                    << std::uppercase
                    << std::setw(2)
                    << std::setfill('0')
                    << static_cast<unsigned int>(c.bytes[i])
                    << ' ';

                if ((i % 16) == 15)
                    decodedWindows << "\n";
            }

            decodedWindows
                << std::dec
                << "\n";

            ++decodedRank;
        }

        if (decodedDeduped.empty())
        {
            decodedRegistration
                << "0,0,0,none,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,NONE,"
                   "no decoded allocator-like XAssetPool field-access window found\n";

            decodedWindows
                << "No decoded allocator-like registration candidates found.\n";
        }

        decodedRegistration.flush();
        decodedWindows.flush();

        // -----------------------------------------------------------------
        // [PROTOTYPE GATE V3]
        // -----------------------------------------------------------------
        bool decodedHighCandidate = false;
        std::uintptr_t decodedBestAddress = 0;
        unsigned int decodedBestScore = 0;

        for (const auto& c : decodedDeduped)
        {
            const double validRatio =
                c.attempted
                ? static_cast<double>(c.decoded) /
                  static_cast<double>(c.attempted)
                : 0.0;

            const bool allocatorSignature =
                c.freeHead.reads > 0 &&
                c.freeHead.writes > 0 &&
                c.allocCount.writes > 0;

            if (c.score > decodedBestScore)
            {
                decodedBestScore = c.score;
                decodedBestAddress = c.start;
            }

            if (allocatorSignature &&
                c.uniqueFields >= 3 &&
                validRatio >= 0.55)
            {
                decodedHighCandidate = true;
                break;
            }
        }

        prototypeGateV3
            << "[FIRST NON-REPLACEMENT CAMO PROTOTYPE - GATE V3]\n"
            << "WeaponCamo allocator="
            << (gateCamoAllocator ? "PASS" : "FAIL")
            << "\n"
            << "Binding allocator="
            << (gateBindingAllocator ? "PASS" : "FAIL")
            << "\n"
            << "Material/texture layout="
            << (gateMaterialLayout ? "PASS" : "FAIL")
            << "\n"
            << "Decoded registration candidates="
            << decodedDeduped.size()
            << "\n"
            << "Decoded HIGH allocator candidate="
            << (decodedHighCandidate ? "YES" : "NO")
            << "\n"
            << "Best decoded candidate=0x"
            << std::hex
            << std::uppercase
            << decodedBestAddress
            << std::dec
            << "\n"
            << "Best decoded score="
            << decodedBestScore
            << "\n\n";

        if (decodedHighCandidate)
        {
            prototypeGateV3
                << "STATUS=REGISTRATION_CANDIDATE_READY_FOR_TARGETED_VALIDATION\n"
                << "The next step is targeted validation of the top decoded candidate, not another broad scanner.\n";
        }
        else
        {
            prototypeGateV3
                << "STATUS=REGISTRATION_PATH_STILL_UNRESOLVED\n";
        }

        prototypeGateV3
            << "\nREADY_FOR_FIRST_NON_REPLACEMENT_PROTOTYPE=NO\n"
            << "This remains NO until the top decoded candidate is validated against live pool bookkeeping.\n";

        prototypeGateV3.flush();

        // -----------------------------------------------------------------
        // [STRICT COHERENT X64 REGISTRATION PASS - V4]
        //
        // V3 still allowed byte-resynchronization. V4 starts only at plausible
        // x64 function prologues, decodes strictly forward (no byte-by-byte
        // resync), requires coherent control flow, rejects pointer-like data,
        // and requires the critical XAssetPool accesses to share one base reg.
        // -----------------------------------------------------------------
        strictRegistration
            << "rank,start,end,section,decoded_instructions,decoded_bytes,"
               "pointer_like_qwords,call_count,branch_count,ret_count,"
               "base_register,unique_fields,total_accesses,"
               "alloccount_reads,alloccount_writes,"
               "freehead_reads,freehead_writes,score,confidence,notes\n";

        struct StrictInsn
        {
            bool valid = false;
            std::size_t length = 0;
            bool hasMemory = false;
            bool readsMemory = false;
            bool writesMemory = false;
            std::int64_t displacement = 0;
            int baseRegister = -1;
            bool call = false;
            bool branch = false;
            bool ret = false;
        };

        auto strictDecode =
            [](const unsigned char* p,
               std::size_t remaining) -> StrictInsn
            {
                StrictInsn out{};

                if (!p || !remaining)
                    return out;

                std::size_t i = 0;
                unsigned char rex = 0;

                while (i < remaining)
                {
                    const unsigned char b = p[i];

                    if (b >= 0x40 && b <= 0x4F)
                    {
                        rex = b;
                        ++i;
                        continue;
                    }

                    if (b == 0x66 || b == 0x67 ||
                        b == 0xF2 || b == 0xF3 ||
                        b == 0x2E || b == 0x36 ||
                        b == 0x3E || b == 0x26 ||
                        b == 0x64 || b == 0x65)
                    {
                        ++i;
                        continue;
                    }

                    break;
                }

                if (i >= remaining)
                    return out;

                const unsigned char op1 = p[i++];

                if (op1 == 0xC3)
                {
                    out.valid = true;
                    out.length = i;
                    out.ret = true;
                    return out;
                }

                if (op1 == 0xC2)
                {
                    if (i + 2 > remaining) return out;
                    out.valid = true;
                    out.length = i + 2;
                    out.ret = true;
                    return out;
                }

                if (op1 == 0xE8)
                {
                    if (i + 4 > remaining) return out;
                    out.valid = true;
                    out.length = i + 4;
                    out.call = true;
                    return out;
                }

                if (op1 == 0xE9)
                {
                    if (i + 4 > remaining) return out;
                    out.valid = true;
                    out.length = i + 4;
                    out.branch = true;
                    return out;
                }

                if (op1 == 0xEB ||
                    (op1 >= 0x70 && op1 <= 0x7F))
                {
                    if (i + 1 > remaining) return out;
                    out.valid = true;
                    out.length = i + 1;
                    out.branch = true;
                    return out;
                }

                if (op1 == 0x90 || op1 == 0xCC ||
                    (op1 >= 0x50 && op1 <= 0x5F))
                {
                    out.valid = true;
                    out.length = i;
                    return out;
                }

                if (op1 >= 0xB8 && op1 <= 0xBF)
                {
                    const std::size_t imm =
                        (rex & 0x08) ? 8u : 4u;

                    if (i + imm > remaining) return out;
                    out.valid = true;
                    out.length = i + imm;
                    return out;
                }

                if (op1 == 0x68)
                {
                    if (i + 4 > remaining) return out;
                    out.valid = true;
                    out.length = i + 4;
                    return out;
                }

                if (op1 == 0x6A)
                {
                    if (i + 1 > remaining) return out;
                    out.valid = true;
                    out.length = i + 1;
                    return out;
                }

                bool twoByte = false;
                unsigned char op2 = 0;

                if (op1 == 0x0F)
                {
                    if (i >= remaining) return out;
                    twoByte = true;
                    op2 = p[i++];

                    if (op2 >= 0x80 && op2 <= 0x8F)
                    {
                        if (i + 4 > remaining) return out;
                        out.valid = true;
                        out.length = i + 4;
                        out.branch = true;
                        return out;
                    }
                }

                bool hasModRM = false;
                bool readMem = false;
                bool writeMem = false;
                std::size_t immBytes = 0;

                if (!twoByte)
                {
                    switch (op1)
                    {
                        case 0x8B: case 0x8A: case 0x8D:
                        case 0x03: case 0x0B: case 0x13: case 0x1B:
                        case 0x23: case 0x2B: case 0x33: case 0x3B:
                        case 0x63: case 0x84: case 0x85: case 0x39:
                            hasModRM = true; readMem = true; break;

                        case 0x89: case 0x88:
                        case 0x01: case 0x09: case 0x11: case 0x19:
                        case 0x21: case 0x29: case 0x31:
                            hasModRM = true; readMem = true; writeMem = true; break;

                        case 0x80:
                            hasModRM = true; readMem = true; writeMem = true; immBytes = 1; break;
                        case 0x81:
                            hasModRM = true; readMem = true; writeMem = true; immBytes = 4; break;
                        case 0x83:
                            hasModRM = true; readMem = true; writeMem = true; immBytes = 1; break;
                        case 0xC6:
                            hasModRM = true; writeMem = true; immBytes = 1; break;
                        case 0xC7:
                            hasModRM = true; writeMem = true; immBytes = 4; break;
                        case 0xFF: case 0xF7:
                            hasModRM = true; readMem = true; writeMem = true; break;
                        default:
                            break;
                    }
                }
                else
                {
                    switch (op2)
                    {
                        case 0xB6: case 0xB7: case 0xBE: case 0xBF:
                        case 0xAF: case 0x10: case 0x28: case 0x6F:
                            hasModRM = true; readMem = true; break;
                        case 0x11: case 0x29: case 0x7F:
                            hasModRM = true; writeMem = true; break;
                        default:
                            break;
                    }
                }

                if (!hasModRM)
                    return out;

                if (i >= remaining)
                    return out;

                const unsigned char modrm = p[i++];
                const unsigned int mod = (modrm >> 6) & 3u;
                const unsigned int rm = modrm & 7u;

                if (mod == 3)
                {
                    if (i + immBytes > remaining) return out;
                    out.valid = true;
                    out.length = i + immBytes;
                    return out;
                }

                int baseReg =
                    static_cast<int>(rm | ((rex & 0x01) ? 8u : 0u));

                bool hasSib = rm == 4;
                unsigned int sibBase = 0;

                if (hasSib)
                {
                    if (i >= remaining) return out;
                    const unsigned char sib = p[i++];
                    sibBase = sib & 7u;
                    baseReg =
                        static_cast<int>(
                            sibBase | ((rex & 0x01) ? 8u : 0u));
                }

                std::size_t dispBytes = 0;

                if (mod == 0)
                {
                    if ((!hasSib && rm == 5) ||
                        (hasSib && sibBase == 5))
                    {
                        dispBytes = 4;
                        baseReg = -1; // RIP-relative / no ordinary base.
                    }
                }
                else if (mod == 1)
                {
                    dispBytes = 1;
                }
                else if (mod == 2)
                {
                    dispBytes = 4;
                }

                std::int64_t disp = 0;

                if (dispBytes == 1)
                {
                    if (i + 1 > remaining) return out;
                    std::int8_t d = 0;
                    std::memcpy(&d, p + i, 1);
                    disp = d;
                    ++i;
                }
                else if (dispBytes == 4)
                {
                    if (i + 4 > remaining) return out;
                    std::int32_t d = 0;
                    std::memcpy(&d, p + i, 4);
                    disp = d;
                    i += 4;
                }

                if (i + immBytes > remaining)
                    return out;

                i += immBytes;

                out.valid = true;
                out.length = i;
                out.hasMemory = true;
                out.readsMemory = readMem;
                out.writesMemory = writeMem;
                out.displacement = disp;
                out.baseRegister = baseReg;
                return out;
            };

        struct StrictBaseStats
        {
            unsigned int poolR = 0, poolW = 0;
            unsigned int sizeR = 0, sizeW = 0;
            unsigned int countR = 0, countW = 0;
            unsigned int allocR = 0, allocW = 0;
            unsigned int freeR = 0, freeW = 0;
        };

        struct StrictCandidate
        {
            std::uintptr_t start = 0;
            std::uintptr_t end = 0;
            std::string section;
            unsigned int instructions = 0;
            unsigned int decodedBytes = 0;
            unsigned int pointerLikeQwords = 0;
            unsigned int calls = 0;
            unsigned int branches = 0;
            unsigned int rets = 0;
            int baseReg = -1;
            StrictBaseStats stats{};
            unsigned int uniqueFields = 0;
            unsigned int totalAccesses = 0;
            unsigned int score = 0;
            std::vector<unsigned char> bytes;
        };

        auto looksLikeFunctionStart =
            [](const unsigned char* p,
               std::size_t n)
            {
                if (!p || n < 6)
                    return false;

                if (p[0] >= 0x40 && p[0] <= 0x4F &&
                    (p[1] == 0x53 || p[1] == 0x55 ||
                     p[1] == 0x56 || p[1] == 0x57))
                    return true;

                if (p[0] == 0x48 &&
                    p[1] == 0x89 &&
                    (p[2] == 0x5C || p[2] == 0x6C ||
                     p[2] == 0x74 || p[2] == 0x7C) &&
                    p[3] == 0x24)
                    return true;

                if (p[0] == 0x48 &&
                    (p[1] == 0x83 || p[1] == 0x81) &&
                    p[2] == 0xEC)
                    return true;

                if (p[0] == 0x4C &&
                    p[1] == 0x8B &&
                    p[2] == 0xDC)
                    return true;

                return false;
            };

        std::vector<StrictCandidate> strictCandidates;

        HMODULE strictExe = GetModuleHandleW(nullptr);

        if (strictExe)
        {
            const auto moduleBase =
                reinterpret_cast<std::uintptr_t>(strictExe);

            IMAGE_DOS_HEADER dos{};

            if (CopyFromProcess(
                    reinterpret_cast<const void*>(moduleBase),
                    &dos,
                    sizeof(dos)) &&
                dos.e_magic == IMAGE_DOS_SIGNATURE)
            {
                IMAGE_NT_HEADERS64 nt{};
                const auto ntAddress =
                    moduleBase +
                    static_cast<std::uintptr_t>(dos.e_lfanew);

                if (CopyFromProcess(
                        reinterpret_cast<const void*>(ntAddress),
                        &nt,
                        sizeof(nt)) &&
                    nt.Signature == IMAGE_NT_SIGNATURE)
                {
                    const auto shBase =
                        ntAddress +
                        sizeof(DWORD) +
                        sizeof(IMAGE_FILE_HEADER) +
                        nt.FileHeader.SizeOfOptionalHeader;

                    for (unsigned int si = 0;
                         si < nt.FileHeader.NumberOfSections;
                         ++si)
                    {
                        IMAGE_SECTION_HEADER sh{};

                        if (!CopyFromProcess(
                                reinterpret_cast<const void*>(
                                    shBase +
                                    static_cast<std::uintptr_t>(si) *
                                    sizeof(sh)),
                                &sh,
                                sizeof(sh)))
                            continue;

                        if (!(sh.Characteristics & IMAGE_SCN_MEM_EXECUTE) ||
                            !(sh.Characteristics & IMAGE_SCN_MEM_READ))
                            continue;

                        char sectionName[9]{};
                        std::memcpy(sectionName, sh.Name, 8);

                        const std::size_t sectionSize =
                            static_cast<std::size_t>(
                                std::max(
                                    sh.Misc.VirtualSize,
                                    sh.SizeOfRawData));

                        if (sectionSize < 0x100 ||
                            sectionSize > 512ull * 1024ull * 1024ull)
                            continue;

                        const auto sectionAddress =
                            moduleBase + sh.VirtualAddress;

                        std::vector<unsigned char> sectionBytes(sectionSize);

                        if (!CopyFromProcess(
                                reinterpret_cast<const void*>(sectionAddress),
                                sectionBytes.data(),
                                sectionBytes.size()))
                            continue;

                        for (std::size_t start = 0;
                             start + 0x40 < sectionBytes.size();
                             ++start)
                        {
                            if (!looksLikeFunctionStart(
                                    sectionBytes.data() + start,
                                    sectionBytes.size() - start))
                                continue;

                            StrictCandidate candidate{};
                            candidate.start = sectionAddress + start;
                            candidate.section = sectionName;

                            StrictBaseStats perBase[16]{};

                            std::size_t ip = start;
                            const std::size_t hardEnd =
                                std::min<std::size_t>(
                                    sectionBytes.size(),
                                    start + 0x300);

                            bool coherent = true;

                            while (ip < hardEnd)
                            {
                                const auto insn =
                                    strictDecode(
                                        sectionBytes.data() + ip,
                                        hardEnd - ip);

                                if (!insn.valid ||
                                    insn.length == 0 ||
                                    insn.length > 15)
                                {
                                    coherent = false;
                                    break;
                                }

                                ++candidate.instructions;
                                candidate.decodedBytes +=
                                    static_cast<unsigned int>(insn.length);

                                if (insn.call) ++candidate.calls;
                                if (insn.branch) ++candidate.branches;
                                if (insn.ret) ++candidate.rets;

                                if (insn.hasMemory &&
                                    insn.baseRegister >= 0 &&
                                    insn.baseRegister < 16)
                                {
                                    auto& b =
                                        perBase[insn.baseRegister];

                                    auto addRW =
                                        [&](unsigned int& r,
                                            unsigned int& w)
                                        {
                                            if (insn.readsMemory) ++r;
                                            if (insn.writesMemory) ++w;
                                        };

                                    if (insn.displacement ==
                                        static_cast<std::int64_t>(offPool))
                                        addRW(b.poolR, b.poolW);
                                    else if (insn.displacement ==
                                        static_cast<std::int64_t>(offItemSize))
                                        addRW(b.sizeR, b.sizeW);
                                    else if (insn.displacement ==
                                        static_cast<std::int64_t>(offItemCount))
                                        addRW(b.countR, b.countW);
                                    else if (insn.displacement ==
                                        static_cast<std::int64_t>(offItemAllocCount))
                                        addRW(b.allocR, b.allocW);
                                    else if (insn.displacement ==
                                        static_cast<std::int64_t>(offFreeHead))
                                        addRW(b.freeR, b.freeW);
                                }

                                ip += insn.length;

                                if (insn.ret)
                                    break;
                            }

                            if (!coherent ||
                                candidate.instructions < 8 ||
                                candidate.rets == 0 ||
                                (candidate.calls + candidate.branches) == 0)
                                continue;

                            candidate.end =
                                sectionAddress + ip;

                            // Reject pointer/address tables: count qwords that
                            // look like canonical user-space pointers.
                            const std::size_t byteCount =
                                std::min<std::size_t>(
                                    ip - start,
                                    0x300);

                            candidate.bytes.assign(
                                sectionBytes.begin() + start,
                                sectionBytes.begin() + start + byteCount);

                            for (std::size_t qoff = 0;
                                 qoff + 8 <= candidate.bytes.size();
                                 qoff += 8)
                            {
                                std::uint64_t q = 0;
                                std::memcpy(
                                    &q,
                                    candidate.bytes.data() + qoff,
                                    sizeof(q));

                                if ((q >= 0x10000ull &&
                                     q <= 0x00007FFFFFFFFFFFull) ||
                                    ((q >> 48) == 0xFFFFull))
                                {
                                    ++candidate.pointerLikeQwords;
                                }
                            }

                            if (!candidate.bytes.empty() &&
                                candidate.pointerLikeQwords * 8u >
                                    candidate.bytes.size() / 2u)
                                continue;

                            int bestBase = -1;
                            unsigned int bestScore = 0;

                            for (int br = 0; br < 16; ++br)
                            {
                                const auto& b = perBase[br];

                                unsigned int unique = 0;
                                unique += (b.poolR || b.poolW) ? 1u : 0u;
                                unique += (b.sizeR || b.sizeW) ? 1u : 0u;
                                unique += (b.countR || b.countW) ? 1u : 0u;
                                unique += (b.allocR || b.allocW) ? 1u : 0u;
                                unique += (b.freeR || b.freeW) ? 1u : 0u;

                                const unsigned int total =
                                    b.poolR + b.poolW +
                                    b.sizeR + b.sizeW +
                                    b.countR + b.countW +
                                    b.allocR + b.allocW +
                                    b.freeR + b.freeW;

                                const bool allocatorSignature =
                                    b.freeR > 0 &&
                                    b.freeW > 0 &&
                                    b.allocW > 0;

                                unsigned int score =
                                    unique * 35u +
                                    total * 4u +
                                    b.freeR * 15u +
                                    b.freeW * 45u +
                                    b.allocW * 45u +
                                    (allocatorSignature ? 150u : 0u) +
                                    candidate.calls * 3u +
                                    candidate.branches * 2u;

                                if (score > bestScore)
                                {
                                    bestScore = score;
                                    bestBase = br;
                                }
                            }

                            if (bestBase < 0)
                                continue;

                            const auto& best =
                                perBase[bestBase];

                            const bool allocatorSignature =
                                best.freeR > 0 &&
                                best.freeW > 0 &&
                                best.allocW > 0;

                            if (!allocatorSignature)
                                continue;

                            candidate.baseReg = bestBase;
                            candidate.stats = best;
                            candidate.score = bestScore;

                            candidate.uniqueFields = 0;
                            candidate.uniqueFields +=
                                (best.poolR || best.poolW) ? 1u : 0u;
                            candidate.uniqueFields +=
                                (best.sizeR || best.sizeW) ? 1u : 0u;
                            candidate.uniqueFields +=
                                (best.countR || best.countW) ? 1u : 0u;
                            candidate.uniqueFields +=
                                (best.allocR || best.allocW) ? 1u : 0u;
                            candidate.uniqueFields +=
                                (best.freeR || best.freeW) ? 1u : 0u;

                            candidate.totalAccesses =
                                best.poolR + best.poolW +
                                best.sizeR + best.sizeW +
                                best.countR + best.countW +
                                best.allocR + best.allocW +
                                best.freeR + best.freeW;

                            strictCandidates.push_back(
                                std::move(candidate));

                            // Skip inside this coherent function.
                            if (ip > start)
                                start = ip - 1;
                        }
                    }
                }
            }
        }

        std::sort(
            strictCandidates.begin(),
            strictCandidates.end(),
            [](const StrictCandidate& a,
               const StrictCandidate& b)
            {
                if (a.score != b.score)
                    return a.score > b.score;
                return a.start < b.start;
            });

        const std::size_t strictLimit =
            std::min<std::size_t>(
                strictCandidates.size(),
                deep ? 32u : 12u);

        bool strictHigh = false;
        std::uintptr_t strictBest = 0;
        unsigned int strictBestScore = 0;

        for (std::size_t i = 0;
             i < strictLimit;
             ++i)
        {
            const auto& c = strictCandidates[i];

            const bool high =
                c.uniqueFields >= 3 &&
                c.stats.freeR > 0 &&
                c.stats.freeW > 0 &&
                c.stats.allocW > 0 &&
                c.rets > 0 &&
                (c.calls + c.branches) > 0;

            if (high && !strictHigh)
            {
                strictHigh = true;
                strictBest = c.start;
                strictBestScore = c.score;
            }

            strictRegistration
                << (i + 1)
                << ",0x"
                << std::hex << std::uppercase
                << c.start
                << ",0x"
                << c.end
                << std::dec
                << ','
                << c.section
                << ','
                << c.instructions
                << ','
                << c.decodedBytes
                << ','
                << c.pointerLikeQwords
                << ','
                << c.calls
                << ','
                << c.branches
                << ','
                << c.rets
                << ','
                << c.baseReg
                << ','
                << c.uniqueFields
                << ','
                << c.totalAccesses
                << ','
                << c.stats.allocR
                << ','
                << c.stats.allocW
                << ','
                << c.stats.freeR
                << ','
                << c.stats.freeW
                << ','
                << c.score
                << ','
                << (high ? "HIGH" : "MEDIUM")
                << ','
                << "strict coherent decode; critical pool fields share one base register"
                << "\n";

            strictWindows
                << "[RANK " << (i + 1)
                << "] start=0x"
                << std::hex << std::uppercase
                << c.start
                << " end=0x" << c.end
                << std::dec
                << " score=" << c.score
                << " baseReg=" << c.baseReg
                << " calls=" << c.calls
                << " branches=" << c.branches
                << " rets=" << c.rets
                << "\n";

            for (std::size_t bi = 0;
                 bi < c.bytes.size();
                 ++bi)
            {
                if ((bi % 16) == 0)
                    strictWindows
                        << "  +0x"
                        << std::hex << std::uppercase
                        << bi << ": ";

                strictWindows
                    << std::setw(2)
                    << std::setfill('0')
                    << std::hex << std::uppercase
                    << static_cast<unsigned int>(c.bytes[bi])
                    << ' ';

                if ((bi % 16) == 15)
                    strictWindows << "\n";
            }

            strictWindows << std::dec << "\n\n";
        }

        if (!strictLimit)
        {
            strictRegistration
                << "0,0,0,none,0,0,0,0,0,0,0,-1,0,0,0,0,0,0,0,NONE,"
                   "no coherent allocator-signature function found\n";
            strictWindows
                << "No coherent allocator-signature function found.\n";
        }

        strictRegistration.flush();
        strictWindows.flush();

        prototypeGateV4
            << "[FIRST NON-REPLACEMENT CAMO PROTOTYPE - GATE V4]\n"
            << "WeaponCamo allocator="
            << (gateCamoAllocator ? "PASS" : "FAIL") << "\n"
            << "Binding allocator="
            << (gateBindingAllocator ? "PASS" : "FAIL") << "\n"
            << "Material/texture layout="
            << (gateMaterialLayout ? "PASS" : "FAIL") << "\n"
            << "Strict coherent registration candidate="
            << (strictHigh ? "YES" : "NO") << "\n"
            << "Best strict candidate=0x"
            << std::hex << std::uppercase
            << strictBest << std::dec << "\n"
            << "Best strict score="
            << strictBestScore << "\n\n";

        if (strictHigh)
        {
            prototypeGateV4
                << "STATUS=STRICT_REGISTRATION_CANDIDATE_READY_FOR_TARGETED_VALIDATION\n"
                << "The candidate passed coherent-code, control-flow, common-base, freeHead R/W, and itemAllocCount-W checks.\n";
        }
        else
        {
            prototypeGateV4
                << "STATUS=REGISTRATION_PATH_STILL_UNRESOLVED\n";
        }

        prototypeGateV4
            << "\nREADY_FOR_FIRST_NON_REPLACEMENT_PROTOTYPE=NO\n"
            << "Prototype remains blocked until the top strict candidate is validated against live XAssetPool bookkeeping.\n";

        prototypeGateV4.flush();

        // -----------------------------------------------------------------
        // [FOCUSED ADDITIVE REGISTRATION STATE]
        // -----------------------------------------------------------------
        additiveRegistration
            << "label,pool,next_index,next_address,item_size,item_count,"
               "item_alloc_count,free_head,free_head_matches_next,confidence,notes\n";

        {
            std::lock_guard<std::mutex> lock(
                g_allocatorResearchSnapshotMutex);

            g_allocatorResearchSnapshot.weaponCamoPool =
                reinterpret_cast<std::uintptr_t>(camoPool);

            g_allocatorResearchSnapshot.weaponCamoBindingPool =
                reinterpret_cast<std::uintptr_t>(bindingPool);

            g_allocatorResearchSnapshot.weaponCamoFreeHead =
                reinterpret_cast<std::uintptr_t>(camoPool->freeHead);

            g_allocatorResearchSnapshot.weaponCamoItemAllocCount =
                camoAllocated;

            g_allocatorResearchSnapshot.weaponCamoBindingFreeHead =
                reinterpret_cast<std::uintptr_t>(bindingPool->freeHead);

            g_allocatorResearchSnapshot.weaponCamoBindingItemAllocCount =
                bindingAllocated;
        }

        const auto nextCamoAddress =
            camoBase +
            static_cast<std::uintptr_t>(camoAllocated) *
            camoPool->itemSize;

        const auto nextBindingAddress =
            bindingBase +
            static_cast<std::uintptr_t>(bindingAllocated) *
            bindingPool->itemSize;

        const bool camoFreeMatches =
            reinterpret_cast<std::uintptr_t>(camoPool->freeHead) ==
            nextCamoAddress;

        const bool bindingFreeMatches =
            reinterpret_cast<std::uintptr_t>(bindingPool->freeHead) ==
            nextBindingAddress;

        additiveRegistration
            << "ADDITIVE_SLOT,WEAPONCAMO,"
            << camoAllocated
            << ",0x"
            << std::hex << std::uppercase
            << nextCamoAddress
            << std::dec
            << ',' << camoPool->itemSize
            << ',' << camoCapacity
            << ',' << camoAllocated
            << ",0x"
            << std::hex << std::uppercase
            << reinterpret_cast<std::uintptr_t>(camoPool->freeHead)
            << std::dec
            << ',' << (camoFreeMatches ? 1 : 0)
            << ',' << (camoFreeMatches ? "HIGH" : "MEDIUM")
            << ",expected engine path: pop freeHead, initialize slot, increment alloc count, register/enroll asset\n";

        additiveRegistration
            << "ADDITIVE_SLOT,WEAPONCAMOBINDING,"
            << bindingAllocated
            << ",0x"
            << std::hex << std::uppercase
            << nextBindingAddress
            << std::dec
            << ',' << bindingPool->itemSize
            << ',' << bindingCapacity
            << ',' << bindingAllocated
            << ",0x"
            << std::hex << std::uppercase
            << reinterpret_cast<std::uintptr_t>(bindingPool->freeHead)
            << std::dec
            << ',' << (bindingFreeMatches ? 1 : 0)
            << ',' << (bindingFreeMatches ? "HIGH" : "MEDIUM")
            << ",expected engine path: pop binding freeHead, initialize owner/binding, increment alloc count\n";

        additiveRegistration.flush();

        focusedSummary
            << "[FOCUSED SINGLE-CAMO PASS]\n"
            << "mode=" << (deep ? "DEEP" : "FAST") << "\n"
            << "material_records_walked=" << focusedMaterialCount << "\n"
            << "material_image_endpoints=" << focusedImageHits << "\n"
            << "weaponCamo_next_index=" << camoAllocated << "\n"
            << "weaponCamo_freeHead_matches_next=" << (camoFreeMatches ? 1 : 0) << "\n"
            << "binding_next_index=" << bindingAllocated << "\n"
            << "binding_freeHead_matches_next=" << (bindingFreeMatches ? 1 : 0) << "\n\n"
            << "ONE normal /scan camo run on ONE MP camo is enough for this build.\n"
            << "Send _55, _73, _92 plus the rest of the camo_scan group.\n";

        focusedSummary.flush();

        // -----------------------------------------------------------------
        // [RUNTIME CAMO ARRAY / COUNT CANDIDATES]
        //
        // We do not know T9's equivalent of MW2019 ncsCamos[] yet. Seed this
        // file with every pointer/count-bearing location we DO know so later
        // differential scans can identify a nearby runtime table or count.
        // -----------------------------------------------------------------
        runtimeCandidates
            << "label,address,value,notes\n";

        runtimeCandidates
            << "weaponCamo.poolBase,0x"
            << std::hex
            << std::uppercase
            << reinterpret_cast<std::uintptr_t>(
                   camoPool->pool.unk)
            << ",0x"
            << reinterpret_cast<std::uintptr_t>(
                   camoPool->pool.unk)
            << std::dec
            << ",asset pool base\n";

        runtimeCandidates
            << "weaponCamo.itemCount.field,0x"
            << std::hex
            << std::uppercase
            << reinterpret_cast<std::uintptr_t>(
                   &camoPool->itemCount)
            << std::dec
            << ','
            << camoPool->itemCount
            << ",asset capacity; NOT assumed to be runtime menu count\n";

        runtimeCandidates
            << "weaponCamo.itemAllocCount.field,0x"
            << std::hex
            << std::uppercase
            << reinterpret_cast<std::uintptr_t>(
                   &camoPool->itemAllocCount)
            << std::dec
            << ','
            << camoPool->itemAllocCount
            << ",allocated asset count; compare across menu states\n";

        runtimeCandidates
            << "weaponCamo.freeHead.field,0x"
            << std::hex
            << std::uppercase
            << reinterpret_cast<std::uintptr_t>(
                   &camoPool->freeHead)
            << ",0x"
            << reinterpret_cast<std::uintptr_t>(
                   camoPool->freeHead)
            << std::dec
            << ",asset allocator free-list head\n";

        runtimeCandidates
            << "weaponCamoBinding.itemAllocCount.field,0x"
            << std::hex
            << std::uppercase
            << reinterpret_cast<std::uintptr_t>(
                   &bindingPool->itemAllocCount)
            << std::dec
            << ','
            << bindingPool->itemAllocCount
            << ",binding allocation count; compare with camo menu transitions\n";

        if (imagePool)
        {
            runtimeCandidates
                << "image.itemAllocCount.field,0x"
                << std::hex
                << std::uppercase
                << reinterpret_cast<std::uintptr_t>(
                       &imagePool->itemAllocCount)
                << std::dec
                << ','
                << imagePool->itemAllocCount
                << ",image allocation count; useful while loading custom image research\n";
        }


        // -----------------------------------------------------------------
        // [ACTUAL RUNTIME CAMO ARRAY / COUNT DISCOVERY]
        //
        // MW2019 has a module-global ncsCamos[] array and ncsCamoCount.
        // Search T9's writable PE sections for the same shape:
        //   * contiguous qwords that point into currently allocated Camo records
        //   * integer values close to the currently allocated/runtime count
        //
        // Read-only: no hooks, no writes, no speculative calls.
        // -----------------------------------------------------------------
        runtimeArrays
            << "label,section,address,run_length,"
               "first_camo_index,last_camo_index,"
               "distinct_indices,pointer_stride,confidence\n";

        runtimeCounts
            << "label,section,address,value,width_bits,"
               "distance_to_nearest_array,confidence\n";

        HMODULE exeModule =
            GetModuleHandleW(nullptr);

        std::vector<std::uintptr_t> discoveredArrays;

        if (exeModule)
        {
            const auto moduleBase =
                reinterpret_cast<std::uintptr_t>(
                    exeModule);

            IMAGE_DOS_HEADER dos{};

            if (CopyFromProcess(
                    reinterpret_cast<const void*>(
                        moduleBase),
                    &dos,
                    sizeof(dos)) &&
                dos.e_magic == IMAGE_DOS_SIGNATURE)
            {
                IMAGE_NT_HEADERS64 nt{};

                const auto ntAddress =
                    moduleBase +
                    static_cast<std::uintptr_t>(
                        dos.e_lfanew);

                if (CopyFromProcess(
                        reinterpret_cast<const void*>(
                            ntAddress),
                        &nt,
                        sizeof(nt)) &&
                    nt.Signature == IMAGE_NT_SIGNATURE)
                {
                    const auto sectionBase =
                        ntAddress +
                        sizeof(DWORD) +
                        sizeof(IMAGE_FILE_HEADER) +
                        nt.FileHeader.SizeOfOptionalHeader;

                    const auto camoAllocatedBegin =
                        camoBase;

                    const auto camoAllocatedEnd =
                        camoBase +
                        static_cast<std::uintptr_t>(
                            camoAllocated) *
                        camoPool->itemSize;

                    auto camoIndexForPtr =
                        [&](std::uint64_t value,
                            unsigned int& indexOut)
                        {
                            if (value <
                                    camoAllocatedBegin ||
                                value >=
                                    camoAllocatedEnd ||
                                camoPool->itemSize == 0)
                            {
                                return false;
                            }

                            const auto delta =
                                static_cast<std::uintptr_t>(
                                    value) -
                                camoAllocatedBegin;

                            if (delta %
                                    camoPool->itemSize !=
                                0)
                            {
                                return false;
                            }

                            const auto index =
                                delta /
                                camoPool->itemSize;

                            if (index >= camoAllocated)
                                return false;

                            indexOut =
                                static_cast<unsigned int>(
                                    index);

                            return true;
                        };

                    for (unsigned int si = 0;
                         si < nt.FileHeader.NumberOfSections;
                         ++si)
                    {
                        IMAGE_SECTION_HEADER sh{};

                        const auto shAddress =
                            sectionBase +
                            static_cast<std::uintptr_t>(
                                si) *
                            sizeof(sh);

                        if (!CopyFromProcess(
                                reinterpret_cast<const void*>(
                                    shAddress),
                                &sh,
                                sizeof(sh)))
                        {
                            continue;
                        }

                        // Runtime pointer arrays/counts should be in readable,
                        // writable data, not executable text.
                        if (!(sh.Characteristics &
                              IMAGE_SCN_MEM_READ) ||
                            !(sh.Characteristics &
                              IMAGE_SCN_MEM_WRITE) ||
                            (sh.Characteristics &
                             IMAGE_SCN_MEM_EXECUTE))
                        {
                            continue;
                        }

                        char sectionName[9]{};
                        std::memcpy(
                            sectionName,
                            sh.Name,
                            8);

                        const std::size_t sectionSize =
                            static_cast<std::size_t>(
                                std::max(
                                    sh.Misc.VirtualSize,
                                    sh.SizeOfRawData));

                        if (sectionSize == 0 ||
                            sectionSize >
                                512ull * 1024ull * 1024ull)
                        {
                            continue;
                        }

                        const auto sectionAddress =
                            moduleBase +
                            sh.VirtualAddress;

                        std::vector<unsigned char> bytes(
                            sectionSize);

                        if (!CopyFromProcess(
                                reinterpret_cast<const void*>(
                                    sectionAddress),
                                bytes.data(),
                                bytes.size()))
                        {
                            continue;
                        }

                        // Find contiguous runs of aligned Camo* pointers.
                        std::size_t offset = 0;

                        while (offset + 8 <=
                               bytes.size())
                        {
                            std::uint64_t value = 0;

                            std::memcpy(
                                &value,
                                bytes.data() + offset,
                                sizeof(value));

                            unsigned int firstIndex = 0;

                            if (!camoIndexForPtr(
                                    value,
                                    firstIndex))
                            {
                                offset += 8;
                                continue;
                            }

                            const std::size_t runStart =
                                offset;

                            std::size_t runOffset =
                                offset;

                            unsigned int lastIndex =
                                firstIndex;

                            std::vector<unsigned int>
                                uniqueIndices;

                            uniqueIndices.push_back(
                                firstIndex);

                            while (runOffset + 8 <=
                                   bytes.size())
                            {
                                std::uint64_t p = 0;

                                std::memcpy(
                                    &p,
                                    bytes.data() +
                                        runOffset,
                                    sizeof(p));

                                unsigned int index = 0;

                                if (!camoIndexForPtr(
                                        p,
                                        index))
                                {
                                    break;
                                }

                                lastIndex = index;

                                if (std::find(
                                        uniqueIndices.begin(),
                                        uniqueIndices.end(),
                                        index) ==
                                    uniqueIndices.end())
                                {
                                    uniqueIndices.push_back(
                                        index);
                                }

                                runOffset += 8;
                            }

                            const std::size_t runLength =
                                (runOffset - runStart) / 8;

                            // Four consecutive Camo* entries is enough to log;
                            // longer runs get stronger confidence.
                            if (runLength >= 4)
                            {
                                const auto address =
                                    sectionAddress +
                                    runStart;

                                discoveredArrays.push_back(
                                    address);

                                const char* confidence =
                                    runLength >= 16
                                    ? "HIGH"
                                    : runLength >= 8
                                        ? "MEDIUM"
                                        : "LOW";

                                runtimeArrays
                                    << "RUNTIME_CAMO_ARRAY,"
                                    << sectionName
                                    << ",0x"
                                    << std::hex
                                    << std::uppercase
                                    << address
                                    << std::dec
                                    << ','
                                    << runLength
                                    << ','
                                    << firstIndex
                                    << ','
                                    << lastIndex
                                    << ','
                                    << uniqueIndices.size()
                                    << ",8,"
                                    << confidence
                                    << "\n";
                            }

                            offset =
                                runOffset > offset
                                ? runOffset
                                : offset + 8;
                        }

                        // Find 32-bit and 8-bit values around the observed
                        // allocated count. A real runtime list may be 58, 57,
                        // or one-off depending on a none/default sentinel.
                        const int expected =
                            static_cast<int>(
                                camoAllocated);

                        for (std::size_t off = 0;
                             off + 4 <= bytes.size();
                             off += 4)
                        {
                            std::uint32_t value32 = 0;

                            std::memcpy(
                                &value32,
                                bytes.data() + off,
                                sizeof(value32));

                            if (value32 <
                                    static_cast<unsigned int>(
                                        std::max(0,
                                            expected - 3)) ||
                                value32 >
                                    static_cast<unsigned int>(
                                        expected + 3))
                            {
                                continue;
                            }

                            const auto address =
                                sectionAddress +
                                off;

                            std::uint64_t nearestDistance =
                                UINT64_MAX;

                            for (const auto arrayAddress :
                                 discoveredArrays)
                            {
                                const std::uint64_t distance =
                                    address >
                                            arrayAddress
                                    ? address -
                                        arrayAddress
                                    : arrayAddress -
                                        address;

                                nearestDistance =
                                    std::min(
                                        nearestDistance,
                                        distance);
                            }

                            const char* confidence =
                                nearestDistance <= 0x100
                                ? "HIGH"
                                : nearestDistance <= 0x1000
                                    ? "MEDIUM"
                                    : "LOW";

                            runtimeCounts
                                << "RUNTIME_CAMO_COUNT32,"
                                << sectionName
                                << ",0x"
                                << std::hex
                                << std::uppercase
                                << address
                                << std::dec
                                << ','
                                << value32
                                << ",32,"
                                << (nearestDistance ==
                                        UINT64_MAX
                                    ? -1ll
                                    : static_cast<long long>(
                                        nearestDistance))
                                << ','
                                << confidence
                                << "\n";
                        }

                        for (std::size_t off = 0;
                             off < bytes.size();
                             ++off)
                        {
                            const unsigned int value8 =
                                bytes[off];

                            if (value8 <
                                    static_cast<unsigned int>(
                                        std::max(0,
                                            expected - 2)) ||
                                value8 >
                                    static_cast<unsigned int>(
                                        std::min(
                                            255,
                                            expected + 2)))
                            {
                                continue;
                            }

                            const auto address =
                                sectionAddress +
                                off;

                            std::uint64_t nearestDistance =
                                UINT64_MAX;

                            for (const auto arrayAddress :
                                 discoveredArrays)
                            {
                                const std::uint64_t distance =
                                    address >
                                            arrayAddress
                                    ? address -
                                        arrayAddress
                                    : arrayAddress -
                                        address;

                                nearestDistance =
                                    std::min(
                                        nearestDistance,
                                        distance);
                            }

                            if (nearestDistance > 0x200)
                                continue;

                            runtimeCounts
                                << "RUNTIME_CAMO_COUNT8,"
                                << sectionName
                                << ",0x"
                                << std::hex
                                << std::uppercase
                                << address
                                << std::dec
                                << ','
                                << value8
                                << ",8,"
                                << static_cast<long long>(
                                    nearestDistance)
                                << ",MEDIUM\n";
                        }
                    }
                }
            }
        }

        if (discoveredArrays.empty())
        {
            runtimeArrays
                << "RUNTIME_CAMO_ARRAY_NONE_FOUND,"
                   "module_writable_sections,0,0,-1,-1,0,8,NONE\n";
        }


        // -----------------------------------------------------------------
        // [EXECUTABLE XREF DISCOVERY]
        //
        // Search executable sections for RIP-relative references to known
        // features/camo/image pool globals and count fields. This is intentionally a
        // conservative decoder for the common x64 RIP+disp32 form:
        //   <opcode bytes> disp32  => target = next_instruction + disp32
        //
        // It does NOT execute candidate code and does NOT patch anything.
        // -----------------------------------------------------------------
        execXrefs
            << "label,section,instruction_address,target_address,"
               "target_label,disp_offset,instruction_len,bytes,confidence\n";

        struct KnownTarget
        {
            std::uintptr_t address = 0;
            const char* label = nullptr;
        };

        std::vector<KnownTarget> knownTargets;

        knownTargets.push_back({
            reinterpret_cast<std::uintptr_t>(&camoPool->itemCount),
            "WEAPONCAMO_ITEMCOUNT_FIELD"
        });

        knownTargets.push_back({
            reinterpret_cast<std::uintptr_t>(&camoPool->itemAllocCount),
            "WEAPONCAMO_ITEMALLOCCOUNT_FIELD"
        });

        knownTargets.push_back({
            reinterpret_cast<std::uintptr_t>(&camoPool->freeHead),
            "WEAPONCAMO_FREEHEAD_FIELD"
        });

        knownTargets.push_back({
            reinterpret_cast<std::uintptr_t>(&bindingPool->itemCount),
            "CAMOBINDING_ITEMCOUNT_FIELD"
        });

        knownTargets.push_back({
            reinterpret_cast<std::uintptr_t>(&bindingPool->itemAllocCount),
            "CAMOBINDING_ITEMALLOCCOUNT_FIELD"
        });

        if (imagePool)
        {
            knownTargets.push_back({
                reinterpret_cast<std::uintptr_t>(&imagePool->itemCount),
                "IMAGE_ITEMCOUNT_FIELD"
            });

            knownTargets.push_back({
                reinterpret_cast<std::uintptr_t>(&imagePool->itemAllocCount),
                "IMAGE_ITEMALLOCCOUNT_FIELD"
            });

            knownTargets.push_back({
                reinterpret_cast<std::uintptr_t>(&imagePool->freeHead),
                "IMAGE_FREEHEAD_FIELD"
            });
        }

        // Pool bases themselves are useful xref anchors too.
        knownTargets.push_back({
            camoBase,
            "WEAPONCAMO_POOL_BASE"
        });

        knownTargets.push_back({
            bindingBase,
            "CAMOBINDING_POOL_BASE"
        });

        if (imagePool && imagePool->pool.unk)
        {
            knownTargets.push_back({
                reinterpret_cast<std::uintptr_t>(imagePool->pool.unk),
                "IMAGE_POOL_BASE"
            });
        }

        struct XrefHit
        {
            std::uintptr_t instruction = 0;
            std::uintptr_t target = 0;
            std::string targetLabel;
            std::string section;
        };

        std::vector<XrefHit> xrefHits;

        HMODULE exeForXref =
            GetModuleHandleW(nullptr);

        if (exeForXref)
        {
            const auto moduleBase =
                reinterpret_cast<std::uintptr_t>(
                    exeForXref);

            IMAGE_DOS_HEADER dos{};

            if (CopyFromProcess(
                    reinterpret_cast<const void*>(
                        moduleBase),
                    &dos,
                    sizeof(dos)) &&
                dos.e_magic == IMAGE_DOS_SIGNATURE)
            {
                IMAGE_NT_HEADERS64 nt{};

                const auto ntAddress =
                    moduleBase +
                    static_cast<std::uintptr_t>(
                        dos.e_lfanew);

                if (CopyFromProcess(
                        reinterpret_cast<const void*>(
                            ntAddress),
                        &nt,
                        sizeof(nt)) &&
                    nt.Signature == IMAGE_NT_SIGNATURE)
                {
                    const auto sectionHeaders =
                        ntAddress +
                        sizeof(DWORD) +
                        sizeof(IMAGE_FILE_HEADER) +
                        nt.FileHeader.SizeOfOptionalHeader;

                    for (unsigned int si = 0;
                         si < nt.FileHeader.NumberOfSections;
                         ++si)
                    {
                        IMAGE_SECTION_HEADER sh{};

                        if (!CopyFromProcess(
                                reinterpret_cast<const void*>(
                                    sectionHeaders +
                                    static_cast<std::uintptr_t>(si) *
                                    sizeof(sh)),
                                &sh,
                                sizeof(sh)))
                        {
                            continue;
                        }

                        if (!(sh.Characteristics &
                              IMAGE_SCN_MEM_EXECUTE) ||
                            !(sh.Characteristics &
                              IMAGE_SCN_MEM_READ))
                        {
                            continue;
                        }

                        char sectionName[9]{};
                        std::memcpy(
                            sectionName,
                            sh.Name,
                            8);

                        const std::size_t sectionSize =
                            static_cast<std::size_t>(
                                std::max(
                                    sh.Misc.VirtualSize,
                                    sh.SizeOfRawData));

                        if (sectionSize < 8 ||
                            sectionSize >
                                512ull * 1024ull * 1024ull)
                        {
                            continue;
                        }

                        const auto sectionAddress =
                            moduleBase +
                            sh.VirtualAddress;

                        std::vector<unsigned char> bytes(
                            sectionSize);

                        if (!CopyFromProcess(
                                reinterpret_cast<const void*>(
                                    sectionAddress),
                                bytes.data(),
                                bytes.size()))
                        {
                            continue;
                        }

                        // Scan plausible instruction lengths 5..10 and each
                        // plausible disp32 offset 1..6. This catches LEA/MOV/CMP
                        // RIP-relative references without needing a disassembler.
                        for (std::size_t off = 0;
                             off + 10 <= bytes.size();
                             ++off)
                        {
                            for (unsigned int instLen = 5;
                                 instLen <= 10;
                                 ++instLen)
                            {
                                for (unsigned int dispOff = 1;
                                     dispOff + 4 <= instLen;
                                     ++dispOff)
                                {
                                    std::int32_t disp = 0;

                                    std::memcpy(
                                        &disp,
                                        bytes.data() +
                                            off +
                                            dispOff,
                                        sizeof(disp));

                                    const auto nextIp =
                                        sectionAddress +
                                        off +
                                        instLen;

                                    const auto target =
                                        static_cast<std::uintptr_t>(
                                            static_cast<std::intptr_t>(
                                                nextIp) +
                                            disp);

                                    for (const auto& known :
                                         knownTargets)
                                    {
                                        if (!known.address ||
                                            target != known.address)
                                        {
                                            continue;
                                        }

                                        std::ostringstream byteText;

                                        for (unsigned int bi = 0;
                                             bi < instLen;
                                             ++bi)
                                        {
                                            if (bi)
                                                byteText << ' ';

                                            byteText
                                                << std::hex
                                                << std::uppercase
                                                << std::setw(2)
                                                << std::setfill('0')
                                                << static_cast<unsigned int>(
                                                       bytes[off + bi]);
                                        }

                                        execXrefs
                                            << "CAMO_EXEC_XREF,"
                                            << sectionName
                                            << ",0x"
                                            << std::hex
                                            << std::uppercase
                                            << (sectionAddress + off)
                                            << ",0x"
                                            << target
                                            << std::dec
                                            << ','
                                            << known.label
                                            << ','
                                            << dispOff
                                            << ','
                                            << instLen
                                            << ",\""
                                            << byteText.str()
                                            << "\",MEDIUM\n";

                                        xrefHits.push_back({
                                            sectionAddress + off,
                                            target,
                                            known.label,
                                            sectionName
                                        });
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        if (xrefHits.empty())
        {
            execXrefs
                << "CAMO_EXEC_XREF_NONE,none,0,0,none,0,0,\"\",NONE\n";
        }

        // -----------------------------------------------------------------
        // [HEAP / PRIVATE WRITABLE RUNTIME ARRAY DISCOVERY]
        //
        // Look for committed writable regions containing contiguous aligned
        // pointers into allocated WeaponCamo records. Bound the work:
        //   - private/mapped writable only
        //   - skip guard/noaccess
        //   - max 64 MiB per region
        //   - max 512 MiB total scanned
        //
        // This targets T9 runtime lists that are allocated outside the EXE.
        // -----------------------------------------------------------------
        heapArrays
            << "label,region_base,region_size,array_address,run_length,"
               "first_camo_index,last_camo_index,distinct_indices,"
               "region_type,confidence\n";

        indexArrays
            << "label,region_base,array_address,element_width,run_length,"
               "min_value,max_value,distinct_values,pattern,confidence\n";

        auto ptrToCamoIndex =
            [&](std::uint64_t value,
                unsigned int& indexOut)
            {
                if (value < camoBase ||
                    value >= camoBase +
                        static_cast<std::uintptr_t>(
                            camoAllocated) *
                        camoPool->itemSize ||
                    camoPool->itemSize == 0)
                {
                    return false;
                }

                const auto delta =
                    static_cast<std::uintptr_t>(value) -
                    camoBase;

                if (delta % camoPool->itemSize)
                    return false;

                const auto idx =
                    delta / camoPool->itemSize;

                if (idx >= camoAllocated)
                    return false;

                indexOut =
                    static_cast<unsigned int>(idx);

                return true;
            };

        SYSTEM_INFO sysInfo{};
        GetSystemInfo(&sysInfo);

        std::uintptr_t cursor =
            reinterpret_cast<std::uintptr_t>(
                sysInfo.lpMinimumApplicationAddress);

        const std::uintptr_t maxAddress =
            reinterpret_cast<std::uintptr_t>(
                sysInfo.lpMaximumApplicationAddress);

        std::uint64_t totalHeapBytesScanned = 0;
        const std::uint64_t kMaxTotalHeapScan =
            deep
            ? 512ull * 1024ull * 1024ull
            : 48ull * 1024ull * 1024ull;

        const std::uint64_t kMaxRegionScan =
            deep
            ? 64ull * 1024ull * 1024ull
            : 8ull * 1024ull * 1024ull;

        unsigned int pointerArrayHits = 0;
        unsigned int indexArrayHits = 0;

        while (cursor < maxAddress &&
               totalHeapBytesScanned <
                   kMaxTotalHeapScan)
        {
            MEMORY_BASIC_INFORMATION mbi{};

            if (!VirtualQuery(
                    reinterpret_cast<LPCVOID>(cursor),
                    &mbi,
                    sizeof(mbi)))
            {
                break;
            }

            const auto regionBase =
                reinterpret_cast<std::uintptr_t>(
                    mbi.BaseAddress);

            const auto regionSize =
                static_cast<std::uint64_t>(
                    mbi.RegionSize);

            const bool committed =
                mbi.State == MEM_COMMIT;

            const bool readableWritable =
                !(mbi.Protect &
                  (PAGE_NOACCESS |
                   PAGE_GUARD)) &&
                (mbi.Protect &
                 (PAGE_READWRITE |
                  PAGE_WRITECOPY |
                  PAGE_EXECUTE_READWRITE |
                  PAGE_EXECUTE_WRITECOPY));

            const bool candidateType =
                mbi.Type == MEM_PRIVATE ||
                mbi.Type == MEM_MAPPED;

            // Avoid scanning our known huge asset-pool backing ranges as
            // "runtime arrays"; those are already dumped separately.
            const bool overlapsKnownPool =
                (regionBase <= camoBase &&
                 regionBase + regionSize > camoBase) ||
                (regionBase <= bindingBase &&
                 regionBase + regionSize > bindingBase) ||
                (imagePool &&
                 imagePool->pool.unk &&
                 regionBase <=
                    reinterpret_cast<std::uintptr_t>(
                        imagePool->pool.unk) &&
                 regionBase + regionSize >
                    reinterpret_cast<std::uintptr_t>(
                        imagePool->pool.unk));

            if (committed &&
                readableWritable &&
                candidateType &&
                !overlapsKnownPool &&
                regionSize >= 0x100 &&
                regionSize <= kMaxRegionScan)
            {
                const std::size_t scanSize =
                    static_cast<std::size_t>(
                        regionSize);

                std::vector<unsigned char> bytes(
                    scanSize);

                if (CopyFromProcess(
                        reinterpret_cast<const void*>(
                            regionBase),
                        bytes.data(),
                        bytes.size()))
                {
                    totalHeapBytesScanned +=
                        bytes.size();

                    // ---- Pointer-array scan ----
                    std::size_t off = 0;

                    while (off + 8 <= bytes.size())
                    {
                        std::uint64_t value = 0;

                        std::memcpy(
                            &value,
                            bytes.data() + off,
                            sizeof(value));

                        unsigned int firstIdx = 0;

                        if (!ptrToCamoIndex(
                                value,
                                firstIdx))
                        {
                            off += 8;
                            continue;
                        }

                        const std::size_t runStart =
                            off;

                        std::size_t runOff =
                            off;

                        unsigned int lastIdx =
                            firstIdx;

                        std::vector<unsigned int> unique;

                        while (runOff + 8 <=
                               bytes.size())
                        {
                            std::uint64_t p = 0;

                            std::memcpy(
                                &p,
                                bytes.data() +
                                    runOff,
                                sizeof(p));

                            unsigned int idxValue = 0;

                            if (!ptrToCamoIndex(
                                    p,
                                    idxValue))
                            {
                                break;
                            }

                            lastIdx = idxValue;

                            if (std::find(
                                    unique.begin(),
                                    unique.end(),
                                    idxValue) ==
                                unique.end())
                            {
                                unique.push_back(
                                    idxValue);
                            }

                            runOff += 8;
                        }

                        const std::size_t runLength =
                            (runOff - runStart) / 8;

                        if (runLength >= 4)
                        {
                            const char* confidence =
                                runLength >= 16
                                ? "HIGH"
                                : runLength >= 8
                                    ? "MEDIUM"
                                    : "LOW";

                            heapArrays
                                << "CAMO_HEAP_ARRAY,0x"
                                << std::hex
                                << std::uppercase
                                << regionBase
                                << ",0x"
                                << regionSize
                                << ",0x"
                                << (regionBase +
                                    runStart)
                                << std::dec
                                << ','
                                << runLength
                                << ','
                                << firstIdx
                                << ','
                                << lastIdx
                                << ','
                                << unique.size()
                                << ','
                                << (mbi.Type == MEM_PRIVATE
                                    ? "PRIVATE"
                                    : "MAPPED")
                                << ','
                                << confidence
                                << "\n";

                            ++pointerArrayHits;
                        }

                        off =
                            runOff > off
                            ? runOff
                            : off + 8;
                    }

                    // ---- Index-array scan ----
                    // Expensive byte-by-byte discovery only runs in deep mode.
                    if (deep)
                    for (std::size_t start = 0;
                         start + 16 <= bytes.size();
                         ++start)
                    {
                        if (bytes[start] >=
                            std::min<unsigned int>(
                                camoAllocated,
                                255u))
                        {
                            continue;
                        }

                        std::size_t run = 0;
                        unsigned int minValue = 255;
                        unsigned int maxValue = 0;
                        bool seen[256]{};
                        unsigned int distinct = 0;

                        while (start + run <
                                   bytes.size() &&
                               run < 512)
                        {
                            const unsigned int v =
                                bytes[start + run];

                            if (v >=
                                std::min<unsigned int>(
                                    camoAllocated,
                                    255u))
                            {
                                break;
                            }

                            minValue =
                                std::min(
                                    minValue,
                                    v);

                            maxValue =
                                std::max(
                                    maxValue,
                                    v);

                            if (!seen[v])
                            {
                                seen[v] = true;
                                ++distinct;
                            }

                            ++run;
                        }

                        if (run >= 16 &&
                            distinct >= 4)
                        {
                            const bool sequentialish =
                                maxValue >= minValue &&
                                (maxValue - minValue + 1) <=
                                    distinct + 4;

                            const char* confidence =
                                run >= 48 &&
                                distinct >= 12
                                ? "HIGH"
                                : run >= 24 &&
                                  distinct >= 8
                                    ? "MEDIUM"
                                    : "LOW";

                            indexArrays
                                << "CAMO_INDEX_ARRAY8,0x"
                                << std::hex
                                << std::uppercase
                                << regionBase
                                << ",0x"
                                << (regionBase + start)
                                << std::dec
                                << ",8,"
                                << run
                                << ','
                                << minValue
                                << ','
                                << maxValue
                                << ','
                                << distinct
                                << ','
                                << (sequentialish
                                    ? "SEQUENTIALISH"
                                    : "MIXED")
                                << ','
                                << confidence
                                << "\n";

                            ++indexArrayHits;

                            start +=
                                run > 1
                                ? run - 1
                                : 0;
                        }
                    }
                }
            }

            if (regionSize == 0 ||
                regionBase + regionSize <= cursor)
            {
                break;
            }

            cursor =
                regionBase +
                static_cast<std::uintptr_t>(
                    regionSize);
        }

        if (!pointerArrayHits)
        {
            heapArrays
                << "CAMO_HEAP_ARRAY_NONE,0,0,0,0,-1,-1,0,NONE,NONE\n";
        }

        if (!indexArrayHits)
        {
            indexArrays
                << "CAMO_INDEX_ARRAY_NONE,0,0,0,0,0,0,0,NONE,NONE\n";
        }


        // -----------------------------------------------------------------
        // [FAST INDEX CANDIDATES]
        // Much stricter than the old 290k-result byte scan.
        // FAST mode samples every 16 bytes and keeps only long/diverse runs.
        // -----------------------------------------------------------------
        fastIndexCandidates
            << "label,region_base,address,run_length,min,max,distinct,score,confidence\n";

        if (!deep)
        {
            std::uintptr_t fastCursor =
                reinterpret_cast<std::uintptr_t>(sysInfo.lpMinimumApplicationAddress);

            std::uint64_t fastTotal = 0;
            constexpr std::uint64_t kFastTotal = 32ull * 1024ull * 1024ull;
            constexpr std::uint64_t kFastRegion = 4ull * 1024ull * 1024ull;
            unsigned int emitted = 0;

            while (fastCursor < maxAddress && fastTotal < kFastTotal && emitted < 64)
            {
                MEMORY_BASIC_INFORMATION mbi{};
                if (!VirtualQuery(reinterpret_cast<LPCVOID>(fastCursor), &mbi, sizeof(mbi)))
                    break;

                const auto regionBase = reinterpret_cast<std::uintptr_t>(mbi.BaseAddress);
                const auto regionSize = static_cast<std::uint64_t>(mbi.RegionSize);

                const bool ok =
                    mbi.State == MEM_COMMIT &&
                    !(mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)) &&
                    (mbi.Protect & (PAGE_READWRITE | PAGE_WRITECOPY)) &&
                    (mbi.Type == MEM_PRIVATE || mbi.Type == MEM_MAPPED) &&
                    regionSize >= 0x100 && regionSize <= kFastRegion;

                if (ok)
                {
                    std::vector<unsigned char> bytes(static_cast<std::size_t>(regionSize));
                    if (CopyFromProcess(reinterpret_cast<const void*>(regionBase), bytes.data(), bytes.size()))
                    {
                        fastTotal += bytes.size();

                        for (std::size_t start = 0; start + 32 <= bytes.size() && emitted < 64; start += 16)
                        {
                            std::size_t run = 0;
                            bool seen[256]{};
                            unsigned int distinct = 0;
                            unsigned int minV = 255, maxV = 0;
                            bool sawTop = false;

                            while (start + run < bytes.size() && run < 256)
                            {
                                const unsigned int v = bytes[start + run];
                                if (v >= std::min<unsigned int>(camoAllocated + 2, 255u))
                                    break;

                                minV = std::min(minV, v);
                                maxV = std::max(maxV, v);
                                if (!seen[v]) { seen[v] = true; ++distinct; }
                                if (v + 2 >= camoAllocated) sawTop = true;
                                ++run;
                            }

                            if (run < 32 || distinct < 10 || !sawTop)
                                continue;

                            const unsigned int score =
                                static_cast<unsigned int>(run) + distinct * 8 + (sawTop ? 64u : 0u);

                            const char* confidence =
                                score >= 320 ? "HIGH" : score >= 220 ? "MEDIUM" : "LOW";

                            fastIndexCandidates
                                << "CAMO_FAST_INDEX,0x" << std::hex << std::uppercase << regionBase
                                << ",0x" << (regionBase + start) << std::dec
                                << ',' << run << ',' << minV << ',' << maxV << ',' << distinct
                                << ',' << score << ',' << confidence << "\n";

                            ++emitted;
                        }
                    }
                }

                if (!regionSize || regionBase + regionSize <= fastCursor)
                    break;
                fastCursor = regionBase + static_cast<std::uintptr_t>(regionSize);
            }
        }

        fastIndexCandidates.flush();

        // -----------------------------------------------------------------
        // [TARGETED CANDIDATE SNAPSHOTS]
        // Fast state-diff pass around known/high-confidence candidates.
        // -----------------------------------------------------------------
        targetedSnapshots
            << "label,address,offset,value8,value16,value32,value64,readable\n";

        std::vector<std::uintptr_t> targeted;
        // Prior absolute heap candidates are not reused across launches (ASLR).
        for (const auto address : discoveredArrays)
            targeted.push_back(address);

        std::sort(targeted.begin(), targeted.end());
        targeted.erase(std::unique(targeted.begin(), targeted.end()), targeted.end());

        for (const auto center : targeted)
        {
            constexpr std::intptr_t kRadius = 0x200;
            for (std::intptr_t rel = -kRadius; rel <= kRadius; rel += 4)
            {
                const auto address = static_cast<std::uintptr_t>(static_cast<std::intptr_t>(center) + rel);
                unsigned char bytes[8]{};
                const bool readable = CopyFromProcess(reinterpret_cast<const void*>(address), bytes, sizeof(bytes));
                std::uint16_t v16 = 0; std::uint32_t v32 = 0; std::uint64_t v64 = 0;
                if (readable) { std::memcpy(&v16,bytes,sizeof(v16)); std::memcpy(&v32,bytes,sizeof(v32)); std::memcpy(&v64,bytes,sizeof(v64)); }
                targetedSnapshots << "CAMO_TARGET_SNAPSHOT,0x" << std::hex << std::uppercase << center << std::dec
                    << ',' << rel << ',' << static_cast<unsigned int>(bytes[0]) << ',' << v16 << ',' << v32
                    << ",0x" << std::hex << std::uppercase << v64 << std::dec << ',' << (readable?1:0) << "\n";
            }
        }
        targetedSnapshots.flush();

        // -----------------------------------------------------------------
        // [CANDIDATE SUMMARY / LABELS]
        // -----------------------------------------------------------------
        candidateSummary
            << "[SCAN CAMO EXTENDED DISCOVERY]\n"
            << "mode=" << (deep ? "DEEP" : "FAST") << "\n"
            << "exec_xrefs=" << xrefHits.size() << "\n"
            << "heap_pointer_arrays=" << pointerArrayHits << "\n"
            << "index_arrays=" << indexArrayHits << "\n"
            << "heap_bytes_scanned=" << totalHeapBytesScanned << "\n"
            << "\n"
            << "[LABEL MEANINGS]\n"
            << "CAMO_EXEC_XREF = executable code referencing a known features/camo/image pool field/base\n"
            << "CAMO_HEAP_ARRAY = runtime heap array containing repeated Camo* pointers\n"
            << "CAMO_INDEX_ARRAY8 = runtime byte array containing plausible camo indices\n"
            << "RUNTIME_CAMO_ARRAY = module writable-section Camo* array candidate\n"
            << "RUNTIME_CAMO_COUNT32/8 = count-like value near a runtime array candidate\n"
            << "\n"
            << "[NEXT TARGET CLASSES]\n"
            << "CAMO_DB_LOOKUP_CANDIDATE = code using camo asset type/name lookup\n"
            << "ASSET_ADD_CANDIDATE = code increasing allocation count / inserting a new asset\n"
            << "IMAGE_SETUP_CANDIDATE = code creating a GfxImage resource/texture id\n"
            << "CAMO_MENU_CANDIDATE = code/UI data consuming camo lists/categories\n"
            << "CAMO_RENDER_CANDIDATE = code resolving equipped camo index -> Camo*/texture defs\n"
            << "\n"
            << "[SAFETY]\n"
            << "This pass is read-only. It does not execute candidates, patch counts, or probe arbitrary COM objects.\n";


        // [ALLOCATOR / ADD-ASSET XREFS]
        allocatorXrefs
            << "label,section,instruction_address,target_address,target_label,"
               "bytes,confidence,notes\n";

        std::vector<std::pair<std::uintptr_t, const char*>> allocatorTargets;

        allocatorTargets.push_back({
            reinterpret_cast<std::uintptr_t>(&camoPool->itemAllocCount),
            "WEAPONCAMO_ITEMALLOCCOUNT"
        });

        allocatorTargets.push_back({
            reinterpret_cast<std::uintptr_t>(&camoPool->freeHead),
            "WEAPONCAMO_FREEHEAD"
        });

        allocatorTargets.push_back({
            camoBase +
                static_cast<std::uintptr_t>(camoAllocated) *
                camoPool->itemSize,
            "WEAPONCAMO_NEXT_SLOT"
        });

        allocatorTargets.push_back({
            reinterpret_cast<std::uintptr_t>(&bindingPool->itemAllocCount),
            "CAMOBINDING_ITEMALLOCCOUNT"
        });

        allocatorTargets.push_back({
            reinterpret_cast<std::uintptr_t>(&bindingPool->freeHead),
            "CAMOBINDING_FREEHEAD"
        });

        allocatorTargets.push_back({
            bindingBase +
                static_cast<std::uintptr_t>(bindingAllocated) *
                bindingPool->itemSize,
            "CAMOBINDING_NEXT_SLOT"
        });

        unsigned int allocatorHitCount = 0;
        HMODULE exe = GetModuleHandleW(nullptr);

        if (exe)
        {
            const auto base =
                reinterpret_cast<std::uintptr_t>(exe);

            IMAGE_DOS_HEADER dos{};

            if (CopyFromProcess(
                    reinterpret_cast<const void*>(base),
                    &dos,
                    sizeof(dos)) &&
                dos.e_magic == IMAGE_DOS_SIGNATURE)
            {
                IMAGE_NT_HEADERS64 nt{};
                const auto ntAddr =
                    base + static_cast<std::uintptr_t>(dos.e_lfanew);

                if (CopyFromProcess(
                        reinterpret_cast<const void*>(ntAddr),
                        &nt,
                        sizeof(nt)) &&
                    nt.Signature == IMAGE_NT_SIGNATURE)
                {
                    const auto shBase =
                        ntAddr +
                        sizeof(DWORD) +
                        sizeof(IMAGE_FILE_HEADER) +
                        nt.FileHeader.SizeOfOptionalHeader;

                    for (unsigned int si = 0;
                         si < nt.FileHeader.NumberOfSections;
                         ++si)
                    {
                        IMAGE_SECTION_HEADER sh{};

                        if (!CopyFromProcess(
                                reinterpret_cast<const void*>(
                                    shBase +
                                    static_cast<std::uintptr_t>(si) *
                                    sizeof(sh)),
                                &sh,
                                sizeof(sh)))
                        {
                            continue;
                        }

                        if (!(sh.Characteristics & IMAGE_SCN_MEM_EXECUTE) ||
                            !(sh.Characteristics & IMAGE_SCN_MEM_READ))
                        {
                            continue;
                        }

                        char sectionName[9]{};
                        std::memcpy(sectionName, sh.Name, 8);

                        const std::size_t size =
                            static_cast<std::size_t>(
                                std::max(
                                    sh.Misc.VirtualSize,
                                    sh.SizeOfRawData));

                        if (size < 8 ||
                            size > 512ull * 1024ull * 1024ull)
                        {
                            continue;
                        }

                        const auto sectionAddr =
                            base + sh.VirtualAddress;

                        std::vector<unsigned char> bytes(size);

                        if (!CopyFromProcess(
                                reinterpret_cast<const void*>(sectionAddr),
                                bytes.data(),
                                bytes.size()))
                        {
                            continue;
                        }

                        for (std::size_t off = 0;
                             off + 10 <= bytes.size();
                             ++off)
                        {
                            for (unsigned int len = 5; len <= 10; ++len)
                            {
                                for (unsigned int dispOff = 1;
                                     dispOff + 4 <= len;
                                     ++dispOff)
                                {
                                    std::int32_t disp = 0;

                                    std::memcpy(
                                        &disp,
                                        bytes.data() + off + dispOff,
                                        sizeof(disp));

                                    const auto target =
                                        static_cast<std::uintptr_t>(
                                            static_cast<std::intptr_t>(
                                                sectionAddr + off + len) +
                                            disp);

                                    for (const auto& candidate : allocatorTargets)
                                    {
                                        if (target != candidate.first)
                                            continue;

                                        std::ostringstream byteText;

                                        for (unsigned int bi = 0; bi < len; ++bi)
                                        {
                                            if (bi) byteText << ' ';
                                            byteText
                                                << std::hex
                                                << std::uppercase
                                                << std::setw(2)
                                                << std::setfill('0')
                                                << static_cast<unsigned int>(
                                                       bytes[off + bi]);
                                        }

                                        allocatorXrefs
                                            << "CAMO_ALLOCATOR_XREF,"
                                            << sectionName
                                            << ",0x"
                                            << std::hex
                                            << std::uppercase
                                            << (sectionAddr + off)
                                            << ",0x"
                                            << target
                                            << std::dec
                                            << ','
                                            << candidate.second
                                            << ",\""
                                            << byteText.str()
                                            << "\",HIGH,"
                                            << "inspect containing function for freeHead pop / alloc-count increment / asset insertion"
                                            << "\n";

                                        ++allocatorHitCount;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        if (!allocatorHitCount)
        {
            allocatorXrefs
                << "CAMO_ALLOCATOR_XREF_NONE,none,0,0,none,\"\",NONE,"
                   "no direct RIP-relative allocator xref found\n";
        }

        allocatorXrefs.flush();

        // -----------------------------------------------------------------
        // [LOADING / ENROLL / RENDER PATH TARGETS]
        // Clearly label the exact classes of functions/structures we still
        // need to resolve in T9, based on the working MW2019 additive design.
        // -----------------------------------------------------------------
        loadingCandidates
            << "[CAMO LOADING / ADDITIVE ASSET TARGETS]\n"
            << "NEED: T9 equivalent of DB_FindXAssetHeader for CAMO and IMAGE\n"
            << "NEED: T9 equivalent of DB_AddXAsset / runtime asset registration\n"
            << "NEED: T9 equivalent of Image_SetupWithData / Image_Setup that creates a resident GfxImage + texture handle\n"
            << "NEED: T9 Camo struct layout: name/internalName/textureDefs/textureDefCount\n"
            << "\n"
            << "[RUNTIME CAMO ENROLLMENT TARGETS]\n"
            << "SCAN: see _61_runtime_array_scan.csv for module-global Camo* array candidates\n"
            << "SCAN: see _62_runtime_count_scan.csv for nearby runtime count candidates\n"
            << "NEED: function that enrolls name/index into that runtime array\n"
            << "NEED: max runtime camo capacity / index width\n"
            << "\n"
            << "[RENDER PATH TARGETS]\n"
            << "NEED: function equivalent to BG_Camo_GetWeaponDObjCamoParams\n"
            << "NEED: weapon field holding equipped camo index/ref\n"
            << "NEED: render-time path that resolves camo index -> Camo* / texture definitions\n"
            << "\n"
            << "[MENU/UI TARGETS]\n"
            << "NEED: T9 camo category table/list and category count\n"
            << "NEED: per-category camo-entry table/list and entry count\n"
            << "NEED: Lua/LUI builder/function responsible for camo category grid\n"
            << "GOAL: add a Custom category instead of overwriting shipped camos\n"
            << "\n"
            << "[CONFIRMED CURRENT T9 DATA]\n"
            << "confirmed current custom overwrite target: camo slot 1 -> color GfxImage 23956\n"
            << "weaponCamo pool capacity=" << camoCapacity
            << " allocated=" << camoAllocated << "\n"
            << "weaponCamoBinding pool capacity=" << bindingCapacity
            << " allocated=" << bindingAllocated << "\n"
            << "Known transition-sensitive watch: weapon camo slot 57; bindings 2660/2661/2666/2667\n"
            << "\n"
            << "[HOW TO USE THIS SCAN]\n"
            << "Run /scan camo in the camo menu. Change category/weapon/state, run it again, then diff the labeled files.\n"
            << "The next resolver update should correlate changed counts/pointers with the UI and rendering state.\n";

        summary
            << "snapshot="
            << stamp
            << "\n"
            << "purpose=unified camo research: slots + bindings + image targets + runtime camo candidates + loading/enrollment/render targets\n"
            << "weaponCamo_base=0x"
            << std::hex
            << std::uppercase
            << camoBase
            << std::dec
            << "\n"
            << "weaponCamo_itemSize="
            << camoPool->itemSize
            << "\n"
            << "weaponCamo_capacity="
            << camoCapacity
            << "\n"
            << "weaponCamo_allocated="
            << camoAllocated
            << "\n"
            << "weaponCamo_readable_capacity_slots="
            << camoReadable
            << "\n"
            << "weaponCamo_nonzero_capacity_slots="
            << camoNonZero
            << "\n"
            << "weaponCamo_nonzero_after_allocated="
            << camoNonZeroPastAllocated
            << "\n"
            << "weaponCamo_zero_inside_allocated="
            << camoZeroInsideAllocated
            << "\n"
            << "weaponCamo_freeHead=0x"
            << std::hex
            << std::uppercase
            << reinterpret_cast<std::uintptr_t>(
                   camoPool->freeHead)
            << std::dec
            << "\n"
            << "binding_base=0x"
            << std::hex
            << std::uppercase
            << bindingBase
            << std::dec
            << "\n"
            << "binding_itemSize="
            << bindingPool->itemSize
            << "\n"
            << "binding_capacity="
            << bindingCapacity
            << "\n"
            << "binding_allocated="
            << bindingAllocated
            << "\n"
            << "binding_readable_capacity_slots="
            << bindingReadable
            << "\n"
            << "binding_nonzero_capacity_slots="
            << bindingNonZero
            << "\n"
            << "binding_nonzero_after_allocated="
            << bindingNonZeroPastAllocated
            << "\n"
            << "binding_zero_inside_allocated="
            << bindingZeroInsideAllocated
            << "\n"
            << "binding_owners_in_weaponCamo_pool="
            << bindingOwnersInCamoPool
            << "\n"
            << "binding_freeHead=0x"
            << std::hex
            << std::uppercase
            << reinterpret_cast<std::uintptr_t>(
                   bindingPool->freeHead)
            << std::dec
            << "\n"
            << "known_transition_watch=weapon camo slot 57 and binding tail 2660/2661/2666/2667 were state-sensitive in earlier snapshots\n"
            << "resource_probe_mode=SAFE_DIRECT_GFXIMAGE_PLUS_0x18_NO_SPECULATIVE_COM\n"
            << "runtime_array_scan=_61_runtime_array_scan.csv\n"
            << "runtime_count_scan=_62_runtime_count_scan.csv\n"
            << "exec_xref_scan=_80_exec_xrefs.csv\n"
            << "heap_runtime_scan=_81_heap_runtime_arrays.csv\n"
            << "index_hash_scan=_82_index_hash_arrays.csv\n"
            << "candidate_summary=_90_candidate_summary.txt\n"
            << "pointer_graph=_53_camo_pointer_graph.csv\n"
            << "gfximage_chain=_54_gfximage_chain.csv\n"
            << "allocator_xrefs=_72_allocator_xrefs.csv\n"
            << "shader_layers=_51_shader_material_layers.csv\n"
            << "shader_floats=_52_shader_float_candidates.csv\n"
            << "extra_slots=_71_extra_slot_candidates.csv\n"
            << "fast_index_candidates=_84_fast_index_candidates.csv\n"
            << "shader_summary=_91_shader_slot_summary.txt\n"
            << "material_images=_55_material_image_endpoints.csv\n"
            << "additive_registration=_73_additive_registration.csv\n"
            << "focused_summary=_92_focused_camo_summary.txt\n"
            << "ranked_layers=_57_ranked_layer_candidates.csv\n"
            << "material_tables=_58_material_texture_tables.csv\n"
            << "generic_pool_xrefs=_74_generic_pool_allocator_xrefs.csv\n"
            << "ranked_summary=_93_ranked_layer_allocator_summary.txt\n"
            << "material30_entries=_59_material30_texture_entries.csv\n"
            << "assetpool_base_xrefs=_75_assetpool_base_index_xrefs.csv\n"
            << "phase_summary=_94_material30_assetpool_summary.txt\n"
            << "material30_q0=_60_material30_q0_table.csv\n"
            << "binding_freelist=_76_binding_freelist_walk.csv\n"
            << "assetpool_indirect=_77_assetpool_indirect_candidates.csv\n"
            << "focused95=_95_material_binding_pool_summary.txt\n"
            << "semantic_clusters=_61_material_semantic_clusters.csv\n"
            << "synthetic_preview=_78_synthetic_additive_preview.txt\n"
            << "menu_candidates=_85_menu_enumeration_candidates.csv\n"
            << "menu_summary=_96_menu_vs_asset_summary.txt\n"
            << "ranked_menu_lists=_86_ranked_menu_lists.csv\n"
            << "menu_structure_xrefs=_87_menu_structure_xrefs.csv\n"
            << "prototype_readiness=_97_prototype_readiness.txt\n"
            << "registration_fields=_98_registration_field_candidates.csv\n"
            << "registration_windows=_99_registration_function_windows.txt\n"
            << "prototype_gate_v2=_100_prototype_gate_v2.txt\n"
            << "decoded_registration=_101_decoded_registration_candidates.csv\n"
            << "decoded_windows=_102_decoded_registration_windows.txt\n"
            << "prototype_gate_v3=_103_prototype_gate_v3.txt\n"
            << "strict_registration=_104_strict_registration_candidates.csv\n"
            << "strict_windows=_105_strict_registration_windows.txt\n"
            << "prototype_gate_v4=_106_prototype_gate_v4.txt\n"
            << "next_step=use fast /scan camo for state diffs; use /scan camo deep only for a full heap/index discovery pass\n";

        std::ostringstream out;

        out
            << "camo scan "
            << stamp
            << " complete: weaponCamo="
            << camoAllocated
            << "/"
            << camoCapacity
            << " binding="
            << bindingAllocated
            << "/"
            << bindingCapacity
            << " tailCamoNonzero="
            << camoNonZeroPastAllocated
            << " tailBindingNonzero="
            << bindingNonZeroPastAllocated
            << " prefix="
            << prefix;

        summary.flush(); camoSlots.flush(); bindingSlots.flush(); freeRanges.flush(); freeList.flush();
        poolFields.flush(); imageTargets.flush(); runtimeCandidates.flush(); runtimeArrays.flush(); runtimeCounts.flush();
        execXrefs.flush(); heapArrays.flush(); indexArrays.flush(); candidateSummary.flush(); targetedSnapshots.flush();

        message =
            out.str();

        return true;
    }

    bool Replace(unsigned int targetIndex, unsigned int sourceIndex, std::string& message)
    {
        std::lock_guard<std::mutex> lock(g_camoMutex);
        XAssetPool* pool = nullptr;
        if (!PoolReady(pool, message)) return false;

        const unsigned int count = static_cast<unsigned int>(std::max(0, pool->itemAllocCount));
        if (targetIndex >= count || sourceIndex >= count)
        {
            std::ostringstream out;
            out << "index out of range; valid range is 0-" << (count ? count - 1 : 0);
            message = out.str();
            return false;
        }
        if (targetIndex == sourceIndex)
        {
            message = "target and source indices are the same";
            return false;
        }

        const auto base = reinterpret_cast<std::uintptr_t>(pool->pool.unk);
        const auto targetAddress = base + static_cast<std::uintptr_t>(targetIndex) * pool->itemSize;
        const auto sourceAddress = base + static_cast<std::uintptr_t>(sourceIndex) * pool->itemSize;

        std::uint64_t targetDefinition = 0, sourceDefinition = 0;
        if (!CopyFromProcess(reinterpret_cast<const void*>(targetAddress + 0x10), &targetDefinition, 8) ||
            !CopyFromProcess(reinterpret_cast<const void*>(sourceAddress + 0x10), &sourceDefinition, 8))
        {
            message = "could not read target/source definition pointers";
            return false;
        }
        if (!sourceDefinition)
        {
            message = "source camo definition pointer is null";
            return false;
        }

        if (!g_backups.count(targetIndex))
            g_backups[targetIndex] = targetDefinition;

        if (!CopyToProcess(reinterpret_cast<void*>(targetAddress + 0x10), &sourceDefinition, 8))
        {
            message = "failed to write target definition pointer";
            return false;
        }

        std::ostringstream out;
        out << "weapon camo slot " << targetIndex << " definition 0x"
            << std::hex << std::uppercase << targetDefinition << " -> 0x"
            << sourceDefinition << std::dec << " from source slot " << sourceIndex
            << " (only +0x10 changed)";
        message = out.str();
        return true;
    }

    bool Restore(unsigned int targetIndex, std::string& message)
    {
        std::lock_guard<std::mutex> lock(g_camoMutex);
        XAssetPool* pool = nullptr;
        if (!PoolReady(pool, message)) return false;

        const auto it = g_backups.find(targetIndex);
        if (it == g_backups.end())
        {
            message = "no in-memory backup exists for that camo slot in this run";
            return false;
        }

        const unsigned int count = static_cast<unsigned int>(std::max(0, pool->itemAllocCount));
        if (targetIndex >= count)
        {
            message = "target index is outside the current camo pool";
            return false;
        }

        const auto base = reinterpret_cast<std::uintptr_t>(pool->pool.unk);
        const auto targetAddress = base + static_cast<std::uintptr_t>(targetIndex) * pool->itemSize;
        const std::uint64_t originalDefinition = it->second;

        if (!CopyToProcess(reinterpret_cast<void*>(targetAddress + 0x10), &originalDefinition, 8))
        {
            message = "failed to restore target definition pointer";
            return false;
        }

        g_backups.erase(it);
        std::ostringstream out;
        out << "restored weapon camo slot " << targetIndex << " definition pointer to 0x"
            << std::hex << std::uppercase << originalDefinition;
        message = out.str();
        return true;
    }

    bool CustomList(std::string& message)
    {
        const auto folders = EnumeratePackageFolders();
        CreateDirectoryA("logs", nullptr);
        std::ofstream file("logs\\camo\\custom_camos.csv", std::ios::trunc);
        if (!file)
        {
            message = "could not create logs\\camo\\custom_camos.csv";
            return false;
        }

        file << "name,folder,info_enabled,info,auto_apply,target_camo,gif,color_format,color_bytes\n";

        unsigned int loaded = 0;
        for (const auto& folder : folders)
        {
            CustomCamoPackage pkg;
            std::string error;
            if (!LoadPackageFolder(folder, pkg, error))
                continue;
            ++loaded;
            file << '"' << pkg.name << "\",\""
                 << pkg.folder << "\","
                 << (kEnableCamoInfoFiles ? 1 : 0) << ",\""
                 << pkg.infoPath << "\","
                 << (pkg.autoApply ? 1 : 0) << ','
                 << pkg.targetCamo << ",\""
                 << pkg.colorPath << "\","
                 << pkg.colorFormat << ','
                 << pkg.colorBytes << "\n";
        }

        std::ostringstream out;
        out << "found " << loaded << " custom camo package(s) under \"" << CamoRoot()
            << "\"; output=logs\\camo\\custom_camos.csv scan=logs\\camo\\custom_camo_folder_scan.log";
        message = out.str();
        return true;
    }

    bool CustomInspect(const std::string& packageName, std::string& message)
    {
        CustomCamoPackage pkg;
        if (!FindPackage(packageName, pkg, message))
            return false;

        std::ostringstream out;
        out << "name=\"" << pkg.name << "\" folder=\"" << pkg.folder << "\""
            << " info_enabled=" << (kEnableCamoInfoFiles ? 1 : 0)
            << " info=\"" << pkg.infoPath << "\""
            << " image=\"" << pkg.colorPath << "\""
            << " auto_apply=" << (pkg.autoApply ? 1 : 0)
            << " target_camo=" << pkg.targetCamo
            << " blend_channels=" << pkg.blendMapChannels
            << " uv=[" << pkg.uvScaleX << ',' << pkg.uvScaleY << ']'
            << " scroll=[" << pkg.scrollX << ',' << pkg.scrollY << ']'
            << " color_cycle=[" << pkg.colorCycleMin << ',' << pkg.colorCycleMax << ']'
            << " tint=\"" << pkg.colorTint << "\""
            << " color=" << pkg.colorFormat << '/' << pkg.colorBytes << "B"
            << " grey=" << pkg.greyFormat << '/' << pkg.greyBytes << "B";
        message = out.str();
        return true;
    }

    bool CustomStage(const std::string& packageName, unsigned int targetIndex, std::string& message)
    {
        CustomCamoPackage pkg;
        if (!FindPackage(packageName, pkg, message))
            return false;

        XAssetPool* pool = nullptr;
        if (!PoolReady(pool, message)) return false;
        const unsigned int count = static_cast<unsigned int>(std::max(0, pool->itemAllocCount));
        if (targetIndex >= count)
        {
            message = "target camo index is outside the weapon-camo pool";
            return false;
        }

        std::vector<unsigned char> color, grey;
        if (!ReadWholeFile(pkg.colorPath, color) || !ReadWholeFile(pkg.greyPath, grey))
        {
            message = "custom camo is missing layer0_color.gif or layer0_grey.gif";
            return false;
        }

        CreateDirectoryA("logs", nullptr);
        std::ofstream file("logs\\camo\\custom_camo_stage.txt", std::ios::trunc);
        file << "package=" << pkg.name << "\n";
        file << "folder=" << pkg.folder << "\n";
        file << "target_camo_index=" << targetIndex << "\n";
        file << "color_file=" << pkg.colorPath << "\n";
        file << "color_format=" << DetectImageFormat(color) << "\n";
        file << "color_bytes=" << color.size() << "\n";
        file << "grey_file=" << pkg.greyPath << "\n";
        file << "grey_format=" << DetectImageFormat(grey) << "\n";
        file << "grey_bytes=" << grey.size() << "\n";
        file << "status=STAGED_ONLY\n";
        file << "next_requirement=weapon camo definition -> binding/material/image reference mapping\n";

        std::ostringstream out;
        out << "staged custom camo \"" << pkg.name << "\" for target slot " << targetIndex
            << "; image bytes validated (" << DetectImageFormat(color) << '/' << color.size()
            << "B, " << DetectImageFormat(grey) << '/' << grey.size()
            << "B). Run /camo inspect to map the live material/image references before apply.";
        message = out.str();
        return true;
    }

    bool CustomApply(const std::string& packageName, unsigned int targetIndex, std::string& message)
    {
        CustomCamoPackage pkg;
        if (!FindPackage(packageName, pkg, message))
            return false;
        if (!FileExists(pkg.colorPath))
        {
            message = "custom camo color image is missing: " + pkg.colorPath;
            return false;
        }

        // Confirmed from the full role-isolation run:
        // camo 1 color/pattern -> GfxImage 23956.
        return camo_texture_upload::Apply(
            targetIndex, pkg.name, pkg.colorPath, message);
    }

    bool CustomApplyConfigured(
        const std::string& packageName,
        std::string& message)
    {
        CustomCamoPackage pkg;

        if (!FindPackage(
                packageName,
                pkg,
                message))
            return false;

        return CustomApply(
            packageName,
            pkg.targetCamo,
            message);
    }

    void StartAutoApply()
    {
        bool expected = false;

        if (!g_autoApplyStarted.compare_exchange_strong(
                expected,
                true))
            return;

        HANDLE thread =
            CreateThread(
                nullptr,
                0,
                AutoApplyWorker,
                nullptr,
                0,
                nullptr);

        if (thread)
        {
            CloseHandle(thread);
            AutoLog("startup Info.txt scanner scheduled");
        }
        else
        {
            g_autoApplyStarted.store(false);
            AutoLog("failed to create startup Info.txt scanner thread");
        }
    }

    void StartDefaultBo4DiamondAutoApply()
    {
        bool expected = false;

        if (!g_defaultCamoAutoStarted.compare_exchange_strong(
                expected,
                true))
        {
            return;
        }

        HANDLE thread =
            CreateThread(
                nullptr,
                0,
                DefaultBo4DiamondWorker,
                nullptr,
                0,
                nullptr);

        if (thread)
        {
            CloseHandle(thread);
            AutoLog(
                "temporary launch default scheduled: Bo4Diamond");
        }
        else
        {
            g_defaultCamoAutoStarted.store(false);

            AutoLog(
                "failed to create Bo4Diamond auto-apply worker");
        }
    }

    bool CustomRestore(unsigned int targetIndex, std::string& message)
    {
        // Restore an actual GPU texture upload first.
        std::string gpuMessage;
        if (camo_texture_upload::Restore(targetIndex, gpuMessage))
        {
            message = gpuMessage;
            return true;
        }

        // Legacy proof-pointer restore remains available.
        std::lock_guard<std::mutex> lock(g_camoMutex);
        const auto it = g_customImageBackups.find(targetIndex);
        if (it == g_customImageBackups.end() || it->second.empty())
        {
            message = "no custom texture upload or proof-pointer backup is active";
            return false;
        }

        std::size_t restored = 0;
        for (auto p = it->second.rbegin(); p != it->second.rend(); ++p)
        {
            if (CopyToProcess(reinterpret_cast<void*>(p->address),
                              &p->originalValue, 8))
                ++restored;
        }

        const std::size_t expected = it->second.size();
        g_customImageBackups.erase(it);

        std::ostringstream out;
        out << "restored " << restored << "/" << expected
            << " legacy proof pointers for camo slot " << targetIndex;
        message = out.str();
        return restored == expected;
    }
    bool CustomAnalyzeImages(unsigned int targetIndex, std::string& message)
    {
        std::lock_guard<std::mutex> lock(g_camoMutex);

        XAssetPool* camoPool = nullptr;
        std::uint64_t definition = 0, nameHash = 0;
        if (!ReadCamoEntry(targetIndex, camoPool, definition, nameHash, message))
            return false;

        const auto& bindingPool = g_assetPool[ASSET_TYPE_WEAPONCAMOBINDING];
        const auto& materialPool = g_assetPool[ASSET_TYPE_MATERIAL];
        const auto& imagePool = g_assetPool[ASSET_TYPE_IMAGE];

        if (!bindingPool.pool.unk || !materialPool.pool.unk || !imagePool.pool.unk)
        {
            message = "binding/material/image pools are not ready";
            return false;
        }

        auto candidates = CollectImageCandidatesForCamo(
            targetIndex, *camoPool, bindingPool, materialPool, imagePool);

        g_imageCandidates[targetIndex] = candidates;

        auto queue = BuildPrioritizedImageQueue(candidates);
        auto& cycle = g_imageCycleStates[targetIndex];
        RestoreCyclePatches(cycle);
        cycle.queue = queue;
        cycle.position = -1;
        cycle.analyzed = true;
        cycle.kept = false;
        cycle.keptRole.clear();

        CreateDirectoryA("logs", nullptr);
        std::ofstream list("logs\\camo\\camo_image_candidates.csv", std::ios::trunc);
        std::ofstream images("logs\\camo\\camo_gfximage_records.csv", std::ios::trunc);
        std::ofstream pointers("logs\\camo\\camo_gfximage_pointer_fields.csv", std::ios::trunc);
        std::ofstream queueFile("logs\\camo\\camo_image_test_queue.csv", std::ios::trunc);

        if (!list || !images || !pointers || !queueFile)
        {
            message = "could not create GfxImage analysis logs";
            return false;
        }

        list << "candidate_index,target_camo,source,owner_index,pointer_address,parent_ptr,parent_offset,image_index,image_ptr\n";
        images << "candidate_index,image_index,image_ptr,record_readable,record_size\n";
        pointers << "candidate_index,image_index,gfximage_offset,value,region_type,readable_span\n";

        queueFile << "queue_position,tier,image_index,ref_count,owner_count\n";
        for (std::size_t qi = 0; qi < queue.size(); ++qi)
        {
            queueFile << qi << ',' << queue[qi].tier << ','
                      << queue[qi].imageIndex << ',' << queue[qi].refCount
                      << ',' << queue[qi].ownerCount << "\n";
        }

        std::unordered_map<unsigned int, bool> dumpedImages;
        unsigned int readableImages = 0;
        unsigned int pointerFields = 0;

        for (std::size_t i = 0; i < candidates.size(); ++i)
        {
            const auto& c = candidates[i];
            list << i << ',' << targetIndex << ',' << c.source << ',' << c.ownerIndex
                 << ",0x" << std::hex << std::uppercase << c.pointerAddress
                 << ",0x" << c.parentPtr
                 << ",0x" << c.parentOffset
                 << std::dec << ',' << c.imageIndex
                 << ",0x" << std::hex << c.imagePtr << std::dec << "\n";

            if (dumpedImages.count(c.imageIndex))
                continue;
            dumpedImages[c.imageIndex] = true;

            std::vector<unsigned char> record(imagePool.itemSize);
            const bool readable = CopyFromProcess(reinterpret_cast<const void*>(c.imagePtr),
                                                  record.data(), record.size());
            images << i << ',' << c.imageIndex << ",0x" << std::hex << std::uppercase
                   << c.imagePtr << std::dec << ',' << (readable ? 1 : 0)
                   << ',' << record.size() << "\n";

            if (!readable)
                continue;

            ++readableImages;

            // Save the raw 208-byte image record plus the first readable child blocks.
            std::ostringstream path;
            path << "logs\\camo\\gfximage_" << c.imageIndex << "_record.txt";
            std::ofstream dump(path.str(), std::ios::trunc);
            if (dump)
            {
                dump << "image_index=" << c.imageIndex << "\n";
                dump << "image_ptr=0x" << std::hex << std::uppercase << c.imagePtr << std::dec << "\n";
                dump << "record_size=" << record.size() << "\n";
                DumpHexBytes(dump, record.data(), record.size());
            }

            for (std::size_t off = 0; off + 8 <= record.size(); off += 8)
            {
                std::uint64_t value = 0;
                std::memcpy(&value, record.data() + off, 8);
                if (!LooksLikePointer(value))
                    continue;

                ++pointerFields;
                const auto span = SafeReadableSpan(value, 0x400);
                pointers << i << ',' << c.imageIndex
                         << ",0x" << std::hex << std::uppercase << off
                         << ",0x" << value << std::dec
                         << ',' << RegionTypeName(value)
                         << ',' << span << "\n";

                if (dump && span >= 16)
                {
                    std::vector<unsigned char> child;
                    if (ReadBlock(value, child, 0x100))
                    {
                        dump << "\nchild_from_record_offset=0x"
                             << std::hex << std::uppercase << off
                             << " ptr=0x" << value << std::dec
                             << " region=" << RegionTypeName(value)
                             << " span=" << span << "\n";
                        DumpHexBytes(dump, child.data(), child.size());
                    }
                }
            }
        }

        const auto tier0Count = static_cast<unsigned int>(std::count_if(
            queue.begin(), queue.end(),
            [](const ImageGroupCandidate& q) { return q.tier == 0; }));

        std::ostringstream out;
        out << "analyzed camo slot " << targetIndex
            << ": rawRefs=" << candidates.size()
            << " uniqueImages=" << dumpedImages.size()
            << " prioritizedQueue=" << queue.size()
            << " tier0=" << tier0Count
            << " readableGfxImages=" << readableImages
            << ". Start with /camo custom next " << targetIndex
            << " to cycle grouped image candidates automatically.";
        message = out.str();
        return true;
    }

    bool CustomTestImage(unsigned int targetIndex, unsigned int candidateIndex, std::string& message)
    {
        std::lock_guard<std::mutex> lock(g_camoMutex);

        const auto it = g_imageCandidates.find(targetIndex);
        if (it == g_imageCandidates.end() || candidateIndex >= it->second.size())
        {
            message = "candidate index is invalid; run /camo custom analyze <targetIndex> first";
            return false;
        }

        const auto& imagePool = g_assetPool[ASSET_TYPE_IMAGE];
        if (!imagePool.pool.unk || imagePool.itemSize == 0 || imagePool.itemAllocCount <= 4)
        {
            message = "image pool is not ready";
            return false;
        }

        // Restore previous single-candidate test for this target.
        auto old = g_singleImageTestBackup.find(targetIndex);
        if (old != g_singleImageTestBackup.end())
        {
            CopyToProcess(reinterpret_cast<void*>(old->second.address),
                          &old->second.originalValue, 8);
            g_singleImageTestBackup.erase(old);
        }

        constexpr unsigned int donorIndex = 4;
        const auto imageBase = reinterpret_cast<std::uintptr_t>(imagePool.pool.unk);
        const std::uint64_t donor =
            imageBase + static_cast<std::uint64_t>(donorIndex) * imagePool.itemSize;

        const auto& c = it->second[candidateIndex];
        std::uint64_t current = 0;
        if (!CopyFromProcess(reinterpret_cast<const void*>(c.pointerAddress), &current, 8))
        {
            message = "could not read candidate pointer";
            return false;
        }

        if (!CopyToProcess(reinterpret_cast<void*>(c.pointerAddress), &donor, 8))
        {
            message = "could not patch candidate pointer";
            return false;
        }

        g_singleImageTestBackup[targetIndex] = {
            c.pointerAddress, current, donor
        };

        std::ostringstream out;
        out << "testing candidate " << candidateIndex
            << " for camo " << targetIndex
            << ": source=" << c.source
            << " owner=" << c.ownerIndex
            << " parentOffset=0x" << std::hex << std::uppercase << c.parentOffset
            << " originalImage=" << std::dec << c.imageIndex
            << " -> donorImage=" << donorIndex
            << ". Use /camo custom testrestore " << targetIndex << " to undo.";
        message = out.str();
        return true;
    }

    bool CustomTestRestore(unsigned int targetIndex, std::string& message)
    {
        std::lock_guard<std::mutex> lock(g_camoMutex);

        std::size_t restored = 0;
        std::size_t expected = 0;

        // New grouped /next /prev test state.
        auto cycleIt = g_imageCycleStates.find(targetIndex);
        if (cycleIt != g_imageCycleStates.end() && !cycleIt->second.activePatches.empty())
        {
            expected += cycleIt->second.activePatches.size();

            for (auto it = cycleIt->second.activePatches.rbegin();
                 it != cycleIt->second.activePatches.rend(); ++it)
            {
                if (CopyToProcess(reinterpret_cast<void*>(it->address),
                                  &it->originalValue, 8))
                    ++restored;
            }

            cycleIt->second.activePatches.clear();

            // Keep the saved role/candidate metadata. /keep means "remember this
            // candidate", not "the donor test must remain patched forever".
            // Position is retained so status still identifies the kept candidate.
        }

        // Older raw /camo custom test <target> <candidate> state.
        auto singleIt = g_singleImageTestBackup.find(targetIndex);
        if (singleIt != g_singleImageTestBackup.end())
        {
            ++expected;
            if (CopyToProcess(reinterpret_cast<void*>(singleIt->second.address),
                              &singleIt->second.originalValue, 8))
                ++restored;
            g_singleImageTestBackup.erase(singleIt);
        }

        if (expected == 0)
        {
            message = "no active camo test patch exists for that target; any kept role remains saved";
            return false;
        }

        std::ostringstream out;
        out << "restored " << restored << "/" << expected
            << " active camo test pointer(s) for target " << targetIndex;

        if (cycleIt != g_imageCycleStates.end() && cycleIt->second.kept)
        {
            out << "; kept role=\"" << cycleIt->second.keptRole << "\" remains saved";
            if (cycleIt->second.position >= 0 &&
                cycleIt->second.position < static_cast<int>(cycleIt->second.queue.size()))
            {
                const auto& q =
                    cycleIt->second.queue[static_cast<std::size_t>(cycleIt->second.position)];
                out << " image=" << q.imageIndex;
            }
        }

        message = out.str();
        return restored == expected;
    }

    bool CustomNextImage(unsigned int targetIndex, std::string& message)
    {
        std::lock_guard<std::mutex> lock(g_camoMutex);
        auto it = g_imageCycleStates.find(targetIndex);
        if (it == g_imageCycleStates.end() || !it->second.analyzed)
        {
            message = "run /camo custom analyze <targetIndex> first";
            return false;
        }
        return ApplyCyclePosition(targetIndex, it->second.position + 1, message);
    }

    bool CustomPrevImage(unsigned int targetIndex, std::string& message)
    {
        std::lock_guard<std::mutex> lock(g_camoMutex);
        auto it = g_imageCycleStates.find(targetIndex);
        if (it == g_imageCycleStates.end() || !it->second.analyzed)
        {
            message = "run /camo custom analyze <targetIndex> first";
            return false;
        }
        const int desired = it->second.position < 0
            ? static_cast<int>(it->second.queue.size()) - 1
            : it->second.position - 1;
        return ApplyCyclePosition(targetIndex, desired, message);
    }

    bool CustomTestStatus(unsigned int targetIndex, std::string& message)
    {
        std::lock_guard<std::mutex> lock(g_camoMutex);
        const auto it = g_imageCycleStates.find(targetIndex);
        if (it == g_imageCycleStates.end() || !it->second.analyzed)
        {
            message = "no analyzed image queue exists for that target";
            return false;
        }

        const auto& state = it->second;
        std::ostringstream out;
        out << "target=" << targetIndex
            << " queue=" << state.queue.size()
            << " position=" << state.position
            << " activePatches=" << state.activePatches.size();

        if (state.position >= 0 && state.position < static_cast<int>(state.queue.size()))
        {
            const auto& q = state.queue[static_cast<std::size_t>(state.position)];
            out << " tier=" << q.tier
                << " image=" << q.imageIndex
                << " refs=" << q.refCount
                << " owners=" << q.ownerCount;
        }

        if (state.kept)
            out << " KEPT role=" << state.keptRole;

        message = out.str();
        return true;
    }

    bool CustomKeepImage(unsigned int targetIndex, const std::string& role, std::string& message)
    {
        std::lock_guard<std::mutex> lock(g_camoMutex);
        auto it = g_imageCycleStates.find(targetIndex);
        if (it == g_imageCycleStates.end() || !it->second.analyzed ||
            it->second.position < 0 ||
            it->second.position >= static_cast<int>(it->second.queue.size()) ||
            it->second.activePatches.empty())
        {
            message = "no active candidate is available to keep";
            return false;
        }

        auto& state = it->second;
        state.kept = true;
        state.keptRole = role.empty() ? "color" : role;
        const auto& q = state.queue[static_cast<std::size_t>(state.position)];

        CreateDirectoryA("logs", nullptr);
        std::ofstream file("logs\\camo\\camo_confirmed_roles.csv", std::ios::app);
        if (file)
        {
            if (file.tellp() == 0)
                file << "target_camo,role,queue_position,tier,image_index,ref_count,owner_count\n";
            file << targetIndex << ',' << state.keptRole << ',' << state.position << ','
                 << q.tier << ',' << q.imageIndex << ',' << q.refCount << ','
                 << q.ownerCount << "\n";
        }

        std::ostringstream out;
        out << "kept candidate " << (state.position + 1) << "/" << state.queue.size()
            << " as role=\"" << state.keptRole << "\" image=" << q.imageIndex
            << ". The donor patch stays active until testrestore or another candidate.";
        message = out.str();
        return true;
    }

}

namespace camo_manager
{
    bool GetAllocatorResearchSnapshot(
        AllocatorResearchSnapshot& out)
    {
        std::lock_guard<std::mutex> lock(
            g_allocatorResearchSnapshotMutex);

        if (!g_allocatorResearchSnapshot.weaponCamoPool ||
            !g_allocatorResearchSnapshot.weaponCamoBindingPool)
        {
            return false;
        }

        out = g_allocatorResearchSnapshot;
        return true;
    }
}


namespace camo_manager
{
    bool TryResolveAllocatorResearchSnapshotEarly(
        AllocatorResearchSnapshot& out)
    {
        // Retail-only, read-only early path. This is intentionally independent
        // of /scan camo and of the delayed g_assetPool initialization.
        constexpr std::uintptr_t kRetailAssetPoolRva = 0x123E2E70;
        constexpr DWORD kRetailTimestamp = t9_addresses::RetailFingerprint.timestamp;
        constexpr std::uint32_t kRetailImageSize = t9_addresses::RetailFingerprint.imageSize;

        HMODULE module = GetModuleHandleW(nullptr);
        if (!module)
            return false;

        const auto base =
            reinterpret_cast<std::uintptr_t>(module);

        IMAGE_DOS_HEADER dos{};
        SIZE_T got = 0;

        if (!ReadProcessMemory(
                GetCurrentProcess(),
                reinterpret_cast<const void*>(base),
                &dos,
                sizeof(dos),
                &got) ||
            got != sizeof(dos) ||
            dos.e_magic != IMAGE_DOS_SIGNATURE)
        {
            return false;
        }

        IMAGE_NT_HEADERS64 nt{};
        got = 0;

        const auto ntAddress =
            base +
            static_cast<std::uintptr_t>(dos.e_lfanew);

        if (!ReadProcessMemory(
                GetCurrentProcess(),
                reinterpret_cast<const void*>(ntAddress),
                &nt,
                sizeof(nt),
                &got) ||
            got != sizeof(nt) ||
            nt.Signature != IMAGE_NT_SIGNATURE)
        {
            return false;
        }

        if (nt.FileHeader.TimeDateStamp != kRetailTimestamp ||
            nt.OptionalHeader.SizeOfImage != kRetailImageSize)
        {
            return false;
        }

        const auto table =
            reinterpret_cast<const XAssetPool*>(
                base + kRetailAssetPoolRva);

        XAssetPool camo{};
        XAssetPool binding{};

        got = 0;
        if (!ReadProcessMemory(
                GetCurrentProcess(),
                &table[ASSET_TYPE_WEAPONCAMO],
                &camo,
                sizeof(camo),
                &got) ||
            got != sizeof(camo))
        {
            return false;
        }

        got = 0;
        if (!ReadProcessMemory(
                GetCurrentProcess(),
                &table[ASSET_TYPE_WEAPONCAMOBINDING],
                &binding,
                sizeof(binding),
                &got) ||
            got != sizeof(binding))
        {
            return false;
        }

        // Keep validation deliberately broad enough to catch the pools while
        // they are being initialized, but strict enough to reject garbage.
        if (camo.itemSize == 0 ||
            camo.itemSize > 0x400 ||
            camo.itemCount < 0 ||
            camo.itemCount > 100000 ||
            binding.itemSize == 0 ||
            binding.itemSize > 0x400 ||
            binding.itemCount < 0 ||
            binding.itemCount > 100000)
        {
            return false;
        }

        out.weaponCamoPool =
            reinterpret_cast<std::uintptr_t>(
                camo.pool.unk);

        out.weaponCamoBindingPool =
            reinterpret_cast<std::uintptr_t>(
                binding.pool.unk);

        out.weaponCamoFreeHead =
            reinterpret_cast<std::uintptr_t>(
                camo.freeHead);

        out.weaponCamoItemAllocCount =
            static_cast<unsigned int>(
                std::max(0, camo.itemAllocCount));

        out.weaponCamoBindingFreeHead =
            reinterpret_cast<std::uintptr_t>(
                binding.freeHead);

        out.weaponCamoBindingItemAllocCount =
            static_cast<unsigned int>(
                std::max(0, binding.itemAllocCount));

        // During the earliest DB setup pool bases can still be null. We still
        // return a valid state once the pool metadata itself is readable so the
        // tracer can catch null->real and 0->allocated transitions.
        return true;
    }
}

#include "../../features/camo/CamoTextureUpload.h"
#include "CamoAllocatorTrace.h"
#include "../../core/Main.hpp"
#include "../../runtime/ui/ImGuiBackendBridge.h"

#include <Windows.h>
#include <d3d12.h>
#include <dxgi1_4.h>
#include <wincodec.h>
#include <wrl/client.h>

#include <algorithm>
#include <atomic>
#include <array>
#include <cctype>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <cstdlib>
#include <fstream>
#include <future>
#include <filesystem>
#include <limits>
#include <mutex>
#include <thread>
#include <memory>
#include <chrono>
#include <sstream>
#include <string>
#include <unordered_map>
#include <vector>

using Microsoft::WRL::ComPtr;

namespace
{
    constexpr unsigned int kConfirmedCamo = 1;
    constexpr unsigned int kConfirmedColorImage = 23956;
    constexpr std::size_t kImageRecordBytes = 208;
    constexpr UINT kExpectedWidth = 256;
    constexpr UINT kExpectedHeight = 256;
    constexpr UINT kExpectedMips = 4;

    struct SubresourceLayout
    {
        D3D12_PLACED_SUBRESOURCE_FOOTPRINT footprint{};
        UINT rows = 0;
        UINT64 rowBytes = 0;
    };

    struct TextureBackup
    {
        ComPtr<ID3D12Resource> resource;
        D3D12_RESOURCE_DESC desc{};
        std::vector<SubresourceLayout> layouts;
        UINT64 totalBytes = 0;
        std::vector<unsigned char> bytes;
    };

    struct RgbaImage
    {
        UINT width = 0;
        UINT height = 0;
        std::vector<unsigned char> pixels;
    };

    struct DecodedFrame
    {
        RgbaImage image;
        UINT delayMs = 100;
    };

    struct CachedFrame
    {
        UINT delayMs = 100;
        std::vector<std::vector<unsigned char>> mipData;
    };

    struct PreparedFrame
    {
        ComPtr<ID3D12Resource> upload;
        UINT delayMs = 100;
    };

    struct AnimationState
    {
        std::jthread worker;
        ComPtr<ID3D12Device> device;
        ComPtr<ID3D12CommandQueue> queue;
        ComPtr<ID3D12Resource> texture;
        std::uint64_t gfxImage = 0;
        std::string colorPath;

        UINT width = 0;
        UINT height = 0;
        UINT mipCount = 0;
        DXGI_FORMAT format = DXGI_FORMAT_UNKNOWN;
        UINT64 totalBytes = 0;

        std::vector<SubresourceLayout> layouts;

        // Low-memory HQ animation path:
        // keep compressed BC7 data once and reuse ONE D3D12 upload buffer.
        std::vector<CachedFrame> frames;
        ComPtr<ID3D12Resource> animationUpload;

        std::vector<TextureBackup> backups;
    };

    std::mutex g_mutex;
    std::unordered_map<unsigned int, TextureBackup> g_backups;
    std::unordered_map<unsigned int, std::unique_ptr<AnimationState>> g_animations;
    std::atomic_bool g_precacheRunning{false};
    std::atomic_uint g_precacheDone{0};
    std::atomic_uint g_precacheTotal{0};
    std::atomic_uint g_precacheHits{0};
    std::atomic_uint g_precacheBuilds{0};
    thread_local bool g_backgroundPrecacheMode = false;

    bool ReadMem(std::uint64_t p, void* out, std::size_t n)
    {
        SIZE_T got = 0;
        return p && out && n &&
            ReadProcessMemory(GetCurrentProcess(),
                reinterpret_cast<const void*>(p), out, n, &got) &&
            got == n;
    }

    std::string Lower(std::string s)
    {
        std::transform(s.begin(), s.end(), s.begin(),
            [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        return s;
    }

    std::string ModuleAt(std::uint64_t address)
    {
        HMODULE module = nullptr;
        if (!address ||
            !GetModuleHandleExA(
                GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                reinterpret_cast<LPCSTR>(address), &module))
            return {};

        char path[MAX_PATH]{};
        if (!GetModuleFileNameA(module, path, MAX_PATH))
            return {};
        return Lower(path);
    }

    bool DriverObject(std::uint64_t object, std::string& module)
    {
        std::uint64_t vtable = 0;
        if (!ReadMem(object, &vtable, sizeof(vtable)))
            return false;

        module = ModuleAt(vtable);
        return module.find("d3d12") != std::string::npos ||
               module.find("nvwgf") != std::string::npos ||
               module.find("atidxx") != std::string::npos ||
               module.find("igd12") != std::string::npos ||
               module.find("dxgi") != std::string::npos;
    }

    // SEH stays isolated from objects requiring unwinding.
    bool TryQIResource(void* object, ID3D12Resource** result)
    {
        if (!result) return false;
        *result = nullptr;

        __try
        {
            IUnknown* unknown = reinterpret_cast<IUnknown*>(object);
            ID3D12Resource* resource = nullptr;
            const HRESULT hr = unknown->QueryInterface(
                __uuidof(ID3D12Resource),
                reinterpret_cast<void**>(&resource));

            if (SUCCEEDED(hr) && resource)
            {
                *result = resource;
                return true;
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
        }

        return false;
    }

    void GatherQwords(const unsigned char* bytes, std::size_t size,
                      std::vector<std::uint64_t>& out)
    {
        for (std::size_t off = 0; off + 8 <= size; off += 8)
        {
            std::uint64_t value = 0;
            std::memcpy(&value, bytes + off, 8);
            if (value < 0x10000)
                continue;

            if (std::find(out.begin(), out.end(), value) == out.end())
                out.push_back(value);
        }
    }

    const char* FormatName(DXGI_FORMAT format)
    {
        switch (format)
        {
        case DXGI_FORMAT_BC7_UNORM: return "BC7_UNORM";
        case DXGI_FORMAT_BC7_UNORM_SRGB: return "BC7_UNORM_SRGB";
        case DXGI_FORMAT_R8G8B8A8_UNORM: return "R8G8B8A8_UNORM";
        case DXGI_FORMAT_R8G8B8A8_UNORM_SRGB: return "R8G8B8A8_UNORM_SRGB";
        default: return "OTHER";
        }
    }

    bool IsPowerOfTwo(UINT value)
    {
        return value != 0 && (value & (value - 1)) == 0;
    }

    bool IsSupportedCamoResource(const D3D12_RESOURCE_DESC& desc)
    {
        return desc.Dimension == D3D12_RESOURCE_DIMENSION_TEXTURE2D &&
               desc.Width >= 64 &&
               desc.Width <= 4096 &&
               desc.Height >= 64 &&
               desc.Height <= 4096 &&
               desc.Width == desc.Height &&
               IsPowerOfTwo(static_cast<UINT>(desc.Width)) &&
               IsPowerOfTwo(desc.Height) &&
               desc.MipLevels >= 1 &&
               (desc.Format == DXGI_FORMAT_BC7_UNORM_SRGB ||
                desc.Format == DXGI_FORMAT_BC7_UNORM);
    }


    // Keep SEH in tiny POD-only helpers. MSVC C2712 forbids __try in
    // functions with C++ objects that require unwinding (ComPtr/string/etc).
    bool SafeGetResourceDesc(
        ID3D12Resource* resource,
        D3D12_RESOURCE_DESC* outDesc)
    {
        if (!resource || !outDesc)
            return false;

        __try
        {
            *outDesc =
                resource->GetDesc();

            return true;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return false;
        }
    }

    bool SafeGetResourceDevice(
        ID3D12Resource* resource,
        ID3D12Device** outDevice)
    {
        if (!resource || !outDevice)
            return false;

        *outDevice = nullptr;

        __try
        {
            return SUCCEEDED(
                resource->GetDevice(
                    IID_PPV_ARGS(outDevice)));
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            *outDevice = nullptr;
            return false;
        }
    }

    bool FindResource(std::uint64_t gfxImage,
                      ID3D12Device* device,
                      ComPtr<ID3D12Resource>& found,
                      std::string& detail,
                      bool writeLog = true)
    {
        found.Reset();

        // Confirmed by /scan camo:
        // T9 GfxImage item size = 0xD0 (208)
        // GfxImage 23956 q3 / +0x18 = live ID3D12Resource interface.
        //
        // IMPORTANT:
        // Older builds recursively gathered arbitrary qwords and called
        // QueryInterface on anything whose vtable looked driver-related.
        // NVIDIA/D3D12 driver objects can fault inside their VEH before our
        // local SEH handler receives control. That caused the 14:46:52 crash.
        //
        // Do NOT probe speculative COM pointers anymore.
        constexpr std::size_t kConfirmedResourceOffset = 0x18;

        std::uint64_t resourceObject = 0;

        if (!ReadMem(
                gfxImage + kConfirmedResourceOffset,
                &resourceObject,
                sizeof(resourceObject)) ||
            !resourceObject)
        {
            detail =
                "GfxImage 23956 +0x18 resource pointer is unavailable";
            return false;
        }

        std::string module;

        if (!DriverObject(resourceObject, module))
        {
            detail =
                "GfxImage 23956 +0x18 does not currently point to a D3D12 driver object";
            return false;
        }

        // The field itself is already the confirmed ID3D12Resource interface
        // for this build. AddRef through QueryInterface only on this ONE
        // engine-owned pointer, never on speculative children.
        ID3D12Resource* raw = nullptr;

        if (!TryQIResource(
                reinterpret_cast<void*>(
                    resourceObject),
                &raw) ||
            !raw)
        {
            detail =
                "confirmed +0x18 D3D12 resource did not expose ID3D12Resource";
            return false;
        }

        ComPtr<ID3D12Resource> resource;
        resource.Attach(raw);

        D3D12_RESOURCE_DESC desc{};

        if (!SafeGetResourceDesc(
                resource.Get(),
                &desc))
        {
            detail =
                "confirmed D3D12 resource became stale during GetDesc";
            return false;
        }

        ID3D12Device* resourceDevice = nullptr;

        const bool gotDevice =
            SafeGetResourceDevice(
                resource.Get(),
                &resourceDevice);

        const bool sameDevice =
            gotDevice &&
            resourceDevice == device;

        if (resourceDevice)
            resourceDevice->Release();

        const bool supported =
            sameDevice &&
            IsSupportedCamoResource(desc);

        if (writeLog)
        {
            CreateDirectoryA("logs\\camo\\camo", nullptr);

            std::ofstream log(
                "logs\\camo\\camo_gfximage_resource_probe.csv",
                std::ios::trunc);

            if (log)
            {
                log
                    << "source,offset,candidate,module,width,height,format,"
                       "format_name,mips,dimension,same_device,supported,selected\n"
                    << "GFXIMAGE_23956_DIRECT,+0x18,0x"
                    << std::hex
                    << std::uppercase
                    << resourceObject
                    << ",\""
                    << module
                    << "\","
                    << std::dec
                    << desc.Width
                    << ','
                    << desc.Height
                    << ','
                    << static_cast<unsigned int>(
                           desc.Format)
                    << ','
                    << FormatName(desc.Format)
                    << ','
                    << desc.MipLevels
                    << ','
                    << static_cast<unsigned int>(
                           desc.Dimension)
                    << ','
                    << (sameDevice ? 1 : 0)
                    << ','
                    << (supported ? 1 : 0)
                    << ','
                    << (supported ? 1 : 0)
                    << "\n";
            }
        }

        if (!supported)
        {
            std::ostringstream out;

            out
                << "confirmed +0x18 resource is "
                << desc.Width
                << 'x'
                << desc.Height
                << ' '
                << FormatName(desc.Format)
                << " mips="
                << desc.MipLevels
                << " sameDevice="
                << (sameDevice ? 1 : 0)
                << "; waiting for supported BC7 camo resource";

            detail = out.str();
            return false;
        }

        found = resource;

        std::ostringstream out;

        out
            << "direct GfxImage+0x18 resource="
            << resourceObject
            << ' '
            << desc.Width
            << 'x'
            << desc.Height
            << ' '
            << FormatName(desc.Format)
            << " mips="
            << desc.MipLevels;

        detail = out.str();
        return true;
    }

    UINT ReadGifDelayMs(IWICBitmapFrameDecode* frame)
    {
        if (!frame)
            return 100;

        ComPtr<IWICMetadataQueryReader> reader;
        if (FAILED(frame->GetMetadataQueryReader(&reader)) || !reader)
            return 100;

        PROPVARIANT value{};
        PropVariantInit(&value);

        UINT delayHundredths = 10;
        if (SUCCEEDED(reader->GetMetadataByName(L"/grctlext/Delay", &value)))
        {
            if (value.vt == VT_UI2)
                delayHundredths = value.uiVal;
            else if (value.vt == VT_UI4)
                delayHundredths = value.ulVal;
        }

        PropVariantClear(&value);

        return std::clamp<UINT>(
            delayHundredths ? delayHundredths * 10u : 100u,
            20u,
            2000u);
    }

    bool ConvertFrameToRGBA(
        IWICImagingFactory* factory,
        IWICBitmapFrameDecode* frame,
        UINT width,
        UINT height,
        RgbaImage& image)
    {
        if (!factory || !frame)
            return false;

        ComPtr<IWICBitmapScaler> scaler;
        ComPtr<IWICFormatConverter> converter;

        HRESULT hr = factory->CreateBitmapScaler(&scaler);
        if (SUCCEEDED(hr))
        {
            hr = scaler->Initialize(
                frame,
                width,
                height,
                WICBitmapInterpolationModeFant);
        }

        if (SUCCEEDED(hr))
            hr = factory->CreateFormatConverter(&converter);

        if (SUCCEEDED(hr))
        {
            hr = converter->Initialize(
                scaler.Get(),
                GUID_WICPixelFormat32bppRGBA,
                WICBitmapDitherTypeNone,
                nullptr,
                0.0,
                WICBitmapPaletteTypeCustom);
        }

        if (FAILED(hr))
            return false;

        image.width = width;
        image.height = height;

        const UINT stride = width * 4;
        image.pixels.resize(
            static_cast<std::size_t>(stride) * height);

        hr = converter->CopyPixels(
            nullptr,
            stride,
            static_cast<UINT>(image.pixels.size()),
            image.pixels.data());

        return SUCCEEDED(hr);
    }


    bool IsPngPath(const std::string& path)
    {
        const auto dot =
            path.find_last_of('.');

        if (dot == std::string::npos)
            return false;

        std::string ext =
            path.substr(dot);

        std::transform(
            ext.begin(),
            ext.end(),
            ext.begin(),
            [](unsigned char c)
            {
                return static_cast<char>(
                    std::tolower(c));
            });

        return ext == ".png";
    }

    std::string SiblingAnimationJson(
        const std::string& imagePath)
    {
        std::filesystem::path p(
            imagePath);

        return
            (p.parent_path() /
             "animation.json").string();
    }

    bool ReadSmallTextFile(
        const std::string& path,
        std::string& text)
    {
        text.clear();

        std::ifstream file(
            path,
            std::ios::binary);

        if (!file)
            return false;

        file.seekg(
            0,
            std::ios::end);

        const auto size =
            file.tellg();

        if (size <= 0 ||
            size >
                static_cast<std::streamoff>(
                    1024 * 1024))
        {
            return false;
        }

        file.seekg(
            0,
            std::ios::beg);

        text.resize(
            static_cast<std::size_t>(
                size));

        file.read(
            text.data(),
            size);

        return
            static_cast<bool>(file);
    }

    bool ParseJsonFloatPairAfter(
        const std::string& text,
        std::size_t start,
        const char* key,
        float& x,
        float& y)
    {
        const std::string quoted =
            std::string("\"") +
            key +
            "\"";

        const auto keyPos =
            text.find(
                quoted,
                start);

        if (keyPos ==
            std::string::npos)
        {
            return false;
        }

        const auto bracket =
            text.find(
                '[',
                keyPos +
                quoted.size());

        if (bracket ==
            std::string::npos)
        {
            return false;
        }

        const char* begin =
            text.c_str() +
            bracket +
            1;

        char* end = nullptr;

        const float a =
            std::strtof(
                begin,
                &end);

        if (!end ||
            end == begin)
        {
            return false;
        }

        while (*end &&
               (*end == ' ' ||
                *end == '\t' ||
                *end == '\r' ||
                *end == '\n' ||
                *end == ','))
        {
            ++end;
        }

        char* end2 = nullptr;

        const float b =
            std::strtof(
                end,
                &end2);

        if (!end2 ||
            end2 == end)
        {
            return false;
        }

        x = a;
        y = b;
        return true;
    }

    bool ReadLevel0Scroll(
        const std::string& imagePath,
        float& scrollX,
        float& scrollY,
        std::string& animationPath)
    {
        scrollX = 0.0f;
        scrollY = 0.0f;

        animationPath =
            SiblingAnimationJson(
                imagePath);

        std::string json;

        if (!ReadSmallTextFile(
                animationPath,
                json))
        {
            return false;
        }

        // Prefer level0.scroll, matching layer0_color.png.
        const auto level0 =
            json.find("\"level0\"");

        if (level0 !=
            std::string::npos &&
            ParseJsonFloatPairAfter(
                json,
                level0,
                "scroll",
                scrollX,
                scrollY))
        {
            return true;
        }

        // Compatibility: if no level0 object exists, use first scroll pair.
        return ParseJsonFloatPairAfter(
            json,
            0,
            "scroll",
            scrollX,
            scrollY);
    }

    RgbaImage ScrollWrapped(
        const RgbaImage& source,
        int offsetX,
        int offsetY)
    {
        RgbaImage result{};

        result.width =
            source.width;

        result.height =
            source.height;

        result.pixels.resize(
            source.pixels.size());

        if (!source.width ||
            !source.height ||
            source.pixels.empty())
        {
            return result;
        }

        const int width =
            static_cast<int>(
                source.width);

        const int height =
            static_cast<int>(
                source.height);

        auto wrap =
            [](int value,
               int limit)
            {
                value %= limit;

                if (value < 0)
                    value += limit;

                return value;
            };

        for (int y = 0;
             y < height;
             ++y)
        {
            const int sy =
                wrap(
                    y - offsetY,
                    height);

            for (int x = 0;
                 x < width;
                 ++x)
            {
                const int sx =
                    wrap(
                        x - offsetX,
                        width);

                const auto src =
                    (static_cast<std::size_t>(
                         sy) *
                         source.width +
                     static_cast<std::size_t>(
                         sx)) *
                    4;

                const auto dst =
                    (static_cast<std::size_t>(
                         y) *
                         source.width +
                     static_cast<std::size_t>(
                         x)) *
                    4;

                std::memcpy(
                    result.pixels.data() +
                        dst,
                    source.pixels.data() +
                        src,
                    4);
            }
        }

        return result;
    }

    void BuildPngScrollAnimation(
        const std::string& imagePath,
        std::vector<DecodedFrame>& frames)
    {
        if (!IsPngPath(
                imagePath) ||
            frames.size() != 1)
        {
            return;
        }

        float scrollX = 0.0f;
        float scrollY = 0.0f;
        std::string animationPath;

        if (!ReadLevel0Scroll(
                imagePath,
                scrollX,
                scrollY,
                animationPath))
        {
            return;
        }

        const float maxSpeed =
            std::max(
                std::fabs(scrollX),
                std::fabs(scrollY));

        if (!std::isfinite(maxSpeed) ||
            maxSpeed < 0.000001f)
        {
            return;
        }

        // animation.json scroll values are treated as UV movement per
        // ~60-Hz engine tick. Example -0.009 means about 0.54 UV/sec.
        // Render generated frames at 30 FPS and wrap UVs at texture edges.
        constexpr float kSourceTicksPerSecond =
            60.0f;

        constexpr float kAnimationFps =
            30.0f;

        const float periodSeconds =
            std::clamp(
                1.0f /
                    (maxSpeed *
                     kSourceTicksPerSecond),
                0.50f,
                8.0f);

        const UINT frameCount =
            std::clamp<UINT>(
                static_cast<UINT>(
                    std::lround(
                        periodSeconds *
                        kAnimationFps)),
                16,
                120);

        constexpr UINT delayMs =
            33;

        const RgbaImage source =
            frames.front().image;

        std::vector<DecodedFrame> generated;
        generated.reserve(
            frameCount);

        for (UINT i = 0;
             i < frameCount;
             ++i)
        {
            const float timeSeconds =
                static_cast<float>(i) /
                kAnimationFps;

            const float u =
                scrollX *
                kSourceTicksPerSecond *
                timeSeconds;

            const float v =
                scrollY *
                kSourceTicksPerSecond *
                timeSeconds;

            const int pixelX =
                static_cast<int>(
                    std::lround(
                        u *
                        source.width));

            const int pixelY =
                static_cast<int>(
                    std::lround(
                        v *
                        source.height));

            DecodedFrame frame{};

            frame.image =
                ScrollWrapped(
                    source,
                    pixelX,
                    pixelY);

            frame.delayMs =
                delayMs;

            generated.push_back(
                std::move(frame));
        }

        if (!generated.empty())
        {
            frames =
                std::move(generated);

            CreateDirectoryA(
                "logs\\camo\\camo",
                nullptr);

            std::ofstream log(
                "logs\\camo\\custom_camo_png_animation.log",
                std::ios::app);

            if (log)
            {
                log
                    << "image=\""
                    << imagePath
                    << "\" animation=\""
                    << animationPath
                    << "\" level0.scroll=["
                    << scrollX
                    << ','
                    << scrollY
                    << "] frames="
                    << frameCount
                    << " delay_ms="
                    << delayMs
                    << " period_seconds="
                    << periodSeconds
                    << "\n";
            }
        }
    }

    bool DecodeFrames(
        const std::string& path,
        UINT width,
        UINT height,
        std::vector<DecodedFrame>& frames,
        std::string& error)
    {
        frames.clear();

        const HRESULT init =
            CoInitializeEx(nullptr, COINIT_MULTITHREADED);
        const bool shouldUninit = SUCCEEDED(init);

        ComPtr<IWICImagingFactory> factory;
        HRESULT hr = CoCreateInstance(
            CLSID_WICImagingFactory,
            nullptr,
            CLSCTX_INPROC_SERVER,
            IID_PPV_ARGS(&factory));

        if (FAILED(hr))
        {
            if (shouldUninit) CoUninitialize();
            error = "WIC factory creation failed";
            return false;
        }

        std::wstring wide(path.begin(), path.end());

        ComPtr<IWICStream> stream;
        ComPtr<IWICBitmapDecoder> decoder;

        hr = factory->CreateStream(&stream);
        if (SUCCEEDED(hr))
            hr = stream->InitializeFromFilename(wide.c_str(), GENERIC_READ);
        if (SUCCEEDED(hr))
        {
            hr = factory->CreateDecoderFromStream(
                stream.Get(),
                nullptr,
                WICDecodeMetadataCacheOnLoad,
                &decoder);
        }

        if (FAILED(hr) || !decoder)
        {
            if (shouldUninit) CoUninitialize();
            error = "WIC failed to open/decode custom color image";
            return false;
        }

        UINT frameCount = 0;
        if (FAILED(decoder->GetFrameCount(&frameCount)) || frameCount == 0)
            frameCount = 1;

        frameCount = std::min<UINT>(frameCount, 240);

        for (UINT i = 0; i < frameCount; ++i)
        {
            ComPtr<IWICBitmapFrameDecode> frame;
            if (FAILED(decoder->GetFrame(i, &frame)) || !frame)
                continue;

            DecodedFrame decoded{};
            decoded.delayMs = ReadGifDelayMs(frame.Get());

            if (!ConvertFrameToRGBA(
                    factory.Get(),
                    frame.Get(),
                    width,
                    height,
                    decoded.image))
                continue;

            frames.push_back(std::move(decoded));
        }

        if (shouldUninit)
            CoUninitialize();

        if (frames.empty())
        {
            error = "WIC could not decode any custom camo frames";
            return false;
        }

        // A PNG can become animated through sibling animation.json.
        // GIFs remain native multi-frame and are not modified here.
        BuildPngScrollAnimation(
            path,
            frames);

        return true;
    }

    float SrgbToLinear(unsigned char value)
    {
        const float s = static_cast<float>(value) / 255.0f;
        return s <= 0.04045f
            ? s / 12.92f
            : std::pow((s + 0.055f) / 1.055f, 2.4f);
    }

    unsigned char LinearToSrgb(float value)
    {
        value = std::clamp(value, 0.0f, 1.0f);

        const float s = value <= 0.0031308f
            ? value * 12.92f
            : 1.055f * std::pow(value, 1.0f / 2.4f) - 0.055f;

        return static_cast<unsigned char>(
            std::clamp(
                static_cast<int>(std::lround(s * 255.0f)),
                0,
                255));
    }

    RgbaImage Downsample2x(const RgbaImage& source)
    {
        RgbaImage out{};
        out.width = std::max<UINT>(1, source.width / 2);
        out.height = std::max<UINT>(1, source.height / 2);
        out.pixels.resize(
            static_cast<std::size_t>(out.width) * out.height * 4);

        for (UINT y = 0; y < out.height; ++y)
        {
            for (UINT x = 0; x < out.width; ++x)
            {
                float linear[3]{};
                unsigned int alpha = 0;

                for (UINT oy = 0; oy < 2; ++oy)
                {
                    for (UINT ox = 0; ox < 2; ++ox)
                    {
                        const UINT sx =
                            std::min(source.width - 1, x * 2 + ox);
                        const UINT sy =
                            std::min(source.height - 1, y * 2 + oy);

                        const auto index =
                            (static_cast<std::size_t>(sy) *
                                source.width + sx) * 4;

                        linear[0] += SrgbToLinear(source.pixels[index + 0]);
                        linear[1] += SrgbToLinear(source.pixels[index + 1]);
                        linear[2] += SrgbToLinear(source.pixels[index + 2]);
                        alpha += source.pixels[index + 3];
                    }
                }

                const auto dst =
                    (static_cast<std::size_t>(y) * out.width + x) * 4;

                out.pixels[dst + 0] =
                    LinearToSrgb(linear[0] * 0.25f);
                out.pixels[dst + 1] =
                    LinearToSrgb(linear[1] * 0.25f);
                out.pixels[dst + 2] =
                    LinearToSrgb(linear[2] * 0.25f);
                out.pixels[dst + 3] =
                    static_cast<unsigned char>((alpha + 2) / 4);
            }
        }

        return out;
    }


    double FrameDifferenceScore(const RgbaImage& a, const RgbaImage& b)
    {
        if (a.width != b.width || a.height != b.height ||
            a.pixels.size() != b.pixels.size() || a.pixels.empty())
            return 1.0;

        constexpr std::size_t kPixelStep = 16;
        double error = 0.0;
        std::size_t samples = 0;
        const std::size_t pixelCount = a.pixels.size() / 4;

        for (std::size_t p = 0; p < pixelCount; p += kPixelStep)
        {
            const std::size_t i = p * 4;
            for (int c = 0; c < 3; ++c)
            {
                const double d =
                    static_cast<double>(a.pixels[i + c]) -
                    static_cast<double>(b.pixels[i + c]);
                error += d * d;
            }
            ++samples;
        }

        if (!samples)
            return 0.0;

        return std::sqrt(
            error / static_cast<double>(samples * 3)) / 255.0;
    }

    RgbaImage BlendFramesLinear(
        const RgbaImage& from,
        const RgbaImage& to,
        float t)
    {
        RgbaImage out{};
        out.width = from.width;
        out.height = from.height;
        out.pixels.resize(from.pixels.size());
        t = std::clamp(t, 0.0f, 1.0f);

        for (std::size_t i = 0; i + 3 < out.pixels.size(); i += 4)
        {
            for (int c = 0; c < 3; ++c)
            {
                const float a = SrgbToLinear(from.pixels[i + c]);
                const float b = SrgbToLinear(to.pixels[i + c]);
                out.pixels[i + c] =
                    LinearToSrgb(a + (b - a) * t);
            }

            const float alpha =
                static_cast<float>(from.pixels[i + 3]) +
                (static_cast<float>(to.pixels[i + 3]) -
                 static_cast<float>(from.pixels[i + 3])) * t;

            out.pixels[i + 3] =
                static_cast<unsigned char>(
                    std::clamp(
                        static_cast<int>(std::lround(alpha)),
                        0,
                        255));
        }

        return out;
    }

    std::vector<DecodedFrame> BuildSeamlessAnimationFrames(
        const std::vector<DecodedFrame>& source,
        bool& addedTransition,
        double& loopDifference)
    {
        addedTransition = false;
        loopDifference = 0.0;

        if (source.size() <= 1)
            return source;

        std::vector<DecodedFrame> result = source;

        loopDifference =
            FrameDifferenceScore(
                source.back().image,
                source.front().image);

        // Preserve already-seamless source GIFs exactly.
        constexpr double kAlreadySeamlessThreshold = 0.025;
        if (loopDifference <= kAlreadySeamlessThreshold)
            return result;

        // ~96 ms linear-light crossfade removes the visible hard reset.
        constexpr UINT kBridgeFrames = 6;
        constexpr UINT kBridgeDelayMs = 16;

        result.reserve(source.size() + kBridgeFrames);

        for (UINT i = 1; i <= kBridgeFrames; ++i)
        {
            const float t =
                static_cast<float>(i) /
                static_cast<float>(kBridgeFrames + 1);

            DecodedFrame bridge{};
            bridge.image =
                BlendFramesLinear(
                    source.back().image,
                    source.front().image,
                    t);
            bridge.delayMs = kBridgeDelayMs;
            result.push_back(std::move(bridge));
        }

        addedTransition = true;
        return result;
    }

    class BitWriter128
    {
    public:
        void Put(std::uint32_t value, unsigned int bits)
        {
            for (unsigned int i = 0; i < bits; ++i)
            {
                if (value & (1u << i))
                    bytes_[bit_ >> 3] |=
                        static_cast<unsigned char>(1u << (bit_ & 7));
                ++bit_;
            }
        }

        const std::array<unsigned char, 16>& Bytes() const
        {
            return bytes_;
        }

        unsigned int BitsWritten() const
        {
            return bit_;
        }

    private:
        std::array<unsigned char, 16> bytes_{};
        unsigned int bit_ = 0;
    };

    struct Pixel
    {
        int c[4]{};
    };

    int ColorDistance(const Pixel& a, const Pixel& b)
    {
        // Alpha gets slightly less weight because most camo color layers are opaque.
        const int dr = a.c[0] - b.c[0];
        const int dg = a.c[1] - b.c[1];
        const int db = a.c[2] - b.c[2];
        const int da = a.c[3] - b.c[3];
        return dr * dr * 3 + dg * dg * 4 + db * db * 2 + da * da;
    }

    Pixel LerpEndpoint(const Pixel& a, const Pixel& b, int weight)
    {
        Pixel out{};
        for (int c = 0; c < 4; ++c)
        {
            out.c[c] =
                ((64 - weight) * a.c[c] +
                  weight * b.c[c] + 32) >> 6;
        }
        return out;
    }

    void QuantizeMode6Endpoint(const Pixel& in,
                               Pixel& expanded,
                               std::array<unsigned int, 4>& q7,
                               unsigned int& pbit)
    {
        unsigned int ones = 0;
        for (int c = 0; c < 4; ++c)
            ones += static_cast<unsigned int>(in.c[c] & 1);

        pbit = ones >= 2 ? 1u : 0u;

        for (int c = 0; c < 4; ++c)
        {
            int value = in.c[c];
            int q = (value - static_cast<int>(pbit) + 1) / 2;
            q = std::clamp(q, 0, 127);
            q7[c] = static_cast<unsigned int>(q);
            expanded.c[c] =
                static_cast<int>((q7[c] << 1) | pbit);
        }
    }

    void EncodeBC7Mode6Block(
        const unsigned char* rgba,
        UINT stride,
        unsigned char outBlock[16])
    {
        Pixel pixels[16]{};

        for (int y = 0; y < 4; ++y)
        {
            for (int x = 0; x < 4; ++x)
            {
                const auto* src =
                    rgba + static_cast<std::size_t>(y) * stride + x * 4;

                Pixel& p = pixels[y * 4 + x];
                p.c[0] = src[0];
                p.c[1] = src[1];
                p.c[2] = src[2];
                p.c[3] = src[3];
            }
        }

        double mean[4]{};
        for (const auto& p : pixels)
            for (int c = 0; c < 4; ++c)
                mean[c] += p.c[c];

        for (double& value : mean)
            value /= 16.0;

        double covariance[3][3]{};

        for (const auto& p : pixels)
        {
            const double d[3]
            {
                p.c[0] - mean[0],
                p.c[1] - mean[1],
                p.c[2] - mean[2]
            };

            for (int row = 0; row < 3; ++row)
                for (int col = 0; col < 3; ++col)
                    covariance[row][col] += d[row] * d[col];
        }

        double axis[3]{1.0, 1.0, 1.0};

        for (int iteration = 0; iteration < 8; ++iteration)
        {
            double next[3]{};

            for (int row = 0; row < 3; ++row)
            {
                next[row] =
                    covariance[row][0] * axis[0] +
                    covariance[row][1] * axis[1] +
                    covariance[row][2] * axis[2];
            }

            const double length =
                std::sqrt(
                    next[0] * next[0] +
                    next[1] * next[1] +
                    next[2] * next[2]);

            if (length < 1e-8)
                break;

            axis[0] = next[0] / length;
            axis[1] = next[1] / length;
            axis[2] = next[2] / length;
        }

        int minPixel = 0;
        int maxPixel = 0;
        double minProjection =
            std::numeric_limits<double>::max();
        double maxProjection =
            -std::numeric_limits<double>::max();

        for (int i = 0; i < 16; ++i)
        {
            const double projection =
                (pixels[i].c[0] - mean[0]) * axis[0] +
                (pixels[i].c[1] - mean[1]) * axis[1] +
                (pixels[i].c[2] - mean[2]) * axis[2];

            if (projection < minProjection)
            {
                minProjection = projection;
                minPixel = i;
            }

            if (projection > maxProjection)
            {
                maxProjection = projection;
                maxPixel = i;
            }
        }

        Pixel endpoint0 = pixels[minPixel];
        Pixel endpoint1 = pixels[maxPixel];

        static constexpr int kWeights[16]
        {
             0,  4,  9, 13,
            17, 21, 26, 30,
            34, 38, 43, 47,
            51, 55, 60, 64
        };

        unsigned int indices[16]{};

        auto assign =
            [&](Pixel& expanded0,
                Pixel& expanded1,
                std::array<unsigned int, 4>& q0,
                std::array<unsigned int, 4>& q1,
                unsigned int& p0,
                unsigned int& p1)
        {
            QuantizeMode6Endpoint(endpoint0, expanded0, q0, p0);
            QuantizeMode6Endpoint(endpoint1, expanded1, q1, p1);

            for (int i = 0; i < 16; ++i)
            {
                int bestIndex = 0;
                int bestError =
                    std::numeric_limits<int>::max();

                for (int index = 0; index < 16; ++index)
                {
                    const Pixel test =
                        LerpEndpoint(
                            expanded0,
                            expanded1,
                            kWeights[index]);

                    const int error =
                        ColorDistance(pixels[i], test);

                    if (error < bestError)
                    {
                        bestError = error;
                        bestIndex = index;
                    }
                }

                indices[i] =
                    static_cast<unsigned int>(bestIndex);
            }
        };

        // Iteratively refine the endpoint line with least-squares fitting.
        for (int iteration = 0; iteration < 5; ++iteration)
        {
            Pixel expanded0{}, expanded1{};
            std::array<unsigned int, 4> q0{}, q1{};
            unsigned int p0 = 0, p1 = 0;

            assign(expanded0, expanded1, q0, q1, p0, p1);

            double aa = 0.0, ab = 0.0, bb = 0.0;
            double rhsA[4]{};
            double rhsB[4]{};

            for (int i = 0; i < 16; ++i)
            {
                const double t =
                    static_cast<double>(
                        kWeights[indices[i]]) / 64.0;

                const double a = 1.0 - t;
                const double b = t;

                aa += a * a;
                ab += a * b;
                bb += b * b;

                for (int c = 0; c < 4; ++c)
                {
                    rhsA[c] += a * pixels[i].c[c];
                    rhsB[c] += b * pixels[i].c[c];
                }
            }

            const double determinant =
                aa * bb - ab * ab;

            if (std::abs(determinant) < 1e-8)
                break;

            for (int c = 0; c < 4; ++c)
            {
                const double aValue =
                    (rhsA[c] * bb - rhsB[c] * ab) /
                    determinant;

                const double bValue =
                    (rhsB[c] * aa - rhsA[c] * ab) /
                    determinant;

                endpoint0.c[c] =
                    std::clamp(
                        static_cast<int>(std::lround(aValue)),
                        0,
                        255);

                endpoint1.c[c] =
                    std::clamp(
                        static_cast<int>(std::lround(bValue)),
                        0,
                        255);
            }
        }

        Pixel expanded0{}, expanded1{};
        std::array<unsigned int, 4> q0{}, q1{};
        unsigned int p0 = 0, p1 = 0;

        assign(expanded0, expanded1, q0, q1, p0, p1);

        if (indices[0] >= 8)
        {
            std::swap(expanded0, expanded1);
            std::swap(q0, q1);
            std::swap(p0, p1);

            for (auto& index : indices)
                index = 15u - index;
        }

        BitWriter128 writer;
        writer.Put(0x40u, 7);

        writer.Put(q0[0], 7);
        writer.Put(q1[0], 7);
        writer.Put(q0[1], 7);
        writer.Put(q1[1], 7);
        writer.Put(q0[2], 7);
        writer.Put(q1[2], 7);
        writer.Put(q0[3], 7);
        writer.Put(q1[3], 7);

        writer.Put(p0, 1);
        writer.Put(p1, 1);

        writer.Put(indices[0], 3);
        for (int i = 1; i < 16; ++i)
            writer.Put(indices[i], 4);

        const auto& bytes = writer.Bytes();
        std::memcpy(outBlock, bytes.data(), 16);
    }

    std::vector<unsigned char> CompressBC7Mode6(const RgbaImage& image)
    {
        const UINT blockWidth =
            (image.width + 3) / 4;

        const UINT blockHeight =
            (image.height + 3) / 4;

        std::vector<unsigned char> compressed(
            static_cast<std::size_t>(blockWidth) *
            blockHeight *
            16);

        unsigned int hardwareThreads =
            std::thread::hardware_concurrency();

        if (hardwareThreads == 0)
            hardwareThreads = 4;

        // Do not peg every logical CPU during a large animated cache build.
        // Leave two logical processors free and cap worker fan-out at 8.
        unsigned int threadCount =
            hardwareThreads > 2
            ? hardwareThreads - 2
            : 1;

        threadCount =
            std::min<unsigned int>(
                threadCount,
                g_backgroundPrecacheMode ? 2u : 8u);

        threadCount =
            std::clamp<unsigned int>(
                threadCount,
                1,
                std::max<UINT>(1, blockHeight));

        // Tiny mips are faster without thread startup overhead.
        if (blockHeight < 16)
            threadCount = 1;

        auto encodeRows =
            [&](UINT firstRow, UINT lastRow)
            {
                unsigned char tile[4 * 4 * 4]{};

                for (UINT by = firstRow;
                     by < lastRow;
                     ++by)
                {
                    for (UINT bx = 0;
                         bx < blockWidth;
                         ++bx)
                    {
                        for (UINT y = 0; y < 4; ++y)
                        {
                            for (UINT x = 0; x < 4; ++x)
                            {
                                const UINT sx =
                                    std::min(
                                        image.width - 1,
                                        bx * 4 + x);

                                const UINT sy =
                                    std::min(
                                        image.height - 1,
                                        by * 4 + y);

                                const auto source =
                                    (static_cast<std::size_t>(sy) *
                                        image.width + sx) * 4;

                                const auto destination =
                                    (static_cast<std::size_t>(y) *
                                        4 + x) * 4;

                                std::memcpy(
                                    tile + destination,
                                    image.pixels.data() + source,
                                    4);
                            }
                        }

                        unsigned char* block =
                            compressed.data() +
                            (static_cast<std::size_t>(by) *
                                blockWidth + bx) * 16;

                        EncodeBC7Mode6Block(
                            tile,
                            4 * 4,
                            block);
                    }
                }
            };

        if (threadCount == 1)
        {
            encodeRows(0, blockHeight);
            return compressed;
        }

        std::vector<std::thread> workers;
        workers.reserve(threadCount);

        UINT nextRow = 0;

        for (unsigned int i = 0;
             i < threadCount;
             ++i)
        {
            const UINT rowsRemaining =
                blockHeight - nextRow;

            const UINT workersRemaining =
                threadCount - i;

            const UINT rows =
                (rowsRemaining +
                 workersRemaining - 1) /
                workersRemaining;

            const UINT begin = nextRow;
            const UINT finish =
                std::min(blockHeight, begin + rows);

            nextRow = finish;

            workers.emplace_back(
                encodeRows,
                begin,
                finish);
        }

        for (auto& worker : workers)
            worker.join();

        return compressed;
    }


    bool CreateBuffer(ID3D12Device* device,
                      UINT64 bytes,
                      D3D12_HEAP_TYPE type,
                      ComPtr<ID3D12Resource>& out)
    {
        D3D12_HEAP_PROPERTIES heap{};
        heap.Type = type;

        D3D12_RESOURCE_DESC desc{};
        desc.Dimension = D3D12_RESOURCE_DIMENSION_BUFFER;
        desc.Width = bytes;
        desc.Height = 1;
        desc.DepthOrArraySize = 1;
        desc.MipLevels = 1;
        desc.Format = DXGI_FORMAT_UNKNOWN;
        desc.SampleDesc.Count = 1;
        desc.Layout = D3D12_TEXTURE_LAYOUT_ROW_MAJOR;

        const auto state =
            type == D3D12_HEAP_TYPE_UPLOAD
            ? D3D12_RESOURCE_STATE_GENERIC_READ
            : D3D12_RESOURCE_STATE_COPY_DEST;

        return SUCCEEDED(
            device->CreateCommittedResource(
                &heap,
                D3D12_HEAP_FLAG_NONE,
                &desc,
                state,
                nullptr,
                IID_PPV_ARGS(&out)));
    }

    bool BuildLayouts(ID3D12Device* device,
                      const D3D12_RESOURCE_DESC& desc,
                      UINT mipCount,
                      std::vector<SubresourceLayout>& layouts,
                      UINT64& totalBytes)
    {
        layouts.resize(mipCount);

        std::vector<D3D12_PLACED_SUBRESOURCE_FOOTPRINT> footprints(mipCount);
        std::vector<UINT> rows(mipCount);
        std::vector<UINT64> rowBytes(mipCount);

        device->GetCopyableFootprints(
            &desc,
            0,
            mipCount,
            0,
            footprints.data(),
            rows.data(),
            rowBytes.data(),
            &totalBytes);

        for (UINT i = 0; i < mipCount; ++i)
        {
            layouts[i].footprint = footprints[i];
            layouts[i].rows = rows[i];
            layouts[i].rowBytes = rowBytes[i];
        }

        return totalBytes != 0;
    }

    bool RunCopies(ID3D12Device* device,
                   ID3D12CommandQueue* queue,
                   ID3D12Resource* texture,
                   const std::vector<SubresourceLayout>& layouts,
                   ID3D12Resource* buffer,
                   bool upload,
                   std::string& error)
    {
        ComPtr<ID3D12CommandAllocator> allocator;
        ComPtr<ID3D12GraphicsCommandList> list;
        ComPtr<ID3D12Fence> fence;

        if (FAILED(device->CreateCommandAllocator(
                D3D12_COMMAND_LIST_TYPE_DIRECT,
                IID_PPV_ARGS(&allocator))) ||
            FAILED(device->CreateCommandList(
                0,
                D3D12_COMMAND_LIST_TYPE_DIRECT,
                allocator.Get(),
                nullptr,
                IID_PPV_ARGS(&list))) ||
            FAILED(device->CreateFence(
                0,
                D3D12_FENCE_FLAG_NONE,
                IID_PPV_ARGS(&fence))))
        {
            error = "DX12 command object creation failed";
            return false;
        }

        const auto shaderState =
            static_cast<D3D12_RESOURCE_STATES>(
                D3D12_RESOURCE_STATE_PIXEL_SHADER_RESOURCE |
                D3D12_RESOURCE_STATE_NON_PIXEL_SHADER_RESOURCE);

        D3D12_RESOURCE_BARRIER before{};
        before.Type = D3D12_RESOURCE_BARRIER_TYPE_TRANSITION;
        before.Transition.pResource = texture;
        before.Transition.Subresource =
            D3D12_RESOURCE_BARRIER_ALL_SUBRESOURCES;
        before.Transition.StateBefore = shaderState;
        before.Transition.StateAfter =
            upload
            ? D3D12_RESOURCE_STATE_COPY_DEST
            : D3D12_RESOURCE_STATE_COPY_SOURCE;

        list->ResourceBarrier(1, &before);

        for (UINT mip = 0;
             mip < static_cast<UINT>(layouts.size());
             ++mip)
        {
            D3D12_TEXTURE_COPY_LOCATION textureLocation{};
            textureLocation.pResource = texture;
            textureLocation.Type =
                D3D12_TEXTURE_COPY_TYPE_SUBRESOURCE_INDEX;
            textureLocation.SubresourceIndex = mip;

            D3D12_TEXTURE_COPY_LOCATION bufferLocation{};
            bufferLocation.pResource = buffer;
            bufferLocation.Type =
                D3D12_TEXTURE_COPY_TYPE_PLACED_FOOTPRINT;
            bufferLocation.PlacedFootprint =
                layouts[mip].footprint;

            if (upload)
            {
                list->CopyTextureRegion(
                    &textureLocation,
                    0, 0, 0,
                    &bufferLocation,
                    nullptr);
            }
            else
            {
                list->CopyTextureRegion(
                    &bufferLocation,
                    0, 0, 0,
                    &textureLocation,
                    nullptr);
            }
        }

        D3D12_RESOURCE_BARRIER after = before;
        std::swap(
            after.Transition.StateBefore,
            after.Transition.StateAfter);
        list->ResourceBarrier(1, &after);

        if (FAILED(list->Close()))
        {
            error = "DX12 command list close failed";
            return false;
        }

        ID3D12CommandList* lists[] = { list.Get() };
        queue->ExecuteCommandLists(1, lists);

        HANDLE eventHandle =
            CreateEventW(nullptr, FALSE, FALSE, nullptr);
        if (!eventHandle)
        {
            error = "DX12 fence event creation failed";
            return false;
        }

        constexpr UINT64 fenceValue = 1;
        HRESULT hr =
            queue->Signal(fence.Get(), fenceValue);

        if (SUCCEEDED(hr) &&
            fence->GetCompletedValue() < fenceValue)
        {
            hr = fence->SetEventOnCompletion(
                fenceValue, eventHandle);

            if (SUCCEEDED(hr))
                WaitForSingleObject(eventHandle, 5000);
        }

        CloseHandle(eventHandle);

        if (FAILED(hr) ||
            fence->GetCompletedValue() < fenceValue)
        {
            error = "DX12 texture copy timed out";
            return false;
        }

        camo_allocator_trace::NotifyImageReady();
    return true;
    }

    bool BackupTexture(ID3D12Device* device,
                       ID3D12CommandQueue* queue,
                       ID3D12Resource* texture,
                       UINT mipCount,
                       TextureBackup& backup,
                       std::string& error)
    {
        backup.resource = texture;
        backup.desc = texture->GetDesc();

        if (!BuildLayouts(
                device,
                backup.desc,
                mipCount,
                backup.layouts,
                backup.totalBytes))
        {
            error = "could not calculate texture copy footprints";
            return false;
        }

        ComPtr<ID3D12Resource> readback;
        if (!CreateBuffer(
                device,
                backup.totalBytes,
                D3D12_HEAP_TYPE_READBACK,
                readback))
        {
            error = "readback allocation failed";
            return false;
        }

        if (!RunCopies(
                device,
                queue,
                texture,
                backup.layouts,
                readback.Get(),
                false,
                error))
            return false;

        void* mapped = nullptr;
        D3D12_RANGE readRange{
            0,
            static_cast<SIZE_T>(backup.totalBytes)
        };

        if (FAILED(readback->Map(
                0, &readRange, &mapped)) ||
            !mapped)
        {
            error = "readback map failed";
            return false;
        }

        backup.bytes.resize(
            static_cast<std::size_t>(backup.totalBytes));
        std::memcpy(
            backup.bytes.data(),
            mapped,
            backup.bytes.size());

        D3D12_RANGE noWrite{0, 0};
        readback->Unmap(0, &noWrite);
        return true;
    }

    bool UploadPreparedBuffer(
        ID3D12Device* device,
        ID3D12CommandQueue* queue,
        ID3D12Resource* texture,
        const std::vector<SubresourceLayout>& layouts,
        UINT64 totalBytes,
        const std::vector<std::vector<unsigned char>>& mipData,
        std::string& error)
    {
        if (layouts.size() != mipData.size())
        {
            error = "mip layout/data count mismatch";
            return false;
        }

        ComPtr<ID3D12Resource> upload;
        if (!CreateBuffer(
                device,
                totalBytes,
                D3D12_HEAP_TYPE_UPLOAD,
                upload))
        {
            error = "upload buffer allocation failed";
            return false;
        }

        unsigned char* mapped = nullptr;
        D3D12_RANGE noRead{0, 0};

        if (FAILED(upload->Map(
                0,
                &noRead,
                reinterpret_cast<void**>(&mapped))) ||
            !mapped)
        {
            error = "upload buffer map failed";
            return false;
        }

        std::memset(
            mapped,
            0,
            static_cast<std::size_t>(totalBytes));

        for (std::size_t mip = 0;
             mip < layouts.size();
             ++mip)
        {
            const auto& layout = layouts[mip];
            const auto& source = mipData[mip];

            const UINT rows = layout.rows;
            const UINT64 sourceRowBytes = layout.rowBytes;
            const UINT destinationPitch =
                layout.footprint.Footprint.RowPitch;

            const UINT64 required =
                sourceRowBytes * rows;

            if (source.size() < required)
            {
                upload->Unmap(0, nullptr);
                error = "BC7 mip byte count is smaller than its footprint";
                return false;
            }

            unsigned char* destination =
                mapped + layout.footprint.Offset;

            for (UINT row = 0; row < rows; ++row)
            {
                std::memcpy(
                    destination +
                        static_cast<std::size_t>(row) * destinationPitch,
                    source.data() +
                        static_cast<std::size_t>(row) * sourceRowBytes,
                    static_cast<std::size_t>(sourceRowBytes));
            }
        }

        upload->Unmap(0, nullptr);

        return RunCopies(
            device,
            queue,
            texture,
            layouts,
            upload.Get(),
            true,
            error);
    }

    bool RestoreBackup(ID3D12Device* device,
                       ID3D12CommandQueue* queue,
                       TextureBackup& backup,
                       std::string& error)
    {
        ComPtr<ID3D12Resource> upload;
        if (!CreateBuffer(
                device,
                backup.totalBytes,
                D3D12_HEAP_TYPE_UPLOAD,
                upload))
        {
            error = "restore upload allocation failed";
            return false;
        }

        void* mapped = nullptr;
        D3D12_RANGE noRead{0, 0};

        if (FAILED(upload->Map(0, &noRead, &mapped)) ||
            !mapped)
        {
            error = "restore upload map failed";
            return false;
        }

        std::memcpy(
            mapped,
            backup.bytes.data(),
            backup.bytes.size());

        upload->Unmap(0, nullptr);

        return RunCopies(
            device,
            queue,
            backup.resource.Get(),
            backup.layouts,
            upload.Get(),
            true,
            error);
    }

    std::vector<std::vector<unsigned char>>
    BuildBC7MipChain(const RgbaImage& base, UINT mipCount)
    {
        std::vector<std::vector<unsigned char>> result;
        result.reserve(mipCount);

        RgbaImage current = base;

        for (UINT mip = 0; mip < mipCount; ++mip)
        {
            result.push_back(
                CompressBC7Mode6(current));

            if (mip + 1 < mipCount)
                current = Downsample2x(current);
        }

        return result;
    }
    std::uint64_t HashBytesFNV1a64(
        std::uint64_t hash,
        const unsigned char* bytes,
        std::size_t count)
    {
        constexpr std::uint64_t kPrime =
            1099511628211ull;

        for (std::size_t i = 0;
             i < count;
             ++i)
        {
            hash ^= bytes[i];
            hash *= kPrime;
        }

        return hash;
    }

    bool HashFileIntoFNV1a64(
        const std::string& path,
        std::uint64_t& hash)
    {
        std::ifstream file(
            path,
            std::ios::binary);

        if (!file)
            return false;

        std::array<char, 64 * 1024> buffer{};

        while (file)
        {
            file.read(
                buffer.data(),
                static_cast<std::streamsize>(
                    buffer.size()));

            const auto count =
                file.gcount();

            if (count > 0)
            {
                hash =
                    HashBytesFNV1a64(
                        hash,
                        reinterpret_cast<
                            const unsigned char*>(
                            buffer.data()),
                        static_cast<std::size_t>(
                            count));
            }
        }

        return true;
    }

    std::uint64_t HashFileFNV1a64(
        const std::string& path)
    {
        constexpr std::uint64_t kOffset =
            14695981039346656037ull;

        std::uint64_t hash =
            kOffset;

        if (!HashFileIntoFNV1a64(
                path,
                hash))
        {
            return 0;
        }

        // PNG animation is data-driven. Include animation.json in the cache
        // identity so editing scroll values automatically rebuilds caches.
        if (IsPngPath(path))
        {
            const std::string animation =
                SiblingAnimationJson(
                    path);

            const DWORD attrs =
                GetFileAttributesA(
                    animation.c_str());

            if (attrs !=
                    INVALID_FILE_ATTRIBUTES &&
                !(attrs &
                  FILE_ATTRIBUTE_DIRECTORY))
            {
                static constexpr
                    unsigned char separator[] =
                    {
                        0x00, 'A', 'N', 'I', 'M',
                        0x00
                    };

                hash =
                    HashBytesFNV1a64(
                        hash,
                        separator,
                        sizeof(separator));

                HashFileIntoFNV1a64(
                    animation,
                    hash);
            }
        }

        return hash;
    }

    std::string CacheSafeName(std::string value)
    {
        for (char& c : value)
        {
            const unsigned char u =
                static_cast<unsigned char>(c);

            if (!std::isalnum(u) &&
                c != '-' &&
                c != '_' &&
                c != '.')
            {
                c = '_';
            }
        }

        if (value.empty())
            value = "camo";

        return value;
    }

    std::string CachePathFor(
        const std::string& colorPath,
        UINT width,
        UINT height,
        UINT mipCount,
        std::uint64_t hash)
    {
        std::filesystem::path source(colorPath);

        std::string folder =
            source.parent_path().filename().string();

        folder =
            CacheSafeName(folder);

        char exePath[MAX_PATH]{};

        std::filesystem::path root;

        if (GetModuleFileNameA(
                nullptr,
                exePath,
                MAX_PATH))
        {
            root =
                std::filesystem::path(exePath)
                    .parent_path();
        }
        else
        {
            root =
                std::filesystem::current_path();
        }

        root /=
            std::filesystem::path("cache") /
            "camos" /
            folder;

        std::error_code ec;
        std::filesystem::create_directories(
            root,
            ec);

        std::ostringstream name;

        name
            << width
            << 'x'
            << height
            << "_m"
            << mipCount
            << "_"
            << std::hex
            << std::uppercase
            << hash
            << ".bc7cache";

        return
            (root / name.str()).string();
    }

#pragma pack(push, 1)
    struct CacheHeader
    {
        char magic[8];
        std::uint32_t version;
        std::uint32_t width;
        std::uint32_t height;
        std::uint32_t mipCount;
        std::uint32_t frameCount;
        std::uint64_t sourceHash;
    };
#pragma pack(pop)

    bool LoadFrameCache(
        const std::string& path,
        UINT width,
        UINT height,
        UINT mipCount,
        std::uint64_t sourceHash,
        std::vector<CachedFrame>& frames)
    {
        frames.clear();

        std::ifstream file(
            path,
            std::ios::binary);

        if (!file)
            return false;

        CacheHeader header{};

        if (!file.read(
                reinterpret_cast<char*>(&header),
                sizeof(header)))
            return false;

        static constexpr char kMagic[8] =
            {'T','9','B','C','7','C','2','\0'};

        if (std::memcmp(
                header.magic,
                kMagic,
                sizeof(kMagic)) != 0 ||
            header.version != 2 ||
            header.width != width ||
            header.height != height ||
            header.mipCount != mipCount ||
            header.sourceHash != sourceHash ||
            header.frameCount == 0 ||
            header.frameCount > 512)
        {
            return false;
        }

        frames.resize(
            header.frameCount);

        for (auto& frame : frames)
        {
            std::uint32_t delay = 0;
            std::uint32_t storedMips = 0;

            if (!file.read(
                    reinterpret_cast<char*>(&delay),
                    sizeof(delay)) ||
                !file.read(
                    reinterpret_cast<char*>(&storedMips),
                    sizeof(storedMips)) ||
                storedMips != mipCount)
            {
                frames.clear();
                return false;
            }

            frame.delayMs =
                delay;

            frame.mipData.resize(
                storedMips);

            for (auto& mip :
                 frame.mipData)
            {
                std::uint64_t size = 0;

                if (!file.read(
                        reinterpret_cast<char*>(&size),
                        sizeof(size)) ||
                    size == 0 ||
                    size > (256ull * 1024ull * 1024ull))
                {
                    frames.clear();
                    return false;
                }

                mip.resize(
                    static_cast<std::size_t>(size));

                if (!file.read(
                        reinterpret_cast<char*>(
                            mip.data()),
                        static_cast<std::streamsize>(
                            mip.size())))
                {
                    frames.clear();
                    return false;
                }
            }
        }

        return true;
    }

    bool SaveFrameCache(
        const std::string& path,
        UINT width,
        UINT height,
        UINT mipCount,
        std::uint64_t sourceHash,
        const std::vector<CachedFrame>& frames)
    {
        if (frames.empty())
            return false;

        const std::string temp =
            path + ".tmp";

        std::ofstream file(
            temp,
            std::ios::binary |
            std::ios::trunc);

        if (!file)
            return false;

        CacheHeader header{};

        static constexpr char kMagic[8] =
            {'T','9','B','C','7','C','2','\0'};

        std::memcpy(
            header.magic,
            kMagic,
            sizeof(kMagic));

        header.version = 2;
        header.width = width;
        header.height = height;
        header.mipCount = mipCount;
        header.frameCount =
            static_cast<std::uint32_t>(
                frames.size());
        header.sourceHash =
            sourceHash;

        file.write(
            reinterpret_cast<const char*>(&header),
            sizeof(header));

        for (const auto& frame :
             frames)
        {
            const std::uint32_t delay =
                frame.delayMs;

            const std::uint32_t storedMips =
                static_cast<std::uint32_t>(
                    frame.mipData.size());

            file.write(
                reinterpret_cast<const char*>(&delay),
                sizeof(delay));

            file.write(
                reinterpret_cast<const char*>(&storedMips),
                sizeof(storedMips));

            for (const auto& mip :
                 frame.mipData)
            {
                const std::uint64_t size =
                    static_cast<std::uint64_t>(
                        mip.size());

                file.write(
                    reinterpret_cast<const char*>(&size),
                    sizeof(size));

                file.write(
                    reinterpret_cast<const char*>(
                        mip.data()),
                    static_cast<std::streamsize>(
                        mip.size()));
            }
        }

        file.close();

        if (!file)
        {
            DeleteFileA(temp.c_str());
            return false;
        }

        DeleteFileA(path.c_str());

        if (!MoveFileA(
                temp.c_str(),
                path.c_str()))
        {
            DeleteFileA(temp.c_str());
            return false;
        }

        return true;
    }


    bool FrameCacheExists(
        const std::string& colorPath,
        UINT width,
        UINT height,
        UINT mipCount,
        std::string* pathOut = nullptr)
    {
        const std::uint64_t sourceHash =
            HashFileFNV1a64(colorPath);

        if (!sourceHash)
            return false;

        const std::string path =
            CachePathFor(
                colorPath,
                width,
                height,
                mipCount,
                sourceHash);

        if (pathOut)
            *pathOut = path;

        const DWORD attributes =
            GetFileAttributesA(path.c_str());

        return attributes != INVALID_FILE_ATTRIBUTES &&
               !(attributes & FILE_ATTRIBUTE_DIRECTORY);
    }

    UINT ExpectedMipCount(UINT size)
    {
        switch (size)
        {
        case 256:  return 4;
        case 512:  return 5;
        case 1024: return 6;
        case 2048: return 7;
        default:
        {
            UINT mips = 1;
            UINT value = size;

            while (value > 32)
            {
                value >>= 1;
                ++mips;
            }

            return mips;
        }
        }
    }

    bool LoadOrBuildFrameCache(
        const std::string& colorPath,
        UINT width,
        UINT height,
        UINT mipCount,
        std::vector<CachedFrame>& frames,
        bool& cacheHit,
        std::string& error)
    {
        cacheHit = false;
        frames.clear();

        const std::uint64_t sourceHash =
            HashFileFNV1a64(colorPath);

        if (!sourceHash)
        {
            error =
                "could not hash custom camo image";
            return false;
        }

        const std::string cachePath =
            CachePathFor(
                colorPath,
                width,
                height,
                mipCount,
                sourceHash);

        if (LoadFrameCache(
                cachePath,
                width,
                height,
                mipCount,
                sourceHash,
                frames))
        {
            cacheHit = true;

            CreateDirectoryA("logs\\camo\\camo", nullptr);
            std::ofstream log(
                "logs\\camo\\custom_camo_cache.log",
                std::ios::app);

            if (log)
            {
                log
                    << "HIT path=\""
                    << cachePath
                    << "\" size="
                    << width
                    << 'x'
                    << height
                    << " mips="
                    << mipCount
                    << " frames="
                    << frames.size()
                    << "\n";
            }

            return true;
        }

        std::vector<DecodedFrame> decoded;

        if (!DecodeFrames(
                colorPath,
                width,
                height,
                decoded,
                error))
        {
            return false;
        }

        bool addedLoopTransition = false;
        double loopDifference = 0.0;

        const auto animationFrames =
            BuildSeamlessAnimationFrames(
                decoded,
                addedLoopTransition,
                loopDifference);

        frames.resize(
            animationFrames.size());

        // Frames are independent too. Keep one level of parallelism here only
        // for small frame counts; BC7 block rows already use all CPU cores.
        for (std::size_t i = 0;
             i < animationFrames.size();
             ++i)
        {
            frames[i].delayMs =
                animationFrames[i].delayMs;

            frames[i].mipData =
                BuildBC7MipChain(
                    animationFrames[i].image,
                    mipCount);
        }

        SaveFrameCache(
            cachePath,
            width,
            height,
            mipCount,
            sourceHash,
            frames);

        CreateDirectoryA("logs\\camo\\camo", nullptr);
        std::ofstream log(
            "logs\\camo\\custom_camo_cache.log",
            std::ios::app);

        if (log)
        {
            log
                << "BUILD path=\""
                << cachePath
                << "\" size="
                << width
                << 'x'
                << height
                << " mips="
                << mipCount
                << " frames="
                << frames.size()
                << " loop_transition="
                << (addedLoopTransition ? 1 : 0)
                << "\n";
        }

        return true;
    }


    bool PrepareUploadFrame(
        ID3D12Device* device,
        const std::vector<SubresourceLayout>& layouts,
        UINT64 totalBytes,
        const std::vector<std::vector<unsigned char>>& mipData,
        UINT delayMs,
        PreparedFrame& prepared,
        std::string& error)
    {
        if (layouts.size() != mipData.size())
        {
            error = "animation mip layout/data count mismatch";
            return false;
        }

        if (!CreateBuffer(
                device,
                totalBytes,
                D3D12_HEAP_TYPE_UPLOAD,
                prepared.upload))
        {
            error = "animation upload buffer allocation failed";
            return false;
        }

        unsigned char* mapped = nullptr;
        D3D12_RANGE noRead{0, 0};

        if (FAILED(prepared.upload->Map(
                0,
                &noRead,
                reinterpret_cast<void**>(&mapped))) ||
            !mapped)
        {
            error = "animation upload buffer map failed";
            return false;
        }

        std::memset(
            mapped,
            0,
            static_cast<std::size_t>(totalBytes));

        for (std::size_t mip = 0; mip < layouts.size(); ++mip)
        {
            const auto& layout = layouts[mip];
            const auto& source = mipData[mip];

            const UINT rows = layout.rows;
            const UINT64 sourceRowBytes = layout.rowBytes;
            const UINT destinationPitch =
                layout.footprint.Footprint.RowPitch;

            if (source.size() < sourceRowBytes * rows)
            {
                prepared.upload->Unmap(0, nullptr);
                error = "animation BC7 mip size mismatch";
                return false;
            }

            unsigned char* destination =
                mapped + layout.footprint.Offset;

            for (UINT row = 0; row < rows; ++row)
            {
                std::memcpy(
                    destination +
                        static_cast<std::size_t>(row) *
                        destinationPitch,
                    source.data() +
                        static_cast<std::size_t>(row) *
                        sourceRowBytes,
                    static_cast<std::size_t>(
                        sourceRowBytes));
            }
        }

        prepared.upload->Unmap(0, nullptr);
        prepared.delayMs = delayMs;
        return true;
    }


    bool SameResourceLayout(const AnimationState& state,
                            ID3D12Resource* resource)
    {
        if (!resource)
            return false;

        const auto desc = resource->GetDesc();

        return state.texture.Get() == resource &&
               state.width == static_cast<UINT>(desc.Width) &&
               state.height == desc.Height &&
               state.mipCount == desc.MipLevels &&
               state.format == desc.Format;
    }


    bool FillReusableUploadBuffer(
        ID3D12Resource* upload,
        const std::vector<SubresourceLayout>& layouts,
        UINT64 totalBytes,
        const CachedFrame& frame,
        std::string& error);

    bool EnsureAnimationUploadBuffer(
        AnimationState& state,
        std::string& error);

    bool PrepareAnimationForResource(
        AnimationState& state,
        ID3D12Resource* resource,
        std::string& error)
    {
        if (!resource)
        {
            error = "resource is null";
            return false;
        }

        const auto desc =
            resource->GetDesc();

        if (!IsSupportedCamoResource(desc))
        {
            error =
                "new texture-quality resource is not a supported BC7 texture";
            return false;
        }

        const UINT width =
            static_cast<UINT>(desc.Width);

        const UINT height =
            desc.Height;

        const UINT mipCount =
            desc.MipLevels;

        std::vector<CachedFrame> cachedFrames;
        bool cacheHit = false;

        if (!LoadOrBuildFrameCache(
                state.colorPath,
                width,
                height,
                mipCount,
                cachedFrames,
                cacheHit,
                error))
        {
            return false;
        }

        TextureBackup backup;

        if (!BackupTexture(
                state.device.Get(),
                state.queue.Get(),
                resource,
                mipCount,
                backup,
                error))
        {
            return false;
        }

        bool alreadyBackedUp = false;

        for (const auto& existing :
             state.backups)
        {
            if (existing.resource.Get() ==
                resource)
            {
                alreadyBackedUp = true;
                break;
            }
        }

        if (!alreadyBackedUp)
            state.backups.push_back(
                std::move(backup));

        state.texture = resource;
        state.width = width;
        state.height = height;
        state.mipCount = mipCount;
        state.format = desc.Format;

        for (const auto& existing :
             state.backups)
        {
            if (existing.resource.Get() ==
                resource)
            {
                state.layouts =
                    existing.layouts;

                state.totalBytes =
                    existing.totalBytes;
                break;
            }
        }

        state.frames =
            std::move(cachedFrames);

        if (!EnsureAnimationUploadBuffer(
                state,
                error))
        {
            return false;
        }

        CreateDirectoryA("logs\\camo\\camo", nullptr);

        std::ofstream quality(
            "logs\\camo\\custom_camo_quality.log",
            std::ios::app);

        if (quality)
        {
            quality
                << "rebound resource="
                << resource
                << " size="
                << width
                << 'x'
                << height
                << " format="
                << FormatName(desc.Format)
                << " mips="
                << mipCount
                << " frames="
                << state.frames.size()
                << " cache="
                << (cacheHit ? "HIT" : "BUILD")
                << "\n";
        }

        return true;
    }



    bool FillReusableUploadBuffer(
        ID3D12Resource* upload,
        const std::vector<SubresourceLayout>& layouts,
        UINT64 totalBytes,
        const CachedFrame& frame,
        std::string& error)
    {
        if (!upload)
        {
            error = "animation upload buffer is null";
            return false;
        }

        if (layouts.size() !=
            frame.mipData.size())
        {
            error =
                "animation mip layout/data count mismatch";
            return false;
        }

        unsigned char* mapped = nullptr;
        D3D12_RANGE noRead{0, 0};

        if (FAILED(upload->Map(
                0,
                &noRead,
                reinterpret_cast<void**>(&mapped))) ||
            !mapped)
        {
            error =
                "animation reusable upload map failed";
            return false;
        }

        std::memset(
            mapped,
            0,
            static_cast<std::size_t>(
                totalBytes));

        for (std::size_t mip = 0;
             mip < layouts.size();
             ++mip)
        {
            const auto& layout =
                layouts[mip];

            const auto& source =
                frame.mipData[mip];

            const UINT rows =
                layout.rows;

            const UINT64 sourceRowBytes =
                layout.rowBytes;

            const UINT destinationPitch =
                layout.footprint.Footprint.RowPitch;

            const UINT64 required =
                sourceRowBytes * rows;

            if (source.size() < required)
            {
                upload->Unmap(0, nullptr);
                error =
                    "cached BC7 mip is smaller than upload footprint";
                return false;
            }

            unsigned char* destination =
                mapped +
                layout.footprint.Offset;

            for (UINT row = 0;
                 row < rows;
                 ++row)
            {
                std::memcpy(
                    destination +
                        static_cast<std::size_t>(
                            row) *
                        destinationPitch,
                    source.data() +
                        static_cast<std::size_t>(
                            row) *
                        sourceRowBytes,
                    static_cast<std::size_t>(
                        sourceRowBytes));
            }
        }

        upload->Unmap(0, nullptr);
        return true;
    }

    bool EnsureAnimationUploadBuffer(
        AnimationState& state,
        std::string& error)
    {
        state.animationUpload.Reset();

        if (!CreateBuffer(
                state.device.Get(),
                state.totalBytes,
                D3D12_HEAP_TYPE_UPLOAD,
                state.animationUpload))
        {
            error =
                "could not allocate reusable animation upload buffer";
            return false;
        }

        return true;
    }

    std::unique_ptr<AnimationState> TakeAnimation(unsigned int camoIndex)
    {
        auto it = g_animations.find(camoIndex);
        if (it == g_animations.end())
            return {};

        auto state = std::move(it->second);
        g_animations.erase(it);

        if (state && state->worker.joinable())
        {
            state->worker.request_stop();
            state->worker.join();
        }

        return state;
    }

    bool StartAnimation(
        unsigned int camoIndex,
        ID3D12Device* device,
        ID3D12CommandQueue* queue,
        ID3D12Resource* texture,
        std::uint64_t gfxImage,
        const std::string& colorPath,
        TextureBackup&& initialBackup,
        std::vector<CachedFrame>&& cachedFrames,
        std::string& error)
    {
        if (cachedFrames.size() <= 1)
            return true;

        auto state =
            std::make_unique<AnimationState>();

        state->device = device;
        state->queue = queue;
        state->texture = texture;
        state->gfxImage = gfxImage;
        state->colorPath = colorPath;

        const auto initialDesc =
            texture->GetDesc();

        state->width =
            static_cast<UINT>(
                initialDesc.Width);

        state->height =
            initialDesc.Height;

        state->mipCount =
            initialDesc.MipLevels;

        state->format =
            initialDesc.Format;

        state->totalBytes =
            initialBackup.totalBytes;

        state->layouts =
            initialBackup.layouts;

        state->backups.push_back(
            std::move(initialBackup));

        // Move the compressed cache into animation state. No second copy.
        state->frames =
            std::move(cachedFrames);

        // Exactly ONE upload resource regardless of frame count/resolution.
        if (!EnsureAnimationUploadBuffer(
                *state,
                error))
        {
            return false;
        }

        CreateDirectoryA(
            "logs\\camo\\camo",
            nullptr);

        {
            std::ofstream memoryLog(
                "logs\\camo\\custom_camo_memory.log",
                std::ios::trunc);

            if (memoryLog)
            {
                std::uint64_t compressedBytes = 0;

                for (const auto& frame :
                     state->frames)
                {
                    for (const auto& mip :
                         frame.mipData)
                    {
                        compressedBytes +=
                            static_cast<std::uint64_t>(
                                mip.size());
                    }
                }

                memoryLog
                    << "frames="
                    << state->frames.size()
                    << "\n"
                    << "resolution="
                    << state->width
                    << 'x'
                    << state->height
                    << "\n"
                    << "mips="
                    << state->mipCount
                    << "\n"
                    << "compressed_frame_bytes="
                    << compressedBytes
                    << "\n"
                    << "d3d12_upload_buffers=1\n"
                    << "upload_buffer_bytes="
                    << state->totalBytes
                    << "\n";
            }
        }

        AnimationState* rawState =
            state.get();

        state->worker =
            std::jthread(
                [rawState](
                    std::stop_token stopToken)
                {
                    std::size_t frameIndex = 1;

                    while (!stopToken.stop_requested())
                    {
                        ComPtr<ID3D12Resource> liveResource;
                        std::string probe;

                        const bool live =
                            FindResource(
                                rawState->gfxImage,
                                rawState->device.Get(),
                                liveResource,
                                probe,
                                false);

                        if (!live ||
                            !liveResource)
                        {
                            std::this_thread::sleep_for(
                                std::chrono::milliseconds(
                                    50));
                            continue;
                        }

                        if (!SameResourceLayout(
                                *rawState,
                                liveResource.Get()))
                        {
                            std::string rebuildError;

                            if (!PrepareAnimationForResource(
                                    *rawState,
                                    liveResource.Get(),
                                    rebuildError))
                            {
                                std::this_thread::sleep_for(
                                    std::chrono::milliseconds(
                                        100));
                                continue;
                            }

                            frameIndex = 0;
                        }

                        if (rawState->frames.empty() ||
                            !rawState->animationUpload)
                        {
                            std::this_thread::sleep_for(
                                std::chrono::milliseconds(
                                    50));
                            continue;
                        }

                        frameIndex %=
                            rawState->frames.size();

                        const auto& frame =
                            rawState->frames[
                                frameIndex];

                        std::string uploadError;

                        // RunCopies waits on a fence before returning, so this
                        // upload buffer is safe to rewrite for the next frame.
                        if (!FillReusableUploadBuffer(
                                rawState->animationUpload.Get(),
                                rawState->layouts,
                                rawState->totalBytes,
                                frame,
                                uploadError))
                        {
                            std::this_thread::sleep_for(
                                std::chrono::milliseconds(
                                    50));
                            continue;
                        }

                        if (!RunCopies(
                                rawState->device.Get(),
                                rawState->queue.Get(),
                                rawState->texture.Get(),
                                rawState->layouts,
                                rawState->animationUpload.Get(),
                                true,
                                uploadError))
                        {
                            std::this_thread::sleep_for(
                                std::chrono::milliseconds(
                                    50));
                            continue;
                        }

                        const UINT delay =
                            std::max<UINT>(
                                frame.delayMs,
                                20u);

                        UINT elapsed = 0;

                        while (elapsed < delay &&
                               !stopToken.stop_requested())
                        {
                            const UINT slice =
                                std::min<UINT>(
                                    10u,
                                    delay - elapsed);

                            std::this_thread::sleep_for(
                                std::chrono::milliseconds(
                                    slice));

                            elapsed += slice;
                        }

                        frameIndex =
                            (frameIndex + 1) %
                            rawState->frames.size();
                    }
                });

        g_animations[camoIndex] =
            std::move(state);

        return true;
    }

}

namespace camo_texture_upload
{
    bool Apply(unsigned int camoIndex,
               const std::string& packageName,
               const std::string& colorPath,
               std::string& message)
    {
        std::lock_guard<std::mutex> lock(g_mutex);

        if (camoIndex != kConfirmedCamo)
        {
            message =
                "only camo slot 1 has a confirmed color role in this build";
            return false;
        }

        if (!g_assetPool)
        {
            message =
                "asset pool table unavailable";
            return false;
        }

        const auto& imagePool =
            g_assetPool[ASSET_TYPE_IMAGE];

        if (!imagePool.pool.unk ||
            imagePool.itemSize < kImageRecordBytes ||
            imagePool.itemAllocCount <=
                static_cast<int>(kConfirmedColorImage))
        {
            message =
                "confirmed color GfxImage 23956 is not currently loaded";
            return false;
        }

        ID3D12Device* device =
            imgui_backend_bridge::AcquireD3D12Device();

        ID3D12CommandQueue* queue =
            imgui_backend_bridge::AcquireD3D12CommandQueue();

        if (!device || !queue)
        {
            if (device) device->Release();
            if (queue) queue->Release();

            message =
                "DX12 device/queue are not ready; wait for the overlay backend and retry";
            return false;
        }

        const auto releaseDx =
            [&]()
            {
                device->Release();
                queue->Release();
            };

        const auto imageBase =
            reinterpret_cast<std::uintptr_t>(
                imagePool.pool.unk);

        const std::uint64_t gfxImage =
            imageBase +
            static_cast<std::uint64_t>(
                kConfirmedColorImage) *
            imagePool.itemSize;

        std::vector<CachedFrame> cachedFrames;
        bool cacheHit = false;
        std::string error;
        std::string probe;

        ComPtr<ID3D12Resource> resource;
        D3D12_RESOURCE_DESC desc{};

        // A first-time 1024/2048 animated cache can take long enough for Cold
        // War to stream/recreate the texture. Therefore:
        //   resolve dimensions -> build/load cache -> THROW THAT POINTER AWAY
        //   -> resolve again -> verify dimensions -> only then touch the GPU.
        //
        // If the live quality changed during the cache build, repeat using the
        // newly observed dimensions. Three passes is enough for a normal
        // settings transition while still failing safely if streaming never
        // settles.
        bool stable = false;

        for (unsigned int pass = 1;
             pass <= 3;
             ++pass)
        {
            ComPtr<ID3D12Resource> sizingResource;
            std::string sizingProbe;

            if (!FindResource(
                    gfxImage,
                    device,
                    sizingResource,
                    sizingProbe,
                    pass == 1))
            {
                releaseDx();
                message =
                    "custom camo resource is not ready: " +
                    sizingProbe;
                return false;
            }

            const auto sizingDesc =
                sizingResource->GetDesc();

            if (!IsSupportedCamoResource(
                    sizingDesc))
            {
                std::ostringstream out;

                out
                    << "current camo resource is unsupported: "
                    << sizingDesc.Width
                    << 'x'
                    << sizingDesc.Height
                    << ' '
                    << FormatName(sizingDesc.Format)
                    << " mips="
                    << sizingDesc.MipLevels;

                releaseDx();
                message = out.str();
                return false;
            }

            // IMPORTANT: release the live game resource before expensive CPU
            // cache generation. We only retain its dimensions.
            sizingResource.Reset();

            cachedFrames.clear();
            cacheHit = false;

            if (!LoadOrBuildFrameCache(
                    colorPath,
                    static_cast<UINT>(
                        sizingDesc.Width),
                    sizingDesc.Height,
                    sizingDesc.MipLevels,
                    cachedFrames,
                    cacheHit,
                    error))
            {
                releaseDx();
                message = error;
                return false;
            }

            // Re-resolve AFTER cache load/build. This is the resource we may
            // actually write to.
            ComPtr<ID3D12Resource> freshResource;
            std::string freshProbe;

            if (!FindResource(
                    gfxImage,
                    device,
                    freshResource,
                    freshProbe,
                    false))
            {
                // Streaming may be between resources. Give it a short window,
                // then retry the whole sizing/cache selection pass.
                Sleep(100);
                continue;
            }

            const auto freshDesc =
                freshResource->GetDesc();

            if (!IsSupportedCamoResource(
                    freshDesc))
            {
                Sleep(100);
                continue;
            }

            const bool sameLayout =
                freshDesc.Width ==
                    sizingDesc.Width &&
                freshDesc.Height ==
                    sizingDesc.Height &&
                freshDesc.MipLevels ==
                    sizingDesc.MipLevels &&
                freshDesc.Format ==
                    sizingDesc.Format;

            if (!sameLayout)
            {
                // Texture Quality changed while the cache was being built.
                // Never upload the old resolution into the new resource.
                CreateDirectoryA(
                    "logs\\camo\\camo",
                    nullptr);

                std::ofstream stability(
                    "logs\\camo\\custom_camo_apply_stability.log",
                    std::ios::app);

                if (stability)
                {
                    stability
                        << "pass="
                        << pass
                        << " layout_changed_during_cache old="
                        << sizingDesc.Width
                        << 'x'
                        << sizingDesc.Height
                        << "/m"
                        << sizingDesc.MipLevels
                        << " new="
                        << freshDesc.Width
                        << 'x'
                        << freshDesc.Height
                        << "/m"
                        << freshDesc.MipLevels
                        << "\n";
                }

                freshResource.Reset();
                Sleep(100);
                continue;
            }

            // One final short stability check catches the common case where
            // the streaming manager swaps resources immediately after the
            // first post-cache resolve.
            Sleep(50);

            ComPtr<ID3D12Resource> verifyResource;
            std::string verifyProbe;

            if (!FindResource(
                    gfxImage,
                    device,
                    verifyResource,
                    verifyProbe,
                    false))
            {
                freshResource.Reset();
                Sleep(100);
                continue;
            }

            const auto verifyDesc =
                verifyResource->GetDesc();

            const bool stillSame =
                verifyDesc.Width ==
                    freshDesc.Width &&
                verifyDesc.Height ==
                    freshDesc.Height &&
                verifyDesc.MipLevels ==
                    freshDesc.MipLevels &&
                verifyDesc.Format ==
                    freshDesc.Format;

            if (!stillSame)
            {
                freshResource.Reset();
                verifyResource.Reset();
                Sleep(100);
                continue;
            }

            // Prefer the most recently resolved object. If the pointer itself
            // changed but layout did not, this avoids writing the older object.
            resource =
                verifyResource;

            desc =
                verifyDesc;

            probe =
                verifyProbe;

            stable = true;
            break;
        }

        if (!stable ||
            !resource)
        {
            releaseDx();

            message =
                "texture quality/resource did not stabilize after cache build; no GPU write was performed";
            return false;
        }

        if (cachedFrames.empty())
        {
            releaseDx();

            message =
                "custom camo cache contains no frames";
            return false;
        }

        CreateDirectoryA(
            "logs\\camo\\camo",
            nullptr);

        std::ofstream status(
            "logs\\camo\\custom_camo_resource_status.txt",
            std::ios::trunc);

        status
            << "package="
            << packageName
            << "\n"
            << "camo_index="
            << camoIndex
            << "\n"
            << "confirmed_color_image=23956\n"
            << "gfximage_ptr=0x"
            << std::hex
            << std::uppercase
            << gfxImage
            << std::dec
            << "\n"
            << "resource_ptr="
            << resource.Get()
            << "\n"
            << "width="
            << desc.Width
            << "\n"
            << "height="
            << desc.Height
            << "\n"
            << "format_id="
            << static_cast<unsigned int>(
                   desc.Format)
            << "\n"
            << "format_name="
            << FormatName(desc.Format)
            << "\n"
            << "mips="
            << desc.MipLevels
            << "\n"
            << "cache="
            << (cacheHit ? "HIT" : "BUILD")
            << "\n"
            << "post_cache_resource_verified=1\n"
            << "probe="
            << probe
            << "\n";

        // Fast custom-to-custom swaps keep the ORIGINAL stock backup instead
        // of restoring stock and immediately reading the exact same texture
        // back from the GPU again. On a cache HIT this removes two synchronous
        // GPU round-trips from the common /apply camo -> /apply camo path.
        //
        // Reuse is deliberately strict: one backup, exact COM resource, and an
        // identical layout. If streaming recreated the texture, fall back to
        // the old restore/re-backup path so release safety is unchanged.
        TextureBackup reusableBackup;
        bool haveReusableBackup = false;
        bool fastSwapReused = false;

        if (auto oldAnimation =
                TakeAnimation(camoIndex))
        {
            if (oldAnimation->backups.size() == 1)
            {
                auto& candidate =
                    oldAnimation->backups.front();

                const bool sameResource =
                    candidate.resource &&
                    candidate.resource.Get() == resource.Get();

                const bool sameLayout =
                    candidate.desc.Width == desc.Width &&
                    candidate.desc.Height == desc.Height &&
                    candidate.desc.MipLevels == desc.MipLevels &&
                    candidate.desc.Format == desc.Format;

                if (sameResource && sameLayout)
                {
                    reusableBackup =
                        std::move(candidate);
                    haveReusableBackup = true;
                    fastSwapReused = true;
                }
            }

            if (!haveReusableBackup)
            {
                for (auto& oldBackup :
                     oldAnimation->backups)
                {
                    std::string ignored;

                    RestoreBackup(
                        oldAnimation->device.Get(),
                        oldAnimation->queue.Get(),
                        oldBackup,
                        ignored);
                }
            }
        }

        auto previous =
            g_backups.find(camoIndex);

        if (previous !=
            g_backups.end())
        {
            auto& candidate =
                previous->second;

            const bool sameResource =
                candidate.resource &&
                candidate.resource.Get() == resource.Get();

            const bool sameLayout =
                candidate.desc.Width == desc.Width &&
                candidate.desc.Height == desc.Height &&
                candidate.desc.MipLevels == desc.MipLevels &&
                candidate.desc.Format == desc.Format;

            if (!haveReusableBackup &&
                sameResource && sameLayout)
            {
                reusableBackup =
                    std::move(candidate);
                haveReusableBackup = true;
                fastSwapReused = true;
            }
            else
            {
                std::string ignored;
                RestoreBackup(
                    device,
                    queue,
                    candidate,
                    ignored);
            }

            g_backups.erase(
                previous);
        }

        // Re-resolve once more after restore activity, because restore itself
        // may have yielded enough time for a stream transition.
        ComPtr<ID3D12Resource> finalResource;
        std::string finalProbe;

        if (!FindResource(
                gfxImage,
                device,
                finalResource,
                finalProbe,
                false))
        {
            releaseDx();
            message =
                "resource disappeared immediately before backup; apply cancelled safely";
            return false;
        }

        const auto finalDesc =
            finalResource->GetDesc();

        const bool finalLayoutMatches =
            finalDesc.Width ==
                desc.Width &&
            finalDesc.Height ==
                desc.Height &&
            finalDesc.MipLevels ==
                desc.MipLevels &&
            finalDesc.Format ==
                desc.Format;

        if (!finalLayoutMatches)
        {
            releaseDx();
            message =
                "texture quality changed immediately before upload; apply cancelled safely, run /apply again";
            return false;
        }

        resource =
            finalResource;

        desc =
            finalDesc;

        TextureBackup backup;

        const bool reusableStillValid =
            haveReusableBackup &&
            reusableBackup.resource &&
            reusableBackup.resource.Get() == resource.Get() &&
            reusableBackup.desc.Width == desc.Width &&
            reusableBackup.desc.Height == desc.Height &&
            reusableBackup.desc.MipLevels == desc.MipLevels &&
            reusableBackup.desc.Format == desc.Format;

        if (reusableStillValid)
        {
            backup =
                std::move(reusableBackup);
        }
        else if (!BackupTexture(
                device,
                queue,
                resource.Get(),
                desc.MipLevels,
                backup,
                error))
        {
            releaseDx();

            message =
                "stable BC7 resource found, but backup failed: " +
                error;

            return false;
        }
        else
        {
            // A resource transition invalidated the reusable backup. The normal
            // readback path above captured the new resource safely.
            fastSwapReused = false;
        }

        status
            << "original_backup="
            << (reusableStillValid ? "REUSED" : "CAPTURED")
            << "\n";

        // Before first write, verify the exact COM object is still the current
        // resource. Same layout alone is insufficient during resource churn.
        ComPtr<ID3D12Resource> writeCheck;
        std::string writeProbe;

        if (!FindResource(
                gfxImage,
                device,
                writeCheck,
                writeProbe,
                false) ||
            !writeCheck ||
            writeCheck.Get() !=
                resource.Get())
        {
            releaseDx();

            message =
                "camo resource changed between backup and upload; no custom write performed, retry /apply";

            return false;
        }

        if (!UploadPreparedBuffer(
                device,
                queue,
                resource.Get(),
                backup.layouts,
                backup.totalBytes,
                cachedFrames.front().mipData,
                error))
        {
            releaseDx();

            message =
                "BC7 custom camo upload failed: " +
                error;

            return false;
        }

        const std::size_t frameCount =
            cachedFrames.size();

        if (frameCount > 1)
        {
            if (!StartAnimation(
                    camoIndex,
                    device,
                    queue,
                    resource.Get(),
                    gfxImage,
                    colorPath,
                    std::move(backup),
                    std::move(cachedFrames),
                    error))
            {
                status
                    << "animation_start=failed\n"
                    << "animation_error="
                    << error
                    << "\n";
            }
            else
            {
                status
                    << "animation_start=success\n"
                    << "animation_frames="
                    << frameCount
                    << "\n"
                    << "loop_smoothing=automatic\n";
            }
        }
        else
        {
            status
                << "animation_start=static\n"
                << "animation_frames=1\n";

            g_backups[camoIndex] =
                std::move(backup);
        }

        status
            << "upload=success\n"
            << "encoder=internal_bc7_mode6\n"
            << "uploaded_mips="
            << desc.MipLevels
            << "\n"
            << "quality_adaptive=1\n";

        releaseDx();

        std::ostringstream out;

        out
            << "HQ BC7 custom camo uploaded into confirmed color image 23956 ("
            << desc.Width
            << 'x'
            << desc.Height
            << ' '
            << FormatName(desc.Format)
            << ", mips="
            << desc.MipLevels
            << ", frames="
            << frameCount
            << ", cache="
            << (cacheHit ? "HIT" : "BUILD")
            << ", fast-swap="
            << (fastSwapReused ? "HIT" : "MISS")
            << "). ";

        if (frameCount > 1)
        {
            out
                << "custom camo animation is running. ";
        }

        out
            << "Post-cache resource was re-resolved and verified before upload.";

        message =
            out.str();

        return true;
    }

    bool IsGifPrecached(
        const std::string& colorPath,
        unsigned int size)
    {
        if (size == 0)
            return false;

        return FrameCacheExists(
            colorPath,
            size,
            size,
            ExpectedMipCount(size));
    }

    bool PrecacheGif(
        const std::string& colorPath,
        std::string& message)
    {
        if (colorPath.empty())
        {
            message = "GIF path is empty";
            return false;
        }

        static constexpr UINT kSizes[] =
        {
            2048,
            1024,
            512,
            256
        };

        unsigned int hits = 0;
        unsigned int builds = 0;
        std::ostringstream summary;

        for (const UINT size : kSizes)
        {
            const UINT mipCount =
                ExpectedMipCount(size);

            if (FrameCacheExists(
                    colorPath,
                    size,
                    size,
                    mipCount))
            {
                ++hits;
                summary << size << "=HIT ";
                continue;
            }

            std::vector<CachedFrame> frames;
            bool cacheHit = false;
            std::string error;

            if (!LoadOrBuildFrameCache(
                    colorPath,
                    size,
                    size,
                    mipCount,
                    frames,
                    cacheHit,
                    error))
            {
                summary
                    << size
                    << "=FAILED("
                    << error
                    << ") ";
                continue;
            }

            if (cacheHit)
            {
                ++hits;
                summary << size << "=HIT ";
            }
            else
            {
                ++builds;
                summary << size << "=BUILT ";
            }

            // Disk cache is the goal; free large frame data immediately.
            std::vector<CachedFrame>().swap(frames);
            Sleep(50);
        }

        std::ostringstream out;
        out
            << "precache complete hits="
            << hits
            << " builds="
            << builds
            << " ["
            << summary.str()
            << "]";

        message = out.str();
        return true;
    }

    std::string PrecacheStatus()
    {
        std::ostringstream out;

        out
            << (g_precacheRunning.load()
                ? "running"
                : "idle")
            << " packages="
            << g_precacheDone.load()
            << "/"
            << g_precacheTotal.load()
            << " hits="
            << g_precacheHits.load()
            << " builds="
            << g_precacheBuilds.load();

        return out.str();
    }

    void StartBackgroundPrecache()
    {
        bool expected = false;

        if (!g_precacheRunning.compare_exchange_strong(
                expected,
                true))
        {
            return;
        }

        g_precacheDone.store(0);
        g_precacheTotal.store(0);
        g_precacheHits.store(0);
        g_precacheBuilds.store(0);

        std::thread(
            []()
            {
                SetThreadPriority(
                    GetCurrentThread(),
                    THREAD_PRIORITY_BELOW_NORMAL);

                g_backgroundPrecacheMode = true;

                char exePath[MAX_PATH]{};
                std::filesystem::path root;

                if (GetModuleFileNameA(
                        nullptr,
                        exePath,
                        MAX_PATH))
                {
                    root =
                        std::filesystem::path(exePath)
                            .parent_path() /
                        "Camos";
                }
                else
                {
                    root =
                        std::filesystem::current_path() /
                        "Camos";
                }

                std::vector<std::string> gifs;
                std::error_code ec;

                if (std::filesystem::exists(root, ec))
                {
                    for (const auto& entry :
                         std::filesystem::directory_iterator(root, ec))
                    {
                        if (ec)
                            break;

                        if (!entry.is_directory())
                            continue;

                        std::vector<std::string> folderGifs;
                        std::vector<std::string> preferredPngs;
                        std::vector<std::string> colorPngs;
                        std::vector<std::string> fallbackPngs;

                        for (const auto& file :
                             std::filesystem::directory_iterator(
                                 entry.path(), ec))
                        {
                            if (ec)
                                break;

                            if (!file.is_regular_file())
                                continue;

                            std::string ext =
                                file.path().extension().string();

                            std::transform(
                                ext.begin(),
                                ext.end(),
                                ext.begin(),
                                [](unsigned char c)
                                {
                                    return static_cast<char>(
                                        std::tolower(c));
                                });

                            std::string filename =
                                file.path().filename().string();

                            std::string lower =
                                filename;

                            std::transform(
                                lower.begin(),
                                lower.end(),
                                lower.begin(),
                                [](unsigned char c)
                                {
                                    return static_cast<char>(
                                        std::tolower(c));
                                });

                            if (ext == ".gif")
                            {
                                folderGifs.push_back(
                                    file.path().string());
                            }
                            else if (ext == ".png")
                            {
                                if (lower == "icon.png" ||
                                    lower.find("normal") != std::string::npos ||
                                    lower.find("gray") != std::string::npos ||
                                    lower.find("grey") != std::string::npos)
                                {
                                    continue;
                                }

                                if (lower == "layer0_color.png")
                                {
                                    preferredPngs.push_back(
                                        file.path().string());
                                }
                                else if (lower.find("color") !=
                                         std::string::npos)
                                {
                                    colorPngs.push_back(
                                        file.path().string());
                                }
                                else
                                {
                                    fallbackPngs.push_back(
                                        file.path().string());
                                }
                            }
                        }

                        std::sort(folderGifs.begin(), folderGifs.end());
                        std::sort(preferredPngs.begin(), preferredPngs.end());
                        std::sort(colorPngs.begin(), colorPngs.end());
                        std::sort(fallbackPngs.begin(), fallbackPngs.end());

                        // ANY GIF wins. PNG priority mirrors CamoManager.
                        if (!folderGifs.empty())
                        {
                            gifs.push_back(
                                folderGifs.front());
                        }
                        else if (!preferredPngs.empty())
                        {
                            gifs.push_back(
                                preferredPngs.front());
                        }
                        else if (!colorPngs.empty())
                        {
                            gifs.push_back(
                                colorPngs.front());
                        }
                        else if (!fallbackPngs.empty())
                        {
                            gifs.push_back(
                                fallbackPngs.front());
                        }
                    }
                }

                std::sort(
                    gifs.begin(),
                    gifs.end(),
                    [](const std::string& a,
                       const std::string& b)
                    {
                        auto folderName = [](const std::string& path)
                        {
                            std::filesystem::path p(path);
                            std::string name =
                                p.parent_path().filename().string();

                            std::transform(
                                name.begin(),
                                name.end(),
                                name.begin(),
                                [](unsigned char c)
                                {
                                    return static_cast<char>(
                                        std::tolower(c));
                                });

                            return name;
                        };

                        const std::string af = folderName(a);
                        const std::string bf = folderName(b);

                        const bool aDefault =
                            af == "bo4diamond";
                        const bool bDefault =
                            bf == "bo4diamond";

                        if (aDefault != bDefault)
                            return aDefault;

                        return a < b;
                    });

                g_precacheTotal.store(
                    static_cast<unsigned int>(
                        gifs.size()));

                CreateDirectoryA("logs\\camo\\camo", nullptr);

                std::ofstream log(
                    "logs\\camo\\custom_camo_prewarm.log",
                    std::ios::trunc);

                if (log)
                {
                    log
                        << "root="
                        << root.string()
                        << "\n"
                        << "folders="
                        << gifs.size()
                        << "\n";
                }

                for (const auto& gif : gifs)
                {
                    unsigned int before = 0;

                    for (const UINT size :
                         {2048u, 1024u, 512u, 256u})
                    {
                        if (FrameCacheExists(
                                gif,
                                size,
                                size,
                                ExpectedMipCount(size)))
                        {
                            ++before;
                        }
                    }

                    if (log)
                        log << "START \"" << gif << "\" cached_before=" << before << "\n";

                    std::string result;
                    PrecacheGif(gif, result);

                    unsigned int after = 0;

                    for (const UINT size :
                         {2048u, 1024u, 512u, 256u})
                    {
                        if (FrameCacheExists(
                                gif,
                                size,
                                size,
                                ExpectedMipCount(size)))
                        {
                            ++after;
                        }
                    }

                    const unsigned int newlyBuilt =
                        after > before
                        ? after - before
                        : 0;

                    g_precacheHits.fetch_add(before);
                    g_precacheBuilds.fetch_add(newlyBuilt);
                    g_precacheDone.fetch_add(1);

                    if (log)
                    {
                        log
                            << "DONE \""
                            << gif
                            << "\" "
                            << result
                            << "\n";
                        log.flush();
                    }

                    Sleep(100);
                }

                if (log)
                {
                    log
                        << "COMPLETE folders="
                        << g_precacheDone.load()
                        << "/"
                        << g_precacheTotal.load()
                        << "\n";
                }

                g_backgroundPrecacheMode = false;
                g_precacheRunning.store(false);
            })
            .detach();
    }

    bool Restore(unsigned int camoIndex,
                 std::string& message)
    {
        std::lock_guard<std::mutex> lock(g_mutex);

        if (auto animation = TakeAnimation(camoIndex))
        {
            std::size_t restored = 0;

            for (auto& backup : animation->backups)
            {
                std::string error;

                if (RestoreBackup(
                        animation->device.Get(),
                        animation->queue.Get(),
                        backup,
                        error))
                {
                    ++restored;
                }
            }

            std::ostringstream out;
            out << "stopped animated camo and restored "
                << restored << "/"
                << animation->backups.size()
                << " original BC7 resource(s)";
            message = out.str();

            return restored ==
                animation->backups.size();
        }

        auto it =
            g_backups.find(camoIndex);

        if (it == g_backups.end())
        {
            message =
                "no real custom camo texture upload backup is active";
            return false;
        }

        ID3D12Device* device =
            imgui_backend_bridge::AcquireD3D12Device();
        ID3D12CommandQueue* queue =
            imgui_backend_bridge::AcquireD3D12CommandQueue();

        if (!device || !queue)
        {
            if (device) device->Release();
            if (queue) queue->Release();

            message =
                "DX12 device/queue are not ready";
            return false;
        }

        std::string error;

        const bool restored =
            RestoreBackup(
                device,
                queue,
                it->second,
                error);

        device->Release();
        queue->Release();

        if (!restored)
        {
            message =
                "failed to restore original BC7 camo texture: " +
                error;
            return false;
        }

        g_backups.erase(it);

        message =
            "restored original 4 BC7 mip levels for confirmed color image 23956";
        return true;
    }
}

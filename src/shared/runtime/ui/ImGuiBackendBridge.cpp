#include "ImGuiBackendBridge.h"
#include "ClientServices.h"
#include "ResearchImGui.h"
#include "../../common/utils/MinHook.hpp"

#include <Windows.h>
#include <d3d12.h>
#include <dxgi1_4.h>
#include <wrl/client.h>

#include "../../../../third_party/imgui/imgui.h"
#include "../../../../third_party/imgui/backends/imgui_impl_dx12.h"
#include "../../../../third_party/imgui/backends/imgui_impl_win32.h"

#include <atomic>
#include <cstdint>
#include <cstdio>
#include <mutex>
#include <vector>
#include <string>
#include <cstring>
#include <algorithm>
#include <exception>

using Microsoft::WRL::ComPtr;

extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND, UINT, WPARAM, LPARAM);

// Resolve DXGI directly from System32. The shared Runtime library must not
// depend on a client-specific proxy export (the unified payload is version.dll).
static HRESULT CreateSystemDXGIFactory1(REFIID riid, void** ppFactory)
{
    using Fn = HRESULT (WINAPI*)(REFIID, void**);
    static Fn fn = []() -> Fn
    {
        wchar_t path[MAX_PATH]{};
        const UINT length = GetSystemDirectoryW(path, MAX_PATH);
        constexpr wchar_t kDxgiSuffix[] = L"\\dxgi.dll";
        if (!length || length >= MAX_PATH || length + (ARRAYSIZE(kDxgiSuffix) - 1) >= MAX_PATH)
            return nullptr;

        lstrcatW(path, kDxgiSuffix);
        const HMODULE module = LoadLibraryW(path);
        return module ? reinterpret_cast<Fn>(GetProcAddress(module, "CreateDXGIFactory1")) : nullptr;
    }();

    return fn ? fn(riid, ppFactory) : E_NOINTERFACE;
}

// Compatibility-only link shim for stale shared ImGui objects built before the
// unified version.dll conversion. This does NOT proxy a local dxgi.dll; it
// forwards directly to System32 and can be removed once all old objects are gone.
extern "C" HRESULT WINAPI Proxy_CreateDXGIFactory1(REFIID riid, void** ppFactory)
{
    return CreateSystemDXGIFactory1(riid, ppFactory);
}

namespace imgui_backend_bridge
{
    namespace
    {
        using PresentFn = HRESULT(__stdcall*)(IDXGISwapChain*, UINT, UINT);
        using ResizeBuffersFn = HRESULT(__stdcall*)(IDXGISwapChain*, UINT, UINT, UINT, DXGI_FORMAT, UINT);
        using ExecuteCommandListsFn = void(__stdcall*)(ID3D12CommandQueue*, UINT, ID3D12CommandList* const*);
        using GetAsyncKeyStateFn = SHORT(WINAPI*)(int);
        using GetKeyStateFn = SHORT(WINAPI*)(int);
        using GetKeyboardStateFn = BOOL(WINAPI*)(PBYTE);
        using GetRawInputDataFn = UINT(WINAPI*)(HRAWINPUT, UINT, LPVOID, PUINT, UINT);
        using GetRawInputBufferFn = UINT(WINAPI*)(PRAWINPUT, PUINT, UINT);

        struct FrameContext
        {
            ComPtr<ID3D12CommandAllocator> allocator;
            ComPtr<ID3D12Resource> backBuffer;
            D3D12_CPU_DESCRIPTOR_HANDLE rtv{};
            UINT64 fenceValue = 0;
        };

        std::atomic_bool g_hooksInstalled{ false };
        std::atomic_bool g_camoCaptureHooksInstalled{ false };
        std::atomic_bool g_installingHooks{ false };
        std::atomic_bool g_ready{ false };
        std::atomic_bool g_shuttingDown{ false };
        std::recursive_mutex g_mutex;

        PresentFn g_originalPresent = nullptr;
        ResizeBuffersFn g_originalResizeBuffers = nullptr;
        ExecuteCommandListsFn g_originalExecuteCommandLists = nullptr;
        void* g_executeCommandListsTarget = nullptr;
        GetAsyncKeyStateFn g_originalGetAsyncKeyState = nullptr;
        GetKeyStateFn g_originalGetKeyState = nullptr;
        GetKeyboardStateFn g_originalGetKeyboardState = nullptr;
        GetRawInputDataFn g_originalGetRawInputData = nullptr;
        GetRawInputBufferFn g_originalGetRawInputBuffer = nullptr;
        void* g_getAsyncKeyStateTarget = nullptr;
        void* g_getKeyStateTarget = nullptr;
        void* g_getKeyboardStateTarget = nullptr;
        void* g_getRawInputDataTarget = nullptr;
        void* g_getRawInputBufferTarget = nullptr;

        struct QueueCandidate
        {
            ComPtr<ID3D12CommandQueue> queue;
            ComPtr<ID3D12Device> device;
            ULONGLONG lastSeen = 0;
            UINT64 executeCount = 0;
        };

        std::vector<QueueCandidate> g_queueCandidates;
        ComPtr<ID3D12CommandQueue> g_commandQueue;
        ComPtr<ID3D12Device> g_device;
        ComPtr<IDXGISwapChain3> g_swapChain;
        ComPtr<ID3D12DescriptorHeap> g_rtvHeap;
        ComPtr<ID3D12DescriptorHeap> g_srvHeap;
        ComPtr<ID3D12GraphicsCommandList> g_commandList;
        ComPtr<ID3D12Fence> g_fence;
        HANDLE g_fenceEvent = nullptr;
        UINT64 g_nextFenceValue = 1;
        std::vector<FrameContext> g_frames;
        std::atomic_bool g_menuRequested{ false };
        std::atomic_bool g_renderFaulted{ false };
        bool g_inputCaptureApplied = false;
        int g_cursorShowAdjustments = 0;
        RECT g_previousClipRect{};
        bool g_hadClipRect = false;

        HWND g_window = nullptr;
        WNDPROC g_originalWndProc = nullptr;
        DXGI_FORMAT g_backBufferFormat = DXGI_FORMAT_R8G8B8A8_UNORM;
        UINT g_rtvStride = 0;
        UINT g_srvStride = 0;
        UINT g_srvCapacity = 64;
        std::vector<UINT> g_freeSrvIndices;
        UINT g_nextSrvIndex = 0;

        void BackendLog(const char* text)
        {
            if (!text) return;
            char path[MAX_PATH]{};
            GetModuleFileNameA(nullptr, path, MAX_PATH);
            char* slash = strrchr(path, '\\');
            if (slash) *(slash + 1) = '\0';
            strcat_s(path, "logs\\ui\\imgui_backend.log");
            CreateDirectoryA((std::string(path).substr(0, std::string(path).find_last_of("\\/")).c_str()), nullptr);
            FILE* f = nullptr;
            if (fopen_s(&f, path, "a") == 0 && f)
            {
                SYSTEMTIME st{}; GetLocalTime(&st);
                fprintf(f, "[%02u:%02u:%02u.%03u] %s\n", st.wHour, st.wMinute, st.wSecond, st.wMilliseconds, text);
                fclose(f);
            }
            OutputDebugStringA(text);
            OutputDebugStringA("\n");
        }


        bool SameComIdentity(IUnknown* a, IUnknown* b)
        {
            if (!a || !b)
                return false;
            ComPtr<IUnknown> ia;
            ComPtr<IUnknown> ib;
            if (FAILED(a->QueryInterface(IID_PPV_ARGS(&ia))) ||
                FAILED(b->QueryInterface(IID_PPV_ARGS(&ib))))
                return false;
            return ia.Get() == ib.Get();
        }

        bool IsUsableGameSwapChain(IDXGISwapChain* swapChain, DXGI_SWAP_CHAIN_DESC* outDesc = nullptr)
        {
            if (!swapChain)
                return false;
            DXGI_SWAP_CHAIN_DESC desc{};
            if (FAILED(swapChain->GetDesc(&desc)) || !desc.OutputWindow || desc.BufferCount < 2)
                return false;
            DWORD pid = 0;
            GetWindowThreadProcessId(desc.OutputWindow, &pid);
            if (pid != GetCurrentProcessId() || !IsWindow(desc.OutputWindow) || !IsWindowVisible(desc.OutputWindow))
                return false;
            RECT rc{};
            if (!GetClientRect(desc.OutputWindow, &rc))
                return false;
            const LONG width = rc.right - rc.left;
            const LONG height = rc.bottom - rc.top;
            if (width < 640 || height < 360)
                return false;
            if (outDesc)
                *outDesc = desc;
            return true;
        }

        ComPtr<ID3D12CommandQueue> SelectQueueForDevice(ID3D12Device* device)
        {
            if (!device)
                return {};
            const ULONGLONG now = GetTickCount64();
            QueueCandidate* best = nullptr;
            for (auto& candidate : g_queueCandidates)
            {
                if (!candidate.queue || !candidate.device ||
                    !SameComIdentity(candidate.device.Get(), device))
                    continue;
                if ((now - candidate.lastSeen) > 3000 || candidate.executeCount < 8)
                    continue;
                if (!best || candidate.executeCount > best->executeCount ||
                    (candidate.executeCount == best->executeCount && candidate.lastSeen > best->lastSeen))
                    best = &candidate;
            }
            return best ? best->queue : ComPtr<ID3D12CommandQueue>{};
        }

        bool IsFrameReady(const FrameContext& frame)
        {
            // Never block the game's Present thread waiting for our overlay work.
            // If this back buffer is still in use by the GPU, skip only this ImGui
            // frame and try again on the next Present. Blocking here can collapse
            // the game to 1 FPS when the queue/fence timing changes.
            if (!g_fence || frame.fenceValue == 0)
                return true;
            return g_fence->GetCompletedValue() >= frame.fenceValue;
        }

        void WaitForGpuIdle()
        {
            if (!g_commandQueue || !g_fence || !g_fenceEvent)
                return;
            const UINT64 value = g_nextFenceValue++;
            if (FAILED(g_commandQueue->Signal(g_fence.Get(), value)))
                return;
            if (g_fence->GetCompletedValue() < value &&
                SUCCEEDED(g_fence->SetEventOnCompletion(value, g_fenceEvent)))
                WaitForSingleObject(g_fenceEvent, 2000);
        }

        void ReleaseFrameResources()
        {
            g_ready.store(false);
            research_imgui::SetBackendReady(false);
            WaitForGpuIdle();

            if (ImGui::GetCurrentContext())
            {
                ImGui_ImplDX12_Shutdown();
                ImGui_ImplWin32_Shutdown();
            }

            for (auto& frame : g_frames)
            {
                frame.backBuffer.Reset();
                frame.allocator.Reset();
            }
            g_frames.clear();
            g_commandList.Reset();
            g_fence.Reset();
            if (g_fenceEvent)
            {
                CloseHandle(g_fenceEvent);
                g_fenceEvent = nullptr;
            }
            g_nextFenceValue = 1;
            g_rtvHeap.Reset();
            g_srvHeap.Reset();
            g_swapChain.Reset();
            g_device.Reset();
            g_freeSrvIndices.clear();
            g_nextSrvIndex = 0;
        }

        void RestoreWndProc()
        {
            if (g_window && g_originalWndProc && IsWindow(g_window))
                SetWindowLongPtrW(g_window, GWLP_WNDPROC, reinterpret_cast<LONG_PTR>(g_originalWndProc));
            g_originalWndProc = nullptr;
            g_window = nullptr;
        }

        void SrvAlloc(ImGui_ImplDX12_InitInfo*, D3D12_CPU_DESCRIPTOR_HANDLE* cpu, D3D12_GPU_DESCRIPTOR_HANDLE* gpu)
        {
            std::scoped_lock lock(g_mutex);
            if (!g_srvHeap || !cpu || !gpu)
                return;

            UINT index = UINT_MAX;
            if (!g_freeSrvIndices.empty())
            {
                index = g_freeSrvIndices.back();
                g_freeSrvIndices.pop_back();
            }
            else if (g_nextSrvIndex < g_srvCapacity)
            {
                index = g_nextSrvIndex++;
            }

            if (index == UINT_MAX)
            {
                *cpu = {};
                *gpu = {};
                return;
            }

            *cpu = g_srvHeap->GetCPUDescriptorHandleForHeapStart();
            *gpu = g_srvHeap->GetGPUDescriptorHandleForHeapStart();
            cpu->ptr += static_cast<SIZE_T>(index) * g_srvStride;
            gpu->ptr += static_cast<UINT64>(index) * g_srvStride;
        }

        void SrvFree(ImGui_ImplDX12_InitInfo*, D3D12_CPU_DESCRIPTOR_HANDLE cpu, D3D12_GPU_DESCRIPTOR_HANDLE)
        {
            std::scoped_lock lock(g_mutex);
            if (!g_srvHeap || !cpu.ptr || !g_srvStride)
                return;
            const auto base = g_srvHeap->GetCPUDescriptorHandleForHeapStart().ptr;
            if (cpu.ptr < base)
                return;
            const SIZE_T delta = cpu.ptr - base;
            if ((delta % g_srvStride) != 0)
                return;
            const UINT index = static_cast<UINT>(delta / g_srvStride);
            if (index < g_srvCapacity)
                g_freeSrvIndices.push_back(index);
        }

        void ReleaseLatchedGameInput()
        {
            if (!g_window || !g_originalWndProc)
                return;

            // The game maintains its own pressed-key state. If a key-down reached the
            // game before the overlay opened and its key-up is then swallowed, movement
            // remains latched. Send release events through the original WndProc once
            // before enabling the hard input block.
            for (int vk = 1; vk < 256; ++vk)
            {
                const SHORT state = g_originalGetAsyncKeyState
                    ? g_originalGetAsyncKeyState(vk)
                    : GetAsyncKeyState(vk);
                if ((state & 0x8000) == 0)
                    continue;

                const LPARAM keyUp = static_cast<LPARAM>(1u | (1u << 30) | (1u << 31));
                CallWindowProcW(g_originalWndProc, g_window, WM_KEYUP, static_cast<WPARAM>(vk), keyUp);
                CallWindowProcW(g_originalWndProc, g_window, WM_SYSKEYUP, static_cast<WPARAM>(vk), keyUp);
            }

            CallWindowProcW(g_originalWndProc, g_window, WM_LBUTTONUP, 0, 0);
            CallWindowProcW(g_originalWndProc, g_window, WM_RBUTTONUP, 0, 0);
            CallWindowProcW(g_originalWndProc, g_window, WM_MBUTTONUP, 0, 0);
            CallWindowProcW(g_originalWndProc, g_window, WM_XBUTTONUP, MAKEWPARAM(0, XBUTTON1), 0);
            CallWindowProcW(g_originalWndProc, g_window, WM_XBUTTONUP, MAKEWPARAM(0, XBUTTON2), 0);
        }

        void ApplyExclusiveInputState(bool open)
        {
            if (open == g_inputCaptureApplied)
                return;

            g_inputCaptureApplied = open;
            const bool showMouse = open && research_imgui::WantsMouseCursor();
            if (ImGui::GetCurrentContext())
                ImGui::GetIO().MouseDrawCursor = showMouse;
            if (open)
            {
                ReleaseLatchedGameInput();
                g_hadClipRect = GetClipCursor(&g_previousClipRect) != FALSE;
                ClipCursor(nullptr);
                if (showMouse)
                {
                    while (ShowCursor(TRUE) < 0)
                        ++g_cursorShowAdjustments;
                    ++g_cursorShowAdjustments;
                    SetCursor(LoadCursor(nullptr, IDC_ARROW));
                }
                else
                {
                    SetCursor(nullptr);
                }
                if (g_window)
                {
                    SetForegroundWindow(g_window);
                    SetFocus(g_window);
                    SetCapture(g_window);
                }
            }
            else
            {
                if (GetCapture() == g_window)
                    ReleaseCapture();
                while (g_cursorShowAdjustments > 0)
                {
                    ShowCursor(FALSE);
                    --g_cursorShowAdjustments;
                }
                if (g_hadClipRect)
                    ClipCursor(&g_previousClipRect);
                g_hadClipRect = false;
                if (g_window)
                {
                    SetForegroundWindow(g_window);
                    SetFocus(g_window);
                }
            }
        }

        bool IsInputMessage(UINT msg)
        {
            switch (msg)
            {
            case WM_INPUT:
            case WM_CHAR:
            case WM_DEADCHAR:
            case WM_SYSCHAR:
            case WM_SYSDEADCHAR:
            case WM_KEYDOWN:
            case WM_KEYUP:
            case WM_SYSKEYDOWN:
            case WM_SYSKEYUP:
            case WM_MOUSEMOVE:
            case WM_LBUTTONDOWN:
            case WM_LBUTTONUP:
            case WM_LBUTTONDBLCLK:
            case WM_RBUTTONDOWN:
            case WM_RBUTTONUP:
            case WM_RBUTTONDBLCLK:
            case WM_MBUTTONDOWN:
            case WM_MBUTTONUP:
            case WM_MBUTTONDBLCLK:
            case WM_XBUTTONDOWN:
            case WM_XBUTTONUP:
            case WM_XBUTTONDBLCLK:
            case WM_MOUSEWHEEL:
            case WM_MOUSEHWHEEL:
                return true;
            default:
                return false;
            }
        }

        bool IsGameWindowForeground();

        bool ClientUiOwnsKeyboard()
        {
            return research_imgui::IsInteractiveVisible() && IsGameWindowForeground();
        }

        SHORT WINAPI GetAsyncKeyStateDetour(int virtualKey)
        {
            if (ClientUiOwnsKeyboard())
                return 0;
            return g_originalGetAsyncKeyState ? g_originalGetAsyncKeyState(virtualKey) : 0;
        }

        SHORT WINAPI GetKeyStateDetour(int virtualKey)
        {
            if (ClientUiOwnsKeyboard())
                return 0;
            return g_originalGetKeyState ? g_originalGetKeyState(virtualKey) : 0;
        }

        BOOL WINAPI GetKeyboardStateDetour(PBYTE keyState)
        {
            if (ClientUiOwnsKeyboard())
            {
                if (keyState)
                    memset(keyState, 0, 256);
                return TRUE;
            }
            return g_originalGetKeyboardState ? g_originalGetKeyboardState(keyState) : FALSE;
        }

        void NeutralizeRawInput(PRAWINPUT input, UINT count)
        {
            if (!input)
                return;
            for (UINT i = 0; i < count; ++i)
            {
                if (input[i].header.dwType == RIM_TYPEKEYBOARD)
                {
                    input[i].data.keyboard.MakeCode = 0;
                    input[i].data.keyboard.Flags = RI_KEY_BREAK;
                    input[i].data.keyboard.Reserved = 0;
                    input[i].data.keyboard.VKey = 0;
                    input[i].data.keyboard.Message = WM_KEYUP;
                    input[i].data.keyboard.ExtraInformation = 0;
                }
                else if (input[i].header.dwType == RIM_TYPEMOUSE)
                {
                    memset(&input[i].data.mouse, 0, sizeof(input[i].data.mouse));
                }
            }
        }

        UINT WINAPI GetRawInputDataDetour(HRAWINPUT rawInput, UINT command, LPVOID data, PUINT size, UINT headerSize)
        {
            const UINT result = g_originalGetRawInputData
                ? g_originalGetRawInputData(rawInput, command, data, size, headerSize)
                : static_cast<UINT>(-1);
            if (result != static_cast<UINT>(-1) && command == RID_INPUT && data && ClientUiOwnsKeyboard())
                NeutralizeRawInput(static_cast<PRAWINPUT>(data), 1);
            return result;
        }

        UINT WINAPI GetRawInputBufferDetour(PRAWINPUT data, PUINT size, UINT headerSize)
        {
            const UINT result = g_originalGetRawInputBuffer
                ? g_originalGetRawInputBuffer(data, size, headerSize)
                : static_cast<UINT>(-1);
            if (result != static_cast<UINT>(-1) && data && ClientUiOwnsKeyboard())
                NeutralizeRawInput(data, result);
            return result;
        }

        bool InstallKeyboardSuppressionHooks()
        {
            // Process-wide User32/RawInput detours proved unstable in Cold War and
            // can also intercept Steam/NVIDIA/Discord overlay threads. Keep input
            // isolation local to the validated game WndProc instead.
            BackendLog("Process-wide keyboard/raw-input hooks disabled for stability; WndProc input isolation active.");
            return true;
        }

        SHORT PollPhysicalKey(int virtualKey)
        {
            return g_originalGetAsyncKeyState ? g_originalGetAsyncKeyState(virtualKey) : GetAsyncKeyState(virtualKey);
        }

        LRESULT CALLBACK WndProcDetour(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
        {
            // While any client UI owns input, route messages to ImGui and never
            // forward gameplay input to the game. This is intentionally independent
            // of ImGui's WantCapture flags so chat/console cannot click, fire, move,
            // or activate menu items behind the overlay.
            const bool interactive = research_imgui::IsInteractiveVisible() && IsGameWindowForeground();
            if (interactive)
            {
                if (ImGui::GetCurrentContext())
                    ImGui_ImplWin32_WndProcHandler(hwnd, msg, wParam, lParam);

                if (msg == WM_SETCURSOR)
                {
                    if (research_imgui::WantsMouseCursor())
                        SetCursor(LoadCursor(nullptr, IDC_ARROW));
                    else
                        SetCursor(nullptr);
                    return TRUE;
                }

                if (research_imgui::ExclusiveInputEnabled() && IsInputMessage(msg))
                    return 0;

                if (ImGui::GetCurrentContext())
                {
                    ImGuiIO& io = ImGui::GetIO();
                    if ((io.WantCaptureMouse || io.WantCaptureKeyboard) && IsInputMessage(msg))
                        return 0;
                }
            }

            return CallWindowProcW(g_originalWndProc, hwnd, msg, wParam, lParam);
        }

        bool CreateRenderResources(IDXGISwapChain* baseSwapChain)
        {
            if (!baseSwapChain)
                return false;

            DXGI_SWAP_CHAIN_DESC validatedDesc{};
            if (!IsUsableGameSwapChain(baseSwapChain, &validatedDesc))
            {
                BackendLog("Ignored non-game or undersized swap chain during ImGui initialization.");
                return false;
            }

            ComPtr<IDXGISwapChain3> swapChain;
            if (FAILED(baseSwapChain->QueryInterface(IID_PPV_ARGS(&swapChain))))
                return false;

            ComPtr<ID3D12Device> device;
            if (FAILED(swapChain->GetDevice(IID_PPV_ARGS(&device))))
                return false;

            DXGI_SWAP_CHAIN_DESC desc = validatedDesc;

            ComPtr<ID3D12CommandQueue> matchingQueue = SelectQueueForDevice(device.Get());
            if (!matchingQueue)
            {
                BackendLog("No stable direct command queue matching the game swap-chain device yet; initialization deferred.");
                return false;
            }
            g_commandQueue = matchingQueue;

            D3D12_DESCRIPTOR_HEAP_DESC rtvDesc{};
            rtvDesc.Type = D3D12_DESCRIPTOR_HEAP_TYPE_RTV;
            rtvDesc.NumDescriptors = desc.BufferCount;
            rtvDesc.Flags = D3D12_DESCRIPTOR_HEAP_FLAG_NONE;

            ComPtr<ID3D12DescriptorHeap> rtvHeap;
            if (FAILED(device->CreateDescriptorHeap(&rtvDesc, IID_PPV_ARGS(&rtvHeap))))
                return false;

            D3D12_DESCRIPTOR_HEAP_DESC srvDesc{};
            srvDesc.Type = D3D12_DESCRIPTOR_HEAP_TYPE_CBV_SRV_UAV;
            srvDesc.NumDescriptors = g_srvCapacity;
            srvDesc.Flags = D3D12_DESCRIPTOR_HEAP_FLAG_SHADER_VISIBLE;

            ComPtr<ID3D12DescriptorHeap> srvHeap;
            if (FAILED(device->CreateDescriptorHeap(&srvDesc, IID_PPV_ARGS(&srvHeap))))
                return false;

            std::vector<FrameContext> frames(desc.BufferCount);
            const UINT rtvStride = device->GetDescriptorHandleIncrementSize(D3D12_DESCRIPTOR_HEAP_TYPE_RTV);
            D3D12_CPU_DESCRIPTOR_HANDLE rtv = rtvHeap->GetCPUDescriptorHandleForHeapStart();

            for (UINT i = 0; i < desc.BufferCount; ++i)
            {
                if (FAILED(device->CreateCommandAllocator(D3D12_COMMAND_LIST_TYPE_DIRECT, IID_PPV_ARGS(&frames[i].allocator))))
                    return false;
                if (FAILED(swapChain->GetBuffer(i, IID_PPV_ARGS(&frames[i].backBuffer))))
                    return false;
                frames[i].rtv = rtv;
                device->CreateRenderTargetView(frames[i].backBuffer.Get(), nullptr, rtv);
                rtv.ptr += rtvStride;
            }

            ComPtr<ID3D12GraphicsCommandList> commandList;
            if (FAILED(device->CreateCommandList(0, D3D12_COMMAND_LIST_TYPE_DIRECT,
                frames[0].allocator.Get(), nullptr, IID_PPV_ARGS(&commandList))))
                return false;
            commandList->Close();

            ComPtr<ID3D12Fence> fence;
            if (FAILED(device->CreateFence(0, D3D12_FENCE_FLAG_NONE, IID_PPV_ARGS(&fence))))
                return false;
            HANDLE fenceEvent = CreateEventW(nullptr, FALSE, FALSE, nullptr);
            if (!fenceEvent)
                return false;

            if (ImGui::GetCurrentContext() == nullptr)
            {
                IMGUI_CHECKVERSION();
                ImGui::CreateContext();
                ImGui::StyleColorsDark();
                ImGuiIO& io = ImGui::GetIO();
                io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;
                io.IniFilename = nullptr; // Keep a bad dragged position from persisting across runs.
            }

            if (!ImGui_ImplWin32_Init(desc.OutputWindow))
                return false;

            g_srvHeap = srvHeap;
            g_srvStride = device->GetDescriptorHandleIncrementSize(D3D12_DESCRIPTOR_HEAP_TYPE_CBV_SRV_UAV);
            g_nextSrvIndex = 0;
            g_freeSrvIndices.clear();

            ImGui_ImplDX12_InitInfo initInfo{};
            initInfo.Device = device.Get();
            initInfo.CommandQueue = g_commandQueue.Get();
            initInfo.NumFramesInFlight = static_cast<int>(desc.BufferCount);
            initInfo.RTVFormat = desc.BufferDesc.Format;
            initInfo.DSVFormat = DXGI_FORMAT_UNKNOWN;
            initInfo.SrvDescriptorHeap = srvHeap.Get();
            initInfo.SrvDescriptorAllocFn = &SrvAlloc;
            initInfo.SrvDescriptorFreeFn = &SrvFree;

            if (!ImGui_ImplDX12_Init(&initInfo))
            {
                ImGui_ImplWin32_Shutdown();
                g_srvHeap.Reset();
                return false;
            }

            g_device = device;
            g_swapChain = swapChain;
            g_rtvHeap = rtvHeap;
            g_commandList = commandList;
            g_fence = fence;
            g_fenceEvent = fenceEvent;
            g_nextFenceValue = 1;
            g_frames = std::move(frames);
            g_rtvStride = rtvStride;
            g_backBufferFormat = desc.BufferDesc.Format;
            g_window = desc.OutputWindow;

            if (!g_originalWndProc)
            {
                SetLastError(0);
                auto oldProc = reinterpret_cast<WNDPROC>(SetWindowLongPtrW(
                    g_window, GWLP_WNDPROC, reinterpret_cast<LONG_PTR>(&WndProcDetour)));
                if (!oldProc && GetLastError() != 0)
                {
                    ImGui_ImplDX12_Shutdown();
                    ImGui_ImplWin32_Shutdown();
                    ReleaseFrameResources();
                    return false;
                }
                g_originalWndProc = oldProc;
            }

            research_imgui::SetBackendReady(true);
            g_ready.store(true);
            return true;
        }

        void __stdcall ExecuteCommandListsDetour(ID3D12CommandQueue* queue, UINT count, ID3D12CommandList* const* lists)
        {
            // Do not feed our own overlay submission back into queue selection.
            // Counting the ImGui command list made the selected queue appear
            // artificially busy and could cause periodic queue churn/stalls.
            bool isOverlaySubmission = false;
            if (g_commandList && lists)
            {
                for (UINT i = 0; i < count; ++i)
                {
                    if (lists[i] == g_commandList.Get())
                    {
                        isOverlaySubmission = true;
                        break;
                    }
                }
            }

            if (queue && !isOverlaySubmission)
            {
                const D3D12_COMMAND_QUEUE_DESC desc = queue->GetDesc();
                if (desc.Type == D3D12_COMMAND_LIST_TYPE_DIRECT)
                {
                    ComPtr<ID3D12Device> device;
                    if (SUCCEEDED(queue->GetDevice(IID_PPV_ARGS(&device))))
                    {
                        std::scoped_lock lock(g_mutex);
                        auto it = std::find_if(g_queueCandidates.begin(), g_queueCandidates.end(),
                            [queue](const QueueCandidate& candidate)
                            {
                                return candidate.queue.Get() == queue;
                            });
                        if (it == g_queueCandidates.end())
                        {
                            QueueCandidate candidate{};
                            candidate.queue = queue;
                            candidate.device = device;
                            candidate.lastSeen = GetTickCount64();
                            candidate.executeCount = 1;
                            g_queueCandidates.push_back(std::move(candidate));
                            BackendLog("Observed a direct command queue candidate.");
                        }
                        else
                        {
                            it->lastSeen = GetTickCount64();
                            ++it->executeCount;
                        }
                    }
                }
            }
            if (g_originalExecuteCommandLists)
                g_originalExecuteCommandLists(queue, count, lists);
        }

        bool IsGameWindowForeground()
        {
            if (!g_window)
                return false;
            HWND foreground = GetForegroundWindow();
            if (!foreground)
                return false;
            return foreground == g_window || GetAncestor(foreground, GA_ROOT) == g_window;
        }

        void CloseInteractiveOverlaysForFocusLoss()
        {
            research_imgui::SetVisible(false);
            research_imgui::SetConsoleVisible(false);
            research_imgui::SetServerBrowserVisible(false);
            research_imgui::SetChatInputVisible(false);
            g_menuRequested.store(false);
            ApplyExclusiveInputState(false);
        }

        void HandleOverlayToggle()
        {
            static bool insertWasDown = false;
            static bool tildeWasDown = false;
            static bool f1WasDown = false;
            static bool tWasDown = false;
            static bool escapeWasDown = false;
            static ULONGLONG lastInsertToggle = 0;
            static ULONGLONG lastTildeToggle = 0;
            static ULONGLONG lastF1Toggle = 0;
            static ULONGLONG lastChatToggle = 0;

            const ULONGLONG now = GetTickCount64();
            const bool insertDown = (PollPhysicalKey(VK_INSERT) & 0x8000) != 0;
            const bool tildeDown = (PollPhysicalKey(VK_OEM_3) & 0x8000) != 0;
            const bool f1Down = (PollPhysicalKey(VK_F1) & 0x8000) != 0;
            const bool tDown = (PollPhysicalKey('T') & 0x8000) != 0;
            const bool escapeDown = (PollPhysicalKey(VK_ESCAPE) & 0x8000) != 0;

            // Global key polling must never activate or feed an overlay while the
            // user is tabbed out. Close any active input surface immediately and
            // synchronize edge state so held keys do not reopen it on Alt-Tab back.
            if (!IsGameWindowForeground())
            {
                if (research_imgui::IsInteractiveVisible())
                    CloseInteractiveOverlaysForFocusLoss();
                insertWasDown = insertDown;
                tildeWasDown = tildeDown;
                f1WasDown = f1Down;
                tWasDown = tDown;
                escapeWasDown = escapeDown;
                return;
            }

            if (insertDown && !insertWasDown && (now - lastInsertToggle) >= 250)
            {
                lastInsertToggle = now;
                const bool next = !research_imgui::IsVisible();
                research_imgui::SetVisible(next);
                g_menuRequested.store(next);
                ApplyExclusiveInputState(research_imgui::IsInteractiveVisible() && g_ready.load());
                BackendLog(next ? "INSERT: research dashboard opened." : "INSERT: research dashboard hidden.");
            }

            if (tildeDown && !tildeWasDown && (now - lastTildeToggle) >= 250)
            {
                lastTildeToggle = now;
                const bool next = !research_imgui::IsConsoleVisible();
                research_imgui::SetConsoleVisible(next);
                g_menuRequested.store(next || research_imgui::IsVisible());
                ApplyExclusiveInputState(research_imgui::IsInteractiveVisible() && g_ready.load());
                BackendLog(next ? "TILDE: T9 Client developer console opened." : "TILDE: T9 Client developer console closed.");
            }

            if (f1Down && !f1WasDown && (now - lastF1Toggle) >= 250)
            {
                lastF1Toggle = now;
                const bool next = !research_imgui::IsServerBrowserVisible();
                research_imgui::SetServerBrowserVisible(next);
                g_menuRequested.store(next || research_imgui::IsVisible() || research_imgui::IsConsoleVisible());
                ApplyExclusiveInputState(research_imgui::IsInteractiveVisible() && g_ready.load());
                BackendLog(next ? "F1: LAN server browser opened." : "F1: LAN server browser closed.");
            }

            // T opens chat only from normal gameplay. It is deliberately ignored
            // while another overlay owns keyboard focus so typing into the console
            // or dashboard cannot accidentally open chat.
            if (tDown && !tWasDown && (now - lastChatToggle) >= 250 &&
                !research_imgui::IsVisible() && !research_imgui::IsConsoleVisible() &&
                !research_imgui::IsServerBrowserVisible())
            {
                lastChatToggle = now;
                research_imgui::SetChatInputVisible(true);
                g_menuRequested.store(true);
                ApplyExclusiveInputState(g_ready.load());
                BackendLog("T: LAN text chat opened.");
            }

            if (escapeDown && !escapeWasDown)
            {
                if (research_imgui::IsChatInputVisible())
                    research_imgui::SetChatInputVisible(false);
                else if (research_imgui::IsServerBrowserVisible())
                    research_imgui::SetServerBrowserVisible(false);
                ApplyExclusiveInputState(research_imgui::IsInteractiveVisible() && g_ready.load());
            }

            insertWasDown = insertDown;
            tildeWasDown = tildeDown;
            f1WasDown = f1Down;
            tWasDown = tDown;
            escapeWasDown = escapeDown;
        }

        bool InitializeBackendAfterPresent(IDXGISwapChain* swapChain)
        {
            if (!swapChain || g_ready.load() || g_renderFaulted.load() || !research_imgui::WantsBackend())
                return g_ready.load();

            std::scoped_lock lock(g_mutex);
            if (g_ready.load())
                return true;
            if (!IsUsableGameSwapChain(swapChain))
                return false;

            BackendLog("Attempting guarded ImGui initialization on validated game swap chain.");
            if (!CreateRenderResources(swapChain))
            {
                // Do not close the menu request or crash the game. Keep waiting until
                // the matching game command queue has been observed and stabilized.
                return false;
            }

            ApplyExclusiveInputState(research_imgui::IsInteractiveVisible());
            BackendLog("ImGui Win32/DX12 backend initialized safely after Present.");
            return true;
        }

        void InitializeBackendAfterPresentSafe(IDXGISwapChain* swapChain)
        {
            __try
            {
                InitializeBackendAfterPresent(swapChain);
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                g_renderFaulted.store(true);
                research_imgui::SetVisible(false);
                research_imgui::SetConsoleVisible(false);
                g_menuRequested.store(false);
                ApplyExclusiveInputState(false);
                research_imgui::SetBackendReady(false);
                BackendLog("Exception during post-Present ImGui initialization; overlay disabled for this run.");
            }
        }

        void RenderPresentFrame(IDXGISwapChain* swapChain)
        {
            if (g_renderFaulted.load() || !g_ready.load())
                return;

            ApplyExclusiveInputState(research_imgui::IsInteractiveVisible());

            std::scoped_lock lock(g_mutex);
            if (!g_swapChain || !g_commandQueue || !g_commandList || g_frames.empty() || !g_fence)
                return;

            const UINT frameIndex = g_swapChain->GetCurrentBackBufferIndex();
            if (frameIndex >= g_frames.size())
                return;

            FrameContext& frame = g_frames[frameIndex];
            if (!IsFrameReady(frame))
                return;
            if (FAILED(frame.allocator->Reset()) ||
                FAILED(g_commandList->Reset(frame.allocator.Get(), nullptr)))
                return;

            D3D12_RESOURCE_BARRIER barrier{};
            barrier.Type = D3D12_RESOURCE_BARRIER_TYPE_TRANSITION;
            barrier.Transition.pResource = frame.backBuffer.Get();
            barrier.Transition.Subresource = D3D12_RESOURCE_BARRIER_ALL_SUBRESOURCES;
            barrier.Transition.StateBefore = D3D12_RESOURCE_STATE_PRESENT;
            barrier.Transition.StateAfter = D3D12_RESOURCE_STATE_RENDER_TARGET;
            g_commandList->ResourceBarrier(1, &barrier);
            g_commandList->OMSetRenderTargets(1, &frame.rtv, FALSE, nullptr);
            ID3D12DescriptorHeap* heaps[] = { g_srvHeap.Get() };
            g_commandList->SetDescriptorHeaps(1, heaps);

            ImGui_ImplDX12_NewFrame();
            ImGui_ImplWin32_NewFrame();
            ImGui::NewFrame();
            research_imgui::Render();
            if (!research_imgui::IsInteractiveVisible())
                ApplyExclusiveInputState(false);
            ImGui::Render();
            ImGui_ImplDX12_RenderDrawData(ImGui::GetDrawData(), g_commandList.Get());

            std::swap(barrier.Transition.StateBefore, barrier.Transition.StateAfter);
            g_commandList->ResourceBarrier(1, &barrier);
            if (FAILED(g_commandList->Close()))
                return;

            ID3D12CommandList* lists[] = { g_commandList.Get() };
            g_commandQueue->ExecuteCommandLists(1, lists);
            const UINT64 fenceValue = g_nextFenceValue++;
            if (SUCCEEDED(g_commandQueue->Signal(g_fence.Get(), fenceValue)))
                frame.fenceValue = fenceValue;
        }

        void RenderPresentFrameSafe(IDXGISwapChain* swapChain)
        {
            __try
            {
                RenderPresentFrame(swapChain);
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                g_renderFaulted.store(true);
                research_imgui::SetVisible(false);
                research_imgui::SetConsoleVisible(false);
                ApplyExclusiveInputState(false);
                research_imgui::SetBackendReady(false);
                BackendLog("Exception in ImGui Present path; rendering disabled for this run.");
            }
        }

        HRESULT __stdcall PresentDetour(IDXGISwapChain* swapChain, UINT syncInterval, UINT flags)
        {
            if (!g_originalPresent)
                return E_FAIL;

            if (g_shuttingDown.load() || !swapChain)
                return g_originalPresent(swapChain, syncInterval, flags);

            // MH_EnableHook can redirect a Present call before InstallHooks has
            // finished enabling the complete hook set. Never initialize ImGui or
            // touch overlay state from that partial-install window.
            if (g_installingHooks.load() || !g_hooksInstalled.load())
                return g_originalPresent(swapChain, syncInterval, flags);

            HandleOverlayToggle();

            // Creating the ImGui font texture can submit work and wait on the
            // captured queue. Doing that while the game is inside its pre-Present
            // path can deadlock the render thread. Let the original Present finish
            // first, then initialize only. Rendering begins on the next frame.
            if (research_imgui::WantsBackend() && !g_ready.load() && !g_renderFaulted.load())
            {
                const HRESULT result = g_originalPresent(swapChain, syncInterval, flags);
                // Only attempt initialization for the actual visible game swap chain.
                // Steam/Discord/other overlay swap chains are ignored.
                if (IsUsableGameSwapChain(swapChain))
                    InitializeBackendAfterPresentSafe(swapChain);
                return result;
            }

            if (g_ready.load() && !g_renderFaulted.load())
                RenderPresentFrameSafe(swapChain);

            return g_originalPresent(swapChain, syncInterval, flags);
        }

        HRESULT __stdcall ResizeBuffersDetour(IDXGISwapChain* swapChain, UINT bufferCount, UINT width,
            UINT height, DXGI_FORMAT newFormat, UINT swapChainFlags)
        {
            if (g_ready.load())
            {
                std::scoped_lock lock(g_mutex);
                RestoreWndProc();
                ReleaseFrameResources();
                BackendLog("Swap-chain resize observed; ImGui resources released for lazy rebuild.");
            }
            return g_originalResizeBuffers ? g_originalResizeBuffers(swapChain, bufferCount, width, height, newFormat, swapChainFlags) : E_FAIL;
        }

        LRESULT CALLBACK DummyWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
        {
            return DefWindowProcW(hwnd, msg, wParam, lParam);
        }

        bool DiscoverMethods(void** present, void** resizeBuffers, void** executeCommandLists)
        {
            *present = nullptr;
            *resizeBuffers = nullptr;
            *executeCommandLists = nullptr;

            const wchar_t* className = L"IWScanner_ImGui_DX12_Discovery";
            WNDCLASSEXW wc{};
            wc.cbSize = sizeof(wc);
            wc.lpfnWndProc = DummyWndProc;
            wc.hInstance = GetModuleHandleW(nullptr);
            wc.lpszClassName = className;
            RegisterClassExW(&wc);

            HWND window = CreateWindowExW(0, className, L"", WS_OVERLAPPEDWINDOW,
                0, 0, 100, 100, nullptr, nullptr, wc.hInstance, nullptr);
            if (!window)
                return false;

            ComPtr<IDXGIFactory4> factory;
            ComPtr<ID3D12Device> device;
            ComPtr<ID3D12CommandQueue> queue;
            ComPtr<IDXGISwapChain1> swapChain1;

            bool success = false;
            if (SUCCEEDED(CreateSystemDXGIFactory1(IID_PPV_ARGS(&factory))) &&
                SUCCEEDED(D3D12CreateDevice(nullptr, D3D_FEATURE_LEVEL_11_0, IID_PPV_ARGS(&device))))
            {
                D3D12_COMMAND_QUEUE_DESC queueDesc{};
                queueDesc.Type = D3D12_COMMAND_LIST_TYPE_DIRECT;
                if (SUCCEEDED(device->CreateCommandQueue(&queueDesc, IID_PPV_ARGS(&queue))))
                {
                    DXGI_SWAP_CHAIN_DESC1 swapDesc{};
                    swapDesc.BufferCount = 2;
                    swapDesc.Width = 100;
                    swapDesc.Height = 100;
                    swapDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
                    swapDesc.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
                    swapDesc.SwapEffect = DXGI_SWAP_EFFECT_FLIP_DISCARD;
                    swapDesc.SampleDesc.Count = 1;

                    if (SUCCEEDED(factory->CreateSwapChainForHwnd(queue.Get(), window, &swapDesc,
                        nullptr, nullptr, &swapChain1)))
                    {
                        void** swapVtable = *reinterpret_cast<void***>(swapChain1.Get());
                        void** queueVtable = *reinterpret_cast<void***>(queue.Get());
                        *present = swapVtable[8];
                        *resizeBuffers = swapVtable[13];
                        *executeCommandLists = queueVtable[10];
                        success = *present && *resizeBuffers && *executeCommandLists;
                    }
                }
            }

            DestroyWindow(window);
            UnregisterClassW(className, wc.hInstance);
            return success;
        }
    }

    bool InstallCamoCaptureHooks()
    {
        // The release camo path only needs a live ID3D12Device + direct command
        // queue. Capturing ExecuteCommandLists is enough to discover those.
        // Do NOT hook Present/ResizeBuffers/WndProc or initialize ImGui here.
        if (g_camoCaptureHooksInstalled.load() || g_hooksInstalled.load())
            return true;

        void* present = nullptr;
        void* resizeBuffers = nullptr;
        void* executeCommandLists = nullptr;
        if (!DiscoverMethods(&present, &resizeBuffers, &executeCommandLists) || !executeCommandLists)
            return false;

        const MH_STATUS init = MH_Initialize();
        if (init != MH_OK && init != MH_ERROR_ALREADY_INITIALIZED)
            return false;

        const MH_STATUS created = MH_CreateHook(
            executeCommandLists,
            reinterpret_cast<LPVOID>(&ExecuteCommandListsDetour),
            reinterpret_cast<void**>(&g_originalExecuteCommandLists));
        if (created != MH_OK && created != MH_ERROR_ALREADY_CREATED)
            return false;

        const MH_STATUS enabled = MH_EnableHook(executeCommandLists);
        if (enabled != MH_OK && enabled != MH_ERROR_ENABLED)
        {
            if (created == MH_OK)
                MH_RemoveHook(executeCommandLists);
            return false;
        }

        g_executeCommandListsTarget = executeCommandLists;
        g_camoCaptureHooksInstalled.store(true);
        BackendLog("Release camo queue capture active (ExecuteCommandLists only; ImGui/Present hooks disabled).");
        return true;
    }

    namespace
    {
        bool InstallCamoCaptureHooksSehBridge()
        {
            __try
            {
                return InstallCamoCaptureHooks();
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                BackendLog("SEH fault while installing release camo queue capture; camo backend left disabled.");
                return false;
            }
        }
    }

    bool InstallCamoCaptureHooksGuarded()
    {
        if (g_camoCaptureHooksInstalled.load() || g_hooksInstalled.load())
            return true;

        try
        {
            return InstallCamoCaptureHooksSehBridge();
        }
        catch (const std::exception& exception)
        {
            BackendLog((std::string("C++ exception while installing release camo queue capture: ") + exception.what()).c_str());
        }
        catch (...)
        {
            BackendLog("Unknown exception while installing release camo queue capture.");
        }
        g_camoCaptureHooksInstalled.store(false);
        return false;
    }

    bool InstallHooks()
    {
        if (g_hooksInstalled.load())
            return true;

        void* present = nullptr;
        void* resizeBuffers = nullptr;
        void* executeCommandLists = nullptr;
        if (!DiscoverMethods(&present, &resizeBuffers, &executeCommandLists))
            return false;

        const MH_STATUS init = MH_Initialize();
        if (init != MH_OK && init != MH_ERROR_ALREADY_INITIALIZED)
            return false;

        g_installingHooks.store(true);
        BackendLog("Installing staged DX12 hooks (all overlay work blocked until installation completes).");
        if (MH_CreateHook(executeCommandLists, reinterpret_cast<LPVOID>(&ExecuteCommandListsDetour),
                reinterpret_cast<void**>(&g_originalExecuteCommandLists)) != MH_OK)
        {
            g_installingHooks.store(false);
            return false;
        }
        if (MH_CreateHook(present, reinterpret_cast<LPVOID>(&PresentDetour), reinterpret_cast<void**>(&g_originalPresent)) != MH_OK)
        {
            MH_RemoveHook(executeCommandLists);
            g_installingHooks.store(false);
            return false;
        }
        if (MH_CreateHook(resizeBuffers, reinterpret_cast<LPVOID>(&ResizeBuffersDetour), reinterpret_cast<void**>(&g_originalResizeBuffers)) != MH_OK)
        {
            MH_RemoveHook(present);
            MH_RemoveHook(executeCommandLists);
            g_installingHooks.store(false);
            return false;
        }

        // Capture the command queue first. Present is safe because it performs no
        // rendering or resource creation until the user explicitly presses INSERT.
        if (MH_EnableHook(executeCommandLists) != MH_OK ||
            MH_EnableHook(present) != MH_OK ||
            MH_EnableHook(resizeBuffers) != MH_OK)
        {
            MH_DisableHook(executeCommandLists);
            MH_DisableHook(present);
            MH_DisableHook(resizeBuffers);
            g_installingHooks.store(false);
            return false;
        }

        // Do not detour process-wide User32 keyboard/raw-input exports here.
        // Hooking these exports affects the game, Steam, NVIDIA, Discord and ImGui
        // simultaneously and has caused startup crashes on this build. Input is
        // isolated through the game-window WndProc and latched-key release path.
        // A future game-specific input hook can be installed only after its exact
        // T9 function and calling convention are validated.
        BackendLog("Process-wide keyboard/raw-input hooks disabled for stability; WndProc input isolation active.");

        // Publish the completed state only after all hooks are enabled.
        // PresentDetour may run immediately on another thread, so ordering here
        // is intentional.
        g_executeCommandListsTarget = executeCommandLists;
        g_hooksInstalled.store(true);
        g_installingHooks.store(false);
        BackendLog("DX12 hooks active; deferred overlay initialization may begin on the next game frame.");
        return true;
    }

    namespace
    {
        bool InstallHooksSehBridge()
        {
            __try
            {
                return InstallHooks();
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                BackendLog("SEH fault while installing DX12 hooks; overlay stage disabled.");
                return false;
            }
        }
    }

    bool InstallHooksGuarded()
    {
        if (g_hooksInstalled.load())
            return true;

        bool installed = false;
        try
        {
            installed = InstallHooksSehBridge();
        }
        catch (const std::exception& exception)
        {
            BackendLog((std::string("C++ exception while installing DX12 hooks: ") + exception.what()).c_str());
            installed = false;
        }
        catch (...)
        {
            BackendLog("Unknown exception while installing DX12 hooks; overlay stage disabled.");
            installed = false;
        }

        if (!installed)
        {
            g_installingHooks.store(false);
            g_hooksInstalled.store(false);
            g_menuRequested.store(false);
            research_imgui::SetVisible(false);
            research_imgui::SetBackendReady(false);
        }
        return installed;
    }

    void Shutdown()
    {
        g_shuttingDown.store(true);
        if (g_getAsyncKeyStateTarget) MH_DisableHook(g_getAsyncKeyStateTarget);
        if (g_getKeyStateTarget) MH_DisableHook(g_getKeyStateTarget);
        if (g_getKeyboardStateTarget) MH_DisableHook(g_getKeyboardStateTarget);
        if (g_getRawInputDataTarget) MH_DisableHook(g_getRawInputDataTarget);
        if (g_getRawInputBufferTarget) MH_DisableHook(g_getRawInputBufferTarget);
        if (g_executeCommandListsTarget) MH_DisableHook(g_executeCommandListsTarget);
        client_services::Shutdown();
        ApplyExclusiveInputState(false);
        std::scoped_lock lock(g_mutex);
        RestoreWndProc();
        ReleaseFrameResources();
        if (ImGui::GetCurrentContext())
            ImGui::DestroyContext();
        g_installingHooks.store(false);
        g_hooksInstalled.store(false);
        g_camoCaptureHooksInstalled.store(false);
        g_executeCommandListsTarget = nullptr;
        g_queueCandidates.clear();
        g_commandQueue.Reset();
        g_menuRequested.store(false);
        g_renderFaulted.store(false);
    }

    bool IsReady()
    {
        return g_ready.load();
    }

    bool HooksInstalled()
    {
        return g_hooksInstalled.load();
    }
    ID3D12Device* AcquireD3D12Device()
    {
        std::scoped_lock lock(g_mutex);
        ID3D12Device* p = g_device.Get();
        if (!p)
        {
            QueueCandidate* best = nullptr;
            const ULONGLONG now = GetTickCount64();
            for (auto& candidate : g_queueCandidates)
            {
                if (!candidate.device || !candidate.queue ||
                    (now - candidate.lastSeen) > 10000)
                    continue;
                if (!best || candidate.executeCount > best->executeCount ||
                    (candidate.executeCount == best->executeCount && candidate.lastSeen > best->lastSeen))
                    best = &candidate;
            }
            if (best)
                p = best->device.Get();
        }
        if (p) p->AddRef();
        return p;
    }

    ID3D12CommandQueue* AcquireD3D12CommandQueue()
    {
        std::scoped_lock lock(g_mutex);
        ID3D12CommandQueue* p = g_commandQueue.Get();
        if (!p)
        {
            QueueCandidate* best = nullptr;
            const ULONGLONG now = GetTickCount64();
            for (auto& candidate : g_queueCandidates)
            {
                if (!candidate.device || !candidate.queue ||
                    (now - candidate.lastSeen) > 10000)
                    continue;
                if (!best || candidate.executeCount > best->executeCount ||
                    (candidate.executeCount == best->executeCount && candidate.lastSeen > best->lastSeen))
                    best = &candidate;
            }
            if (best)
                p = best->queue.Get();
        }
        if (p) p->AddRef();
        return p;
    }

}

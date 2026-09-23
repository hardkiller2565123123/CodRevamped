#pragma once

struct ID3D12Device;
struct ID3D12CommandQueue;

namespace imgui_backend_bridge
{
    // Installs generic DX12 hooks using a temporary swap chain. Call only after
    // the game's native frontend is ready. The real device/queue/swap chain are
    // captured from the game on its next Present/ExecuteCommandLists calls.
    bool InstallHooks();
    bool InstallHooksGuarded();
    // Release path: capture only the game's D3D12 direct queue for custom-camo uploads.
    // No Present/Resize/WndProc/ImGui/client-service hooks are installed.
    bool InstallCamoCaptureHooks();
    bool InstallCamoCaptureHooksGuarded();
    void Shutdown();
    bool IsReady();
    bool HooksInstalled();
    ID3D12Device* AcquireD3D12Device();
    ID3D12CommandQueue* AcquireD3D12CommandQueue();
}

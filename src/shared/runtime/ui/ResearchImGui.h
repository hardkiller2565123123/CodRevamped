#pragma once

namespace research_imgui
{
    using CommandExecutor = bool(*)(const char* command);

    void SetVisible(bool visible);
    bool IsVisible();
    void SetConsoleVisible(bool visible);
    bool IsConsoleVisible();
    void SetServerBrowserVisible(bool visible);
    bool IsServerBrowserVisible();
    void SetChatInputVisible(bool visible);
    bool IsChatInputVisible();
    bool IsInteractiveVisible();
    bool WantsMouseCursor();
    bool WantsBackend();
    void SetBackendReady(bool ready);
    bool BackendAvailable();
    void ConfigureCommandExecutor(CommandExecutor executor);
    bool ExclusiveInputEnabled();
    void Render();
}

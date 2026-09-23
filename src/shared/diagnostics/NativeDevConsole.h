#pragma once

namespace native_dev_console
{
    // Starts passive/automatic discovery of the native rendering, input and command
    // primitives required for a game-rendered developer console. No ImGui console,
    // fake toggleconsole command, or manual scan step is used.
    void StartAsync();
    bool Ready();
}

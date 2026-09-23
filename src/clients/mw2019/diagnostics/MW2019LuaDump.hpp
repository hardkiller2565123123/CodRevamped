#pragma once

namespace mw2019_lua
{
    void Initialize() noexcept;
    void Tick(unsigned long long uptimeMs) noexcept;
    void DumpNow(const char* reason) noexcept;
}

#pragma once

namespace mw2019_network
{
    void Initialize() noexcept;
    void Tick(unsigned long long uptimeMs) noexcept;
    bool IsEnabled() noexcept;
}

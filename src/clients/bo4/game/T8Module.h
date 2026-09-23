#pragma once
#include "../../../shared/compat/games/common/IGameModule.h"
namespace games
{
    class T8Module final : public IGameModule
    {
    public:
        GameKind Kind() const noexcept override;
        const char* Name() const noexcept override;
        bool Matches(const ExecutableInfo& image) const noexcept override;
        DWORD Initialize(const ExecutableInfo& image) noexcept override;
    };
}

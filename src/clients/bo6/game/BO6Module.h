#pragma once
#include "../../../shared/compat/games/common/IGameModule.h"

namespace games
{
    enum class BO6Variant
    {
        Unknown,
        Beta,
        Retail
    };

    class BO6Module final : public IGameModule
    {
    public:
        GameKind Kind() const noexcept override;
        const char* Name() const noexcept override;
        bool Matches(const ExecutableInfo& image) const noexcept override;
        DWORD Initialize(const ExecutableInfo& image) noexcept override;

        static BO6Variant DetectVariant(const ExecutableInfo& image) noexcept;
        static const char* VariantName(BO6Variant variant) noexcept;
    };
}

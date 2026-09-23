#pragma once
#include "../../../shared/compat/games/common/IGameModule.h"
#include "IW8Addresses.h"
#include "IW8144Compat.h"

namespace games
{
    enum class IW8Variant
    {
        Unknown,
        Beta2019,
        Steam169,
        Steam167LegacyDisabled,
        Legacy144
    };

    class IW8Module final : public IGameModule
    {
    public:
        GameKind Kind() const noexcept override;
        const char* Name() const noexcept override;
        bool Matches(const ExecutableInfo& image) const noexcept override;
        DWORD Initialize(const ExecutableInfo& image) noexcept override;
        static IW8Variant DetectVariant(const ExecutableInfo& image) noexcept;
        static const char* VariantName(IW8Variant variant) noexcept;
    };
}

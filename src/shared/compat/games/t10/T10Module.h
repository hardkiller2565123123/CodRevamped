#pragma once
#include "../common/IGameModule.h"
#include "T10Addresses.h"

namespace games
{
    class T10Module final : public IGameModule
    {
    public:
        GameKind Kind() const noexcept override;
        const char* Name() const noexcept override;
        bool Matches(const ExecutableInfo& image) const noexcept override;
        DWORD Initialize(const ExecutableInfo& image) noexcept override;

        static t10_addresses::Variant DetectVariant(
            const ExecutableInfo& image) noexcept;
        static const char* VariantName(
            t10_addresses::Variant variant) noexcept;
    };
}

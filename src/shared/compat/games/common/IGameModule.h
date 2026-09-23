#pragma once
#include "GameTypes.h"

namespace games
{
    class IGameModule
    {
    public:
        virtual ~IGameModule() = default;
        virtual GameKind Kind() const noexcept = 0;
        virtual const char* Name() const noexcept = 0;
        virtual bool Matches(const ExecutableInfo& image) const noexcept = 0;
        virtual DWORD Initialize(const ExecutableInfo& image) noexcept = 0;
    };
}

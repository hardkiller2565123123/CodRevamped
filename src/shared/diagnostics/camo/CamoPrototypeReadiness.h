#pragma once
#include <string>

namespace camo_prototype_readiness
{
    // Read-only readiness API for the research build.
    // This does not allocate/register a custom asset yet.
    bool IsReady();
    std::string Summary();
}

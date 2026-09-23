#pragma once
#include <string>

namespace camo_manager
{
    bool Status(std::string& message);
    bool Dump(std::string& message);

    // One command now inspects every allocated weapon camo and scans its
    // definition block for references into the binding/material/image pools.
    bool InspectAll(std::string& message);
    bool ScanCamo(std::string& message, bool deep = false);

    bool Replace(unsigned int targetIndex, unsigned int sourceIndex, std::string& message);
    bool Restore(unsigned int targetIndex, std::string& message);

    bool CustomList(std::string& message);
    bool CustomInspect(const std::string& packageName, std::string& message);
    bool CustomStage(const std::string& packageName, unsigned int targetIndex, std::string& message);
    bool CustomApply(const std::string& packageName, unsigned int targetIndex, std::string& message);
    bool CustomApplyConfigured(const std::string& packageName, std::string& message);
    void StartAutoApply();
    void StartDefaultBo4DiamondAutoApply();
    bool CustomRestore(unsigned int targetIndex, std::string& message);
    bool CustomAnalyzeImages(unsigned int targetIndex, std::string& message);
    bool CustomTestImage(unsigned int targetIndex, unsigned int candidateIndex, std::string& message);
    bool CustomTestRestore(unsigned int targetIndex, std::string& message);
    bool CustomNextImage(unsigned int targetIndex, std::string& message);
    bool CustomPrevImage(unsigned int targetIndex, std::string& message);
    bool CustomTestStatus(unsigned int targetIndex, std::string& message);
    bool CustomKeepImage(unsigned int targetIndex, const std::string& role, std::string& message);
}


namespace camo_manager
{
    struct AllocatorResearchSnapshot
    {
        std::uintptr_t weaponCamoPool = 0;
        std::uintptr_t weaponCamoBindingPool = 0;
        std::uintptr_t weaponCamoFreeHead = 0;
        unsigned int weaponCamoItemAllocCount = 0;
        std::uintptr_t weaponCamoBindingFreeHead = 0;
        unsigned int weaponCamoBindingItemAllocCount = 0;
    };

    bool GetAllocatorResearchSnapshot(
        AllocatorResearchSnapshot& out);
    bool TryResolveAllocatorResearchSnapshotEarly(
        AllocatorResearchSnapshot& out);
}

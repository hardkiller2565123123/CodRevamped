#include "com_optimized.h"
#ifdef REPLAY_COMPILER_OPTIMIZED
#include "com_debugstates.h"

extern "C" {
dvar_t* com_optimized = nullptr;
uint32_t s_comOptimizedMode = 0;
uint32_t s_comOptimizedTransitions = 0;
uint32_t s_comOptimizedDvarWrites = 0;
}

namespace {
struct ComOptimizedDvar {
    const char* name;
    uint8_t type;
    int value;
    uint8_t minimumMode;
    dvar_t* captured;
    uint32_t checksum;
    DvarValue savedCurrent;
    DvarValue savedLatched;
};

// Types and enum entries are verified in this Replay's registrations
// and serialized enum tables, rather than borrowed from another game build.
ComOptimizedDvar s_settings[] = {
    {"lui_gc_use_new_frontend_collect", 0, 1, 1, nullptr, 0, {}, {}},
    {"lui_gc_allocated_time", 5, 8000, 1, nullptr, 0, {}, {}},
    {"lui_gc_step_size", 5, 0, 1, nullptr, 0, {}, {}},
    {"r_ssao", 8, 0, 2, nullptr, 0, {}, {}},
    {"r_ssrMode", 8, 0, 2, nullptr, 0, {}, {}},
    // Native off branch drains pending probe stages, then stops issuing new
    // relighting work. Probe resources and synchronization remain engine-owned.
    {"r_reflectionProbeLightingEnabled", 0, 0, 2, nullptr, 0, {}, {}},
    {"r_postAA", 8, 0, 2, nullptr, 0, {}, {}},
    {"r_dof_enable", 0, 0, 2, nullptr, 0, {}, {}},
    {"r_mbEnable", 8, 0, 2, nullptr, 0, {}, {}},
    {"r_mbEnableA", 0, 0, 2, nullptr, 0, {}, {}},
    {"sm_sunEnable", 0, 0, 2, nullptr, 0, {}, {}},
    {"sm_spotEnable", 0, 0, 2, nullptr, 0, {}, {}},
    {"sm_sunFarShadows", 0, 0, 2, nullptr, 0, {}, {}},
    {"r_spotLightShadows", 0, 0, 2, nullptr, 0, {}, {}},
    {"r_transShadowEnable", 0, 0, 2, nullptr, 0, {}, {}},
    {"r_volumetrics", 0, 0, 2, nullptr, 0, {}, {}},
    {"r_fog", 0, 0, 2, nullptr, 0, {}, {}},
    {"r_distortion", 0, 0, 2, nullptr, 0, {}, {}},
    // This disables the SSS contribution; the engine retains any shared filter.
    {"r_sssEnable", 0, 0, 2, nullptr, 0, {}, {}},
    // Eliminate extra subdivision and displacement through native fallbacks.
    {"r_subdiv", 0, 0, 2, nullptr, 0, {}, {}},
    {"r_subdivLimit", 5, 0, 2, nullptr, 0, {}, {}},
    {"r_tessellation", 8, 0, 2, nullptr, 0, {}, {}},
    {"r_tessellationOverride", 5, 0, 2, nullptr, 0, {}, {}},
    // Use the engine's own FX off path, including processing and drawing.
    {"fx_enable", 0, 0, 2, nullptr, 0, {}, {}},
    {"fx_draw", 0, 0, 2, nullptr, 0, {}, {}},
    {"fx_draw_spotLight", 0, 0, 2, nullptr, 0, {}, {}},
    {"fx_draw_omniLight", 0, 0, 2, nullptr, 0, {}, {}},
    // Replay registrations prove these runtime controls and their domains.
    // Shader LOD 1 uses the shipped low-detail material path.
    {"r_materialLodOverride", 5, 1, 2, nullptr, 0, {}, {}},
    {"r_materialLodMin", 5, 1, 2, nullptr, 0, {}, {}},
    {"r_decalVolumes", 0, 0, 2, nullptr, 0, {}, {}},
    {"r_decalVolumesStatic", 0, 0, 2, nullptr, 0, {}, {}},
    {"r_decalVolumesObjSpaceModel", 0, 0, 2, nullptr, 0, {}, {}},
    {"r_decalVolumesMaxVisible", 5, 0, 2, nullptr, 0, {}, {}},
    {"r_reactiveMotionClutter", 0, 0, 2, nullptr, 0, {}, {}},
    // Native wait paths can process eligible jobs instead of yielding idle.
    {"r_smp_workercmds_on_render", 0, 1, 1, nullptr, 0, {}, {}},
    {"r_smp_workercmds_on_frontend", 0, 1, 1, nullptr, 0, {}, {}},
    {"r_smp_workercmds_on_server", 0, 1, 1, nullptr, 0, {}, {}},
    // Dynamic material samplers: point filtering and point mip selection.
    // Mip mode 0 would disable mipmaps and increase texture bandwidth.
    {"r_texFilter", 8, 0, 2, nullptr, 0, {}, {}},
    {"r_texFilterMipMode", 8, 1, 2, nullptr, 0, {}, {}},
    {"r_texFilterMipBias", 1, 3, 2, nullptr, 0, {}, {}},
    // Native image semantics exempt no-picmip images; the streamer owns
    // residency, synchronization and coarse-to-fine restoration on toggles.
    {"r_picmip", 5, 3, 2, nullptr, 0, {}, {}},
    {"r_picmip_bump", 5, 3, 2, nullptr, 0, {}, {}},
    {"r_picmip_spec", 5, 3, 2, nullptr, 0, {}, {}},
    // Mark generation has its own enable path, separate from particle FX.
    // This experimental mode also hides tracker-perk ground marks.
    {"fx_marks_all", 0, 0, 2, nullptr, 0, {}, {}},
    {"fx_marks", 0, 0, 2, nullptr, 0, {}, {}},
    // Use native client animation LODs earlier; clocks/notifies remain native.
    {"cg_animLODScale", 1, 100, 2, nullptr, 0, {}, {}},
    // Cosmetic foot pinning, independent of weapon/hand IK and collision.
    {"xanim_ik_antislide_enable", 0, 0, 2, nullptr, 0, {}, {}},
};
unsigned s_refreshFrames = 0;

bool Matches(const dvar_t* dvar, const ComOptimizedDvar& setting) {
    if (setting.type == 0) return dvar->current.enabled == (setting.value != 0);
    // Profile floats are deliberately integer-valued. Compare as float,
    // preserving the complete native union when capturing/restoring values.
    if (setting.type == 1) return dvar->current.value == float(setting.value);
    return dvar->current.integer == setting.value;
}

void Set(dvar_t* dvar, const DvarValue& value) {
    // Preserve native validation, modified flags and server synchronization.
    // These controls are runtime values; no latched-only or read-only flags.
    alignas(16) const DvarValue transfer = value;
    Dvar_SetVariant(dvar, &transfer, 0);
    ++s_comOptimizedDvarWrites;
}

void Apply(unsigned mode) {
    for (auto& setting : s_settings) {
        const bool active = mode >= setting.minimumMode;
        // Inactive settings with no restore point need no lookup or write.
        if (!active && !setting.captured) continue;
        dvar_t* dvar = Dvar_FindVarByName(setting.name);
        // A missing or differently typed dvar is never created or coerced.
        // Resolve it again on refresh to tolerate deregistration and reuse.
        if (!dvar || dvar->type != setting.type || (dvar->flags & 0x2802)) {
            setting.captured = nullptr;
            continue;
        }
        const bool same = setting.captured == dvar && setting.checksum == dvar->checksum;
        if (!active) {
            // Retain an explicit user edit made while the optimization was on.
            if (same && Matches(dvar, setting)) Set(dvar, setting.savedCurrent);
            setting.captured = nullptr;
            continue;
        }
        if (setting.type == 8 && (dvar->domain.enumeration.count <= setting.value || setting.value < 0))
            continue;
        if (setting.type == 5 && (setting.value < dvar->domain.integer.minimum ||
                                setting.value > dvar->domain.integer.maximum)) continue;
        if (setting.type == 1 && !(float(setting.value) >= dvar->domain.value.minimum &&
                                  float(setting.value) <= dvar->domain.value.maximum)) continue;
        if (!same || !Matches(dvar, setting)) {
            // Preserve intervening edits/re-registration as the next restore
            // point, rather than silently reverting to the first snapshot.
            setting.captured = dvar;
            setting.checksum = dvar->checksum;
            setting.savedCurrent = dvar->current;
            setting.savedLatched = dvar->latched;
        }
        if (!Matches(dvar, setting)) {
            DvarValue value{};
            if (setting.type == 0) value.enabled = setting.value != 0;
            else if (setting.type == 1) value.value = float(setting.value);
            else value.integer = setting.value;
            Set(dvar, value);
        }
    }
}
}

extern "C" unsigned Com_Optimized_GetMode() {
    return __atomic_load_n(&s_comOptimizedMode, __ATOMIC_RELAXED);
}

extern "C" bool Com_Optimized_IsEnabled() {
    return Com_Optimized_GetMode() != 0;
}

extern "C" bool Com_Optimized_UseReducedVisuals() {
    return Com_Optimized_GetMode() >= 2;
}

extern "C" void Com_Optimized_Frame() {
    if (!Sys_IsMainThread()) return;
    if (!com_optimized) {
        Dvar_BeginPermanentRegistration();
        com_optimized = Dvar_RegisterInt("com_optimized", 1, 0, 2, 0,
            "Optimization mode: 0 off; 1 CPU scheduling, incremental GC and diagnostic overhead reductions with native scene quality; 2 full experimental low-detail profile. Preserves selected scene resolution.");
        Dvar_EndPermanentRegistration();
    }
    if (!com_optimized || com_optimized->type != 5) return;
    const int value = com_optimized->current.integer;
    const unsigned requested = value <= 0 ? 0 : (value >= 2 ? 2 : 1);
    const unsigned previous = Com_Optimized_GetMode();
    if (requested == previous && s_refreshFrames) { --s_refreshFrames; return; }
    // Apply only after database work is idle and LUI workers have joined.
    if (!Sys_IsDatabaseReady()) return;
    if (requested || previous) Apply(requested);
    __atomic_store_n(&s_comOptimizedMode, requested, __ATOMIC_RELAXED);
    s_refreshFrames = 60;
    if (requested != previous) {
        ++s_comOptimizedTransitions;
        const char* description = requested == 0 ? "off; previous settings restored" :
            requested == 1 ? "CPU scheduling, incremental GC and diagnostic overhead; native scene quality" :
                             "full experimental low-detail profile, including CPU optimizations";
        Com_Printf(16, "com_optimized %u: %s (selected scene resolution preserved)\n",
                   requested, description);
    }
}

extern "C" const dvar_t* Com_Optimized_ArchivedDvar(const dvar_t* dvar, dvar_t* view) {
    if (!Com_Optimized_IsEnabled()) return dvar;
    for (const auto& setting : s_settings) {
        if (setting.captured == dvar && setting.checksum == dvar->checksum &&
            setting.type == dvar->type && Matches(dvar, setting)) {
            // Serialize a local native record with the saved values. Render
            // threads continue using the real optimized record throughout.
            *view = *dvar;
            view->current = setting.savedCurrent;
            view->latched = setting.savedLatched;
            return view;
        }
    }
    return dvar;
}
#endif

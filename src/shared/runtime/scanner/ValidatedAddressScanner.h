#pragma once
namespace scanner
{
    // Runs a conservative validation pass over executable PE sections.
    // It never patches memory or installs hooks.
    bool RunValidatedAddressPass();
}

#pragma once

namespace mw2019_patches
{
    // These two functions are safe to call before the MSVC CRT has initialized.
    // They use Win32 APIs and zero-initialized POD state only.
    bool IsExact128LoaderSafe() noexcept;
    bool Initialize128LoaderSafe() noexcept;

    // Normal routed entrypoint used after CRT startup for other paths.
    bool InitializeEarly();

    // Compatibility alias kept for older callers. The exact 1.28 path no
    // longer needs a worker because its tiny patch can be installed safely by
    // the pre-CRT bootstrap.
    void QueueDeferredInitialize() noexcept;
}

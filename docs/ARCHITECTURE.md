# Build and source organization

The public solution contains five clients, seven shared libraries, and one IW8 backend. BO4 and Cold War each own a private static-library project in `build/clients/<game>/internal`. These preserve the existing library compilation/linking behavior and are built by the owning client. They are not independent clients and are not separate solution entries.

All source-file references use the repository root supplied by `Directory.Build.props`. Literal C/C++ includes were resolved against their original files and rewritten for the new locations. Shared library source is under `src/shared`; game loaders and implementations are under `src/clients/<game>`. The compatibility header groups remain because compiled code includes them.

The IW8 backend is a project dependency of MW2019 and builds as its own executable. BO4 also builds a minimal DXGI bootstrap required by its existing loader flow.

The source archive includes only the buildable source distribution, build metadata, runtime assets, documentation, license notices, and the two build/package helpers. It does not include `.git`, generated output, AI tools, private controller state, old ZIPs, or reference game executables.

BO4 and Cold War expose their internal source files in the public client project for navigation. These view entries do not compile the files again; the private library owns compilation.

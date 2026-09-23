# CodRevamped

Windows/x64 client workspace and IW8 backend emulator. Each game has one public client project and one source folder.

## Clients

| Client | Source | Release files |
| --- | --- | --- |
| BO4 | `src/clients/bo4` | `version.dll`, `dxgi.dll` bootstrap |
| Cold War | `src/clients/coldwar` | `version.dll` |
| MW2019 | `src/clients/mw2019` | `version.dll`, `RevampedIW8Server.exe` |
| BO6 | `src/clients/bo6` | `version.dll` |
| MW3 | `src/clients/mw3` | `version.dll` |

BO4's bootstrap loads its client; it is not a second client. BO4 and Cold War keep their supporting static-library build details inside the corresponding client build folder, rather than exposing duplicate game entries in the solution.

## Build

Install Visual Studio Desktop development with C++, the MSVC v143 toolset, and a Windows SDK. Open `CodRevamped.sln` or run:

<<<<<<< HEAD
```powershell
./tools/build.ps1
./tools/build.ps1 -Target BO4
./tools/build.ps1 -Target MW2019 -Configuration Debug
./tools/build.ps1 -Configuration All
=======
**Revamped exists to preserve those games and their functionality.**

Instead of allowing older versions to become unusable because their original infrastructure is gone, Revamped works to restore local/offline functionality, compatibility, and access to supported builds using legally obtained game files.

---

# Game Support

```text
CoD Revamped
│
├── Black Ops 4
│   ├── ◇ Retail — Not Playable
│   ├── ◇ Multiplayer Beta — Not Playable
│   └── ◇ Blackout Beta — Not Playable
│
├── Black Ops Cold War
│   ├── ✓ Steam Retail — Playable
│   ├── ✓ Alpha — Playable / Windows 11 Patched
│   ├── ✓ Season 2 — Playable / Windows 11 Patched
│   ├── ◇ Open Beta — Not Playable / Windows 11 Patched
│   └── ◇ Battle.net Retail — Not Playable
│
├── Modern Warfare (2019)
│   ├── ◇ Beta — Not Playable
│   ├── ◇ 1.28 — Not Playable / Windows 11 Patched
│   ├── ◇ 1.44 — Not Playable
│   └── ◇ Retail — Not Playable
│
├── Vanguard
│   ├── ◇ Beta — Not Playable
│   ├── ◇ 1.10 — Not Playable
│   ├── ◇ 1.14 — Not Playable
│   ├── ◇ 1.16 — Not Playable
│   ├── ◇ 1.24 — Not Playable
│   └── ◇ Retail — Not Playable
│
├── Modern Warfare II
│   ├── ◇ Beta — Not Playable
│   └── ◇ Retail — Not Playable
│
├── Modern Warfare III
│   ├── ◇ Beta — Not Playable
│   └── ◇ Retail — Not Playable
│
└── Black Ops 6
    ├── ◇ Beta — Not Playable
    └── ◇ Retail — Not Playable
>>>>>>> 095fe69c6be6abbc6f7acf4b059c1906cf41cba3
```

Outputs go to `artifacts/bin/<client>/<configuration>`. Build logs, intermediate objects, and libraries stay under `artifacts/` and are ignored by Git. Dependencies are built from the included source; no precompiled MinHook library is required.

## Repository layout

- `src/clients/`: one folder per game, containing its loader and implementation.
- `src/shared/`: common runtime, interfaces, and active diagnostics.
- `src/backend/iw8/`: Battle.net/Demonware emulator.
- `build/`: shared settings and client/backend project files.
- `assets/`: runtime Lua assets, retaining their deployment-relative layout.
- `third_party/`: dependency source and original notices.
- `tools/`: build and release packaging scripts only.
- `docs/`: architecture, release instructions, and known limitations.

AI controllers, autonomous research tools/data, alternate unused source checkouts, executable dumps, archive snapshots, and local IDE state are excluded from the release source tree.

## Release

<<<<<<< HEAD
```powershell
./tools/package.ps1 -Version dev
```
=======
# AI-Assisted Development

CoD Revamped uses AI-assisted development tools to help speed up development.

AI is used for things such as reviewing logs, comparing research, debugging, organizing information, reducing repetitive work, and assisting with code development.

It is simply another development tool. The client still requires manual research, reverse engineering, testing, debugging, and validation against the actual games.

Using AI does not mean the entire project was automatically generated, and it does not replace the work required to make features function correctly.

The goal is simply to save time on repetitive tasks and make development faster.

If you do not like AI-assisted development, that is completely fine. **CoD Revamped is optional software and nobody is required to use it.**

---

# Legal & Preservation Notice
>>>>>>> 095fe69c6be6abbc6f7acf4b059c1906cf41cba3

This builds Release/x64, then creates a source archive, one binary archive per client, and SHA-256 checksums under `artifacts/releases/`. It does not push, tag, or publish a GitHub release. See [release instructions](docs/RELEASE.md).

The CI workflow builds Release and Debug and uploads Release packages as workflow artifacts.

## Status and license

This is development software. Build success does not establish gameplay compatibility. The MW2019 session/Source3 completion blocker is unresolved; stock startup reaching the frontend/menu has not been demonstrated by this cleanup. Other clients also require game-specific runtime validation.

Original CodRevamped contributions are provided under [MIT](LICENSE). Existing third-party or adapted code retains its own notices and terms; see [third-party notices](THIRD_PARTY_NOTICES.md). Game executables and private research data are not included.

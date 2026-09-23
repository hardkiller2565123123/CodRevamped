# Preparing a GitHub release

1. Build both configurations with `./tools/build.ps1 -Configuration All`.
2. Test the intended game/build locally. The MW2019 frontend blocker is still unresolved; describe this limitation in release notes.
3. Run `./tools/package.ps1 -Version <your-version>` to build Release and create archives plus SHA-256 checksums. `-SkipBuild` is available only when intentionally packaging already validated output.
4. Review the source archive and notices. It is an allowlisted distribution and contains no Git history, AI data, or game executable dumps.
5. Commit the reviewed folder reorganization and deletions to the intended repository. Existing Git history and the configured remote are unchanged by this preparation.
6. Create your GitHub release and attach the desired per-client archives and checksums. No script publishes automatically.

Runtime archives contain only the selected client's built DLLs/executable, the runtime asset tree, project readme/license, and available dependency license notices. They do not contain Windows SDK/runtime installers or game files.

GitHub Actions uses the official [checkout](https://github.com/actions/checkout) and [upload-artifact](https://github.com/actions/upload-artifact) actions. Workflow permissions are read-only, and packaging runs only for the Release job.

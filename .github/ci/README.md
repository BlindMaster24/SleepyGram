# CI package checks

The platform jobs package with `tar`, `Compress-Archive`, and `ditto` and use
`build_artifact.py` to write or verify a safe `build-manifest.json` in each
archive. The manifest records the source commit,
workflow run, actual recursive submodule commits, Qt version, runner, and
compiler/toolchain versions. It contains no credentials or environment dump.

The package check validates archive paths and required bundle files, then reads
the executable headers to confirm Linux x64, Windows x64, or macOS arm64. The
Windows archive retains the x64 `d3dcompiler_47.dll` module when the build
produces it for the Windows 7 baseline; Updater binaries are also retained when
present.

The startup smoke launches the extracted package for at most eight seconds with
`-workdir` pointed at a temporary profile and temporary home/config directories.
Linux's Qt build enables xcb and Wayland, not the offscreen plugin, so CI starts
host Xvfb and runs xcb inside the build container with networking disabled. If
Xvfb or a usable Qt platform is unavailable, the smoke reports an explicit
skip; a short clean exit is also reported as inconclusive. A process that stays
up for the full window passes. This checks startup only; it does not sign in,
exercise UI flows, or validate network/API behavior.

Release publishing runs only for `v*` tag pushes or an explicitly requested
manual run with all three platforms selected. It checks each artifact's source
SHA and workflow run ID/attempt before publishing, and fails if a release already
exists so public releases and assets are never overwritten.

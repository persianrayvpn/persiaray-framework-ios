# Bundled trees

| Directory | Origin |
| --- | --- |
| `awg-ios/` | Copy of `PersianRay/awg-ios` (amneziawg-go v3.1.20260814 + `cmd/persianray`). |
| `xray-core/` | Copy of `PersianRay/PersianRay/xray/.work-xray` (module `github.com/xtls/xray-core`). Use this tree for any Xray-core edits. |
| `libxray/` | `git clone --branch v26.7.28 https://github.com/XTLS/libXray` (wrapper only). It `replace`s `github.com/xtls/xray-core => ../xray-core`. |
| `psiphon-ios/` | Complete local customized Psiphon tunnel-core tree. |
| `usque-ios/` | Pre-downloaded `github.com/Diniboy1123/usque` tree. `mobile/` is the PersianRay in-process adapter; no git fetch is performed by the build. |

Edit **xray-core in this folder** if you need iOS behavior changes. Re-copy from `.work-xray` only when you intend to refresh from that HarmonyOS worktree.

The root `go.mod` locally replaces all four engine modules and pins one gVisor
implementation for the unified archive. `go mod tidy` may download ordinary
transitive module dependencies, but it never replaces the bundled engine
source trees.

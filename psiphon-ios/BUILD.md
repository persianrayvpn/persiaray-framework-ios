# What to put on GitHub

**Do not upload `persianray-ios`.** The Action only builds the framework.

Create a repo whose **root is the `psiphon-ios` folder**. Upload that directory as-is.

```text
your-github-repo/          ← this IS psiphon-ios/
  .github/workflows/psiphon-apple.yml
  MobileLibrary/iOS/build-psiphon-framework.sh
  psiphon/                 ← Edge Fronting + PersianRay policy
  ClientLibrary/
  ConsoleClient/
  vendor/
  go.mod
  PERSIANRAY.md
  BUILD.md
  ...
```

That’s the whole list: **the `psiphon-ios` directory**, nothing else.

`.gitattributes` keeps `*.sh` as LF. If you zip-upload from Windows, the Action still strips `\r` before running the build script.

| Upload | Skip |
|---|---|
| `psiphon-ios/` (entire folder, as repo root) | `persianray-ios/` |
| | `_psiphon_build/` |
| | `PersianRay-Android/` |
| | Tauri / desktop trees |

After you push:

1. Actions → **psiphon-apple** → Run workflow
2. Download artifact **PsiphonTunnel.xcframework**
3. On your machine only: copy it into `persianray-ios/Vendor/Psiphon/` (local, not this GitHub repo)

## Local Mac (optional)

```bash
cd psiphon-ios/MobileLibrary/iOS
./build-psiphon-framework.sh
```

Go **1.26.3** and Xcode required. Same script the Action runs.

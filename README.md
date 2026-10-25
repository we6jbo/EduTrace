# EduTrace 0.7.0

A local-only Qt/C++ command-line tool for encrypted historical research notes. MIT licensed. No AI model, network service, or automated publishing is included. AI agents may invoke the CLI, but sending decrypted results to a cloud model is a separate privacy decision.

## Build

Requires Qt 6 Core and Sql, libsodium, OpenSSL Crypto, CMake, and a C++17 compiler.

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j2
./build/EduTrace help
```

## Commands

`help`, `init`, `status`, `research` (aliases `run`, `activate`), `add-note`, `read-notes`, `search TEXT`, `ask QUESTION`, `add-source`, `sources`, `set-secret`, `read-secret`, `verify-challenge`, `extension-path`. In interactive `research`: `help`, `status`, `note`, `notes`, `search TERM`, `ask QUESTION`, `add-source`, `sources`, `challenge`, `exit`.

`ask` searches notes, not an AI model. Note entry ends with `.END` on its own line. Do not publish decrypted notes or the local key.

## Private storage

Priority: `EDUTRACE_PRIVATE_DIR` if set; Snap `$SNAP_USER_DATA/private`; `$XDG_DATA_HOME/edutrace-private` (including Flatpak); existing `/var/lib/edutrace-private`; otherwise `~/.local/share/edutrace-private`. For your existing installation, use `EDUTRACE_PRIVATE_DIR=/var/lib/edutrace-private` to preserve its encrypted records. Do not move only encrypted files without their matching key. Never commit any private records.

## Distribution

See `snap/snapcraft.yaml` and `flatpak/org.edutrace.EduTrace.yml`. Packaging files are preparation, **not evidence of store acceptance**. Flathub may require a suitable terminal launcher and AppStream metadata and review of CLI-only apps. Review dependencies and validate on each target build environment.

## Privacy and provenance

The public archive is a clean source export without `.git` history, local settings, family-tree snapshots, or screenshot. Historical private data stays outside this repository. Screenshot is deliberately excluded until manually inspected and approved for public release.

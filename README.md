# SNISPF-HJ Android

An Android app that runs [SNISPF-HJ-GO](https://github.com/hjfisher/SNISPF-HJ-GO) — a cross-platform DPI bypass tool — directly on your phone, with **no Termux, no root required**.

The Go binary is cross-compiled for Android and bundled inside the APK, managed through a native Jetpack Compose UI.

---

## How It Works

SNISPF sits between your apps and the internet. It intercepts the TLS ClientHello handshake and either fragments the SNI field across multiple TCP packets, or injects a decoy hello with an allowed hostname, so DPI firewalls cannot identify and block the real destination.

```
┌──────────┐     ┌─────────────┐     ┌──────────┐     ┌─────────────┐
│ Your App ├────>│  SNISPF-HJ  ├────>│ Firewall ├────>│ Real Server │
│ (v2ray,  │     │ (port 40443)│     │  (DPI)   │     │             │
│  clash…) │     │             │     │          │     │             │
└──────────┘     └─────────────┘     └──────────┘     └─────────────┘
                       │                   │
               sends fragmented     sees incomplete
               or fake SNI hello    SNI → lets it through
```

The proxy listens on `127.0.0.1:40443`. Point any proxy client (v2ray, clash, etc.) at that address.

---

## Features

- **No root required** — works on any Android 8.0+ device
- **No Termux needed** — standalone APK, no external dependencies
- **In-process uTLS** — browser TLS fingerprinting (Chrome, Firefox, Safari, etc.)
- **IP pool + discovery** — automatic Cloudflare IP scanning and health checks
- **Multiple bypass methods** — fragment, fake_sni, combined, mitm
- **Foreground service** — keeps proxy alive in background

---

## Supported Architectures

| ABI | Binary | Description |
|-----|--------|-------------|
| `arm64-v8a` | `snispf-arm64` | Most modern Android phones (64-bit ARM) |
| `armeabi-v7a` | `snispf-arm` | Older Android phones (32-bit ARM) |
| `x86_64` | `snispf-amd64` | Android emulators and Chromebooks |

---

## Project Structure

```
app/src/main/
├── assets/bin/
│   ├── snispf-arm64          # Go binary for arm64-v8a
│   ├── snispf-arm            # Go binary for armeabi-v7a
│   └── snispf-amd64          # Go binary for x86_64
├── kotlin/com/snispf/android/
│   ├── MainActivity.kt       # Jetpack Compose UI
│   ├── GoBridge.kt           # Go binary lifecycle management
│   ├── SnispfViewModel.kt    # Business logic / state management
│   ├── ConfigBuilderScreen.kt # Config builder UI with all settings
│   └── SnispfService.kt      # Foreground service (keeps proxy alive)
├── build.gradle
├── settings.gradle
└── gradle.properties
```

---

## Prerequisites

| Tool | Version |
|------|---------|
| JDK | 17 |
| Android SDK | platform-tools + build-tools 34 + android-34 |
| Go | 1.24+ (for cross-compiling the binary) |

---

## Build

### 1. Cross-compile Go for Android

```bash
cd SNISPF-HJ-GO
set CGO_ENABLED=0
set GOOS=linux

set GOARCH=arm64
go build -o ../SNISPF-HJ-Android/app/src/main/assets/bin/snispf-arm64 .

set GOARCH=arm
go build -o ../SNISPF-HJ-Android/app/src/main/assets/bin/snispf-arm .

set GOARCH=amd64
go build -o ../SNISPF-HJ-Android/app/src/main/assets/bin/snispf-amd64 .
```

### 2. Build Android APK

```bash
cd ../SNISPF-HJ-Android

# Windows
.\gradlew.bat assembleDebug

# Linux / macOS
./gradlew assembleDebug
```

Output: `app/build/outputs/apk/debug/app-debug.apk`

---

## Install

```bash
adb install app/build/outputs/apk/debug/app-debug.apk
```

Or copy the APK to your device and install manually (enable "Install from unknown sources" in settings).

---

## Usage

1. Open the app and configure your settings in the **Config Builder** tab.
2. Tap **Start** — the app launches a foreground service that keeps the proxy running in the background.
3. In your proxy client (v2ray, clash, etc.), set the upstream proxy to:
   ```
   Address: 127.0.0.1
   Port:    40443
   ```

---

## Architecture

```
[Compose UI]  ←→  [SnispfViewModel]  ←→  [GoBridge]  ←→  [snispf binary]
                         ↕
               [SnispfService (Foreground)]
```

GoBridge extracts the Go binary from APK assets, writes the config to a JSON file, and launches the binary as a subprocess. Logs and stats are parsed from the binary's stdout output.

---

## Bypass Methods

| Method | Description |
|--------|-------------|
| `fragment` | Splits the TLS ClientHello so no single packet contains the full SNI |
| `fake_sni` | Sends a decoy hello with an allowed hostname before the real one |
| `combined` | Both methods together — strongest option for aggressive DPI |
| `mitm` | TLS-terminating relay with uTLS fingerprinting (in-process, no sidecar) |

---

## TLS Fingerprinting (MITM mode)

The Go port supports in-process uTLS fingerprinting. Select a browser profile in the Config Builder:

| Profile | Description |
|---------|-------------|
| `chrome` | Chrome 133 (default) |
| `firefox` | Firefox 120 |
| `safari` | Safari 16.0 |
| `ios` | iOS 14 |
| `android` | Android 11 OkHttp |
| `random` | Different browser per connection |
| `randomized` | Unique randomized hello per connection |
| `unsafe` | Plain Go TLS, no impersonation |

---

## Upstream Project

This app is an Android frontend for **[SNISPF-HJ-GO](https://github.com/hjfisher/SNISPF-HJ-GO)** by [@hjfisher](https://github.com/hjfisher).

See the [upstream README](https://github.com/hjfisher/SNISPF-HJ-GO#readme) for full configuration options.

---

## License

MIT — see [LICENSE](LICENSE) for details.
